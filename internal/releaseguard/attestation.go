package releaseguard

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	maxAttestationBundleSize  = 2 << 20
	maxAttestationPayload     = 1 << 20
	maxAttestationCertificate = 32 << 10
	maxAttestationSignature   = 4 << 10
	maxAttestationFutureSkew  = 5 * time.Minute

	sigstoreBundleMediaType = "application/vnd.dev.sigstore.bundle.v0.3+json"
	dssePayloadType         = "application/vnd.in-toto+json"
	inTotoStatementType     = "https://in-toto.io/Statement/v1"
	slsaProvenanceType      = "https://slsa.dev/provenance/v1"
	githubWorkflowBuildType = "https://actions.github.io/buildtypes/workflow/v1"
	releaseWorkflowPath     = ".github/workflows/release.yml"
)

type sigstoreBundle struct {
	MediaType            *string                       `json:"mediaType"`
	VerificationMaterial *sigstoreVerificationMaterial `json:"verificationMaterial"`
	DSSEEnvelope         *dsseEnvelope                 `json:"dsseEnvelope"`
	MessageSignature     json.RawMessage               `json:"messageSignature"`
}

type sigstoreVerificationMaterial struct {
	Certificate          *sigstoreCertificate `json:"certificate"`
	X509CertificateChain json.RawMessage      `json:"x509CertificateChain"`
	PublicKey            json.RawMessage      `json:"publicKey"`
	TLogEntries          *[]json.RawMessage   `json:"tlogEntries"`
}

type sigstoreCertificate struct {
	RawBytes *string `json:"rawBytes"`
}

type dsseEnvelope struct {
	Payload     *string          `json:"payload"`
	PayloadType *string          `json:"payloadType"`
	Signatures  *[]dsseSignature `json:"signatures"`
}

type dsseSignature struct {
	KeyID *string `json:"keyid"`
	Sig   *string `json:"sig"`
}

type inTotoStatement struct {
	Type          *string              `json:"_type"`
	Subject       *[]inTotoSubject     `json:"subject"`
	PredicateType *string              `json:"predicateType"`
	Predicate     *provenancePredicate `json:"predicate"`
}

type inTotoSubject struct {
	Name   *string            `json:"name"`
	Digest *map[string]string `json:"digest"`
}

type provenancePredicate struct {
	BuildDefinition *provenanceBuildDefinition `json:"buildDefinition"`
	RunDetails      *provenanceRunDetails      `json:"runDetails"`
}

type provenanceBuildDefinition struct {
	BuildType            *string                       `json:"buildType"`
	ExternalParameters   *provenanceExternalParameters `json:"externalParameters"`
	InternalParameters   *provenanceInternalParameters `json:"internalParameters"`
	ResolvedDependencies *[]provenanceDependency       `json:"resolvedDependencies"`
}

type provenanceExternalParameters struct {
	Workflow *provenanceWorkflow `json:"workflow"`
}

type provenanceWorkflow struct {
	Ref        *string `json:"ref"`
	Repository *string `json:"repository"`
	Path       *string `json:"path"`
}

type provenanceInternalParameters struct {
	GitHub *provenanceGitHub `json:"github"`
}

type provenanceGitHub struct {
	EventName         *string `json:"event_name"`
	RepositoryID      *string `json:"repository_id"`
	RepositoryOwnerID *string `json:"repository_owner_id"`
	RunnerEnvironment *string `json:"runner_environment"`
}

type provenanceDependency struct {
	URI    *string            `json:"uri"`
	Digest *map[string]string `json:"digest"`
}

type provenanceRunDetails struct {
	Builder  *provenanceBuilder  `json:"builder"`
	Metadata *provenanceMetadata `json:"metadata"`
}

type provenanceBuilder struct {
	ID *string `json:"id"`
}

type provenanceMetadata struct {
	InvocationID *string `json:"invocationId"`
}

type transparencyLogEntry struct {
	LogIndex *string `json:"logIndex"`
	LogID    *struct {
		KeyID *string `json:"keyId"`
	} `json:"logId"`
	KindVersion *struct {
		Kind    *string `json:"kind"`
		Version *string `json:"version"`
	} `json:"kindVersion"`
	IntegratedTime    *string                     `json:"integratedTime"`
	InclusionProof    *transparencyInclusionProof `json:"inclusionProof"`
	CanonicalizedBody *string                     `json:"canonicalizedBody"`
}

type transparencyInclusionProof struct {
	LogIndex   *string   `json:"logIndex"`
	RootHash   *string   `json:"rootHash"`
	TreeSize   *string   `json:"treeSize"`
	Hashes     *[]string `json:"hashes"`
	Checkpoint *struct {
		Envelope *string `json:"envelope"`
	} `json:"checkpoint"`
}

type rekorDSSEBody struct {
	APIVersion *string `json:"apiVersion"`
	Kind       *string `json:"kind"`
	Spec       *struct {
		PayloadHash *struct {
			Algorithm *string `json:"algorithm"`
			Value     *string `json:"value"`
		} `json:"payloadHash"`
		Signatures *[]struct {
			Signature *string `json:"signature"`
			Verifier  *string `json:"verifier"`
		} `json:"signatures"`
	} `json:"spec"`
}

// VerifyAttestation verifies the runner-local bundle emitted by the pinned
// actions/attest step, then repeats the remote tag, policy, and OCI checks. The
// local verification proves that the DSSE payload was signed by the included
// Fulcio-shaped certificate and binds the exact provenance fields. Trust in the
// Fulcio root and Rekor checkpoint is provided by the immediately preceding
// pinned gh attestation verification over this same bundle and the pinned
// custom Sigstore root; this intentionally small helper does not embed a
// rotating Sigstore trust root.
func (g *Guard) VerifyAttestation(ctx context.Context, release Context, getenv func(string) string) error {
	binding, err := loadBinding(release, getenv)
	if err != nil {
		return err
	}
	path := ""
	if getenv != nil {
		path = getenv("N2U_ATTESTATION_BUNDLE")
	}
	if err := verifyAttestationFile(release, binding, path, time.Now()); err != nil {
		return err
	}
	if err := g.trustReserved(ctx, release); err != nil {
		return err
	}
	if err := g.requireImageBinding(ctx, release, binding); err != nil {
		return err
	}
	// Private-draft validation belongs to Bind's contents-write job. This
	// image/attestation job must not gain repository write authority merely
	// to read that draft. A missing/changed draft blocks Bind, not this proof.
	return nil
}

func verifyAttestationFile(release Context, binding bindingInput, path string, now time.Time) error {
	if path == "" {
		return errors.New("N2U_ATTESTATION_BUNDLE is required")
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("N2U_ATTESTATION_BUNDLE must be an absolute canonical path")
	}
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Size() <= 0 || before.Size() > maxAttestationBundleSize {
		return errors.New("attestation bundle is not a bounded regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return errors.New("open attestation bundle")
	}
	after, statErr := file.Stat()
	if statErr != nil || !os.SameFile(before, after) {
		file.Close()
		return errors.New("attestation bundle changed while opening")
	}
	payload, readErr := io.ReadAll(io.LimitReader(file, maxAttestationBundleSize+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || int64(len(payload)) != after.Size() || len(payload) > maxAttestationBundleSize {
		return errors.New("read attestation bundle")
	}
	return verifyAttestationBundle(release, binding, payload, now)
}

func verifyAttestationBundle(release Context, binding bindingInput, payload []byte, now time.Time) error {
	var bundle sigstoreBundle
	if err := decodeJSON(payload, &bundle); err != nil {
		return errors.New("attestation bundle is malformed")
	}
	if bundle.MediaType == nil || *bundle.MediaType != sigstoreBundleMediaType || bundle.VerificationMaterial == nil || bundle.DSSEEnvelope == nil || len(bundle.MessageSignature) != 0 {
		return errors.New("attestation bundle has an unsupported envelope")
	}
	material := bundle.VerificationMaterial
	if material.Certificate == nil || material.Certificate.RawBytes == nil || len(material.X509CertificateChain) != 0 || len(material.PublicKey) != 0 || material.TLogEntries == nil || len(*material.TLogEntries) != 1 {
		return errors.New("attestation bundle has invalid verification material")
	}
	certificateDER, err := decodeBoundedBase64(*material.Certificate.RawBytes, maxAttestationCertificate)
	if err != nil {
		return errors.New("attestation certificate is invalid")
	}
	certificate, err := x509.ParseCertificate(certificateDER)
	if err != nil {
		return errors.New("attestation certificate is invalid")
	}
	envelope := bundle.DSSEEnvelope
	if envelope.Payload == nil || envelope.PayloadType == nil || *envelope.PayloadType != dssePayloadType || envelope.Signatures == nil || len(*envelope.Signatures) != 1 {
		return errors.New("attestation DSSE envelope is invalid")
	}
	statementJSON, err := decodeBoundedBase64(*envelope.Payload, maxAttestationPayload)
	if err != nil {
		return errors.New("attestation DSSE payload is invalid")
	}
	signatureEntry := (*envelope.Signatures)[0]
	if signatureEntry.Sig == nil || (signatureEntry.KeyID != nil && *signatureEntry.KeyID != "") {
		return errors.New("attestation DSSE signature metadata is invalid")
	}
	signature, err := decodeBoundedBase64(*signatureEntry.Sig, maxAttestationSignature)
	if err != nil {
		return errors.New("attestation DSSE signature is invalid")
	}
	if err := verifyDSSESignature(certificate, *envelope.PayloadType, statementJSON, signature); err != nil {
		return err
	}
	if err := verifyProvenanceStatement(release, binding, statementJSON); err != nil {
		return err
	}
	integratedTime, err := verifyTransparencyEntry((*material.TLogEntries)[0], certificateDER, statementJSON, *signatureEntry.Sig)
	if err != nil {
		return err
	}
	if now.IsZero() || integratedTime.After(now.Add(maxAttestationFutureSkew)) {
		return errors.New("attestation transparency log time is after the permitted observation window")
	}
	if err := verifyAttestationCertificate(certificate, release, integratedTime); err != nil {
		return err
	}
	return nil
}

func verifyAttestationCertificate(certificate *x509.Certificate, release Context, now time.Time) error {
	if certificate == nil || now.Before(certificate.NotBefore) || now.After(certificate.NotAfter) || certificate.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return errors.New("attestation certificate is not valid for this verification time")
	}
	codeSigning := false
	for _, usage := range certificate.ExtKeyUsage {
		if usage == x509.ExtKeyUsageCodeSigning {
			codeSigning = true
		}
	}
	publicKey, ok := certificate.PublicKey.(*ecdsa.PublicKey)
	if !ok || publicKey.Curve != elliptic.P256() || !codeSigning {
		return errors.New("attestation certificate has an unsupported signing key")
	}
	if len(certificate.Issuer.Organization) != 1 || certificate.Issuer.Organization[0] != "sigstore.dev" {
		return errors.New("attestation certificate has an unexpected issuer identity")
	}
	expectedWorkflow := workflowIdentity(release)
	if len(certificate.URIs) != 1 || certificate.URIs[0].String() != expectedWorkflow {
		return errors.New("attestation certificate does not identify the release workflow")
	}
	expectedClaims := map[string]string{
		"1.3.6.1.4.1.57264.1.8":  "https://token.actions.githubusercontent.com",
		"1.3.6.1.4.1.57264.1.9":  expectedWorkflow,
		"1.3.6.1.4.1.57264.1.10": release.SourceSHA,
		"1.3.6.1.4.1.57264.1.11": "github-hosted",
		"1.3.6.1.4.1.57264.1.12": "https://github.com/" + RepositoryName,
		"1.3.6.1.4.1.57264.1.13": release.SourceSHA,
		"1.3.6.1.4.1.57264.1.14": "refs/heads/main",
		"1.3.6.1.4.1.57264.1.15": strconv.FormatInt(release.RepositoryID, 10),
		"1.3.6.1.4.1.57264.1.16": "https://github.com/" + RepositoryOwner,
		"1.3.6.1.4.1.57264.1.17": strconv.FormatInt(release.RepositoryOwnerID, 10),
		"1.3.6.1.4.1.57264.1.18": expectedWorkflow,
		"1.3.6.1.4.1.57264.1.19": release.SourceSHA,
		"1.3.6.1.4.1.57264.1.20": "workflow_dispatch",
		"1.3.6.1.4.1.57264.1.21": invocationIdentity(release),
		"1.3.6.1.4.1.57264.1.22": "public",
	}
	claims := make(map[string]string, len(expectedClaims))
	for _, extension := range certificate.Extensions {
		oid := extension.Id.String()
		if _, required := expectedClaims[oid]; !required {
			continue
		}
		if _, duplicate := claims[oid]; duplicate {
			return errors.New("attestation certificate contains a duplicate identity claim")
		}
		var value string
		remainder, err := asn1.Unmarshal(extension.Value, &value)
		if err != nil || len(remainder) != 0 {
			return errors.New("attestation certificate contains a malformed identity claim")
		}
		claims[oid] = value
	}
	if len(claims) != len(expectedClaims) {
		return errors.New("attestation certificate is missing a required identity claim")
	}
	for oid, expected := range expectedClaims {
		if claims[oid] != expected {
			return errors.New("attestation certificate identity does not match this workflow")
		}
	}
	return nil
}

func verifyDSSESignature(certificate *x509.Certificate, payloadType string, payload, signature []byte) error {
	publicKey, ok := certificate.PublicKey.(*ecdsa.PublicKey)
	if !ok || publicKey.Curve != elliptic.P256() {
		return errors.New("attestation DSSE signing key is unsupported")
	}
	pae := []byte("DSSEv1 " + strconv.Itoa(len(payloadType)) + " " + payloadType + " " + strconv.Itoa(len(payload)) + " ")
	pae = append(pae, payload...)
	digest := sha256.Sum256(pae)
	if !ecdsa.VerifyASN1(publicKey, digest[:], signature) {
		return errors.New("attestation DSSE signature verification failed")
	}
	return nil
}

func verifyProvenanceStatement(release Context, binding bindingInput, payload []byte) error {
	var statement inTotoStatement
	if err := decodeJSON(payload, &statement); err != nil {
		return errors.New("attestation provenance statement is malformed")
	}
	if statement.Type == nil || *statement.Type != inTotoStatementType || statement.PredicateType == nil || *statement.PredicateType != slsaProvenanceType || statement.Subject == nil || len(*statement.Subject) != 1 || statement.Predicate == nil {
		return errors.New("attestation provenance statement has an unexpected type")
	}
	subject := (*statement.Subject)[0]
	if subject.Name == nil || *subject.Name != ImageName || subject.Digest == nil || len(*subject.Digest) != 1 || (*subject.Digest)["sha256"] != strings.TrimPrefix(binding.digest, "sha256:") {
		return errors.New("attestation subject does not match the release image digest")
	}
	definition := statement.Predicate.BuildDefinition
	run := statement.Predicate.RunDetails
	if definition == nil || definition.BuildType == nil || *definition.BuildType != githubWorkflowBuildType || definition.ExternalParameters == nil || definition.ExternalParameters.Workflow == nil || definition.InternalParameters == nil || definition.InternalParameters.GitHub == nil || definition.ResolvedDependencies == nil || len(*definition.ResolvedDependencies) != 1 || run == nil || run.Builder == nil || run.Builder.ID == nil || run.Metadata == nil || run.Metadata.InvocationID == nil {
		return errors.New("attestation provenance is incomplete")
	}
	workflow := definition.ExternalParameters.Workflow
	if workflow.Ref == nil || *workflow.Ref != "refs/heads/main" || workflow.Repository == nil || *workflow.Repository != "https://github.com/"+RepositoryName || workflow.Path == nil || *workflow.Path != releaseWorkflowPath {
		return errors.New("attestation provenance names a different workflow")
	}
	github := definition.InternalParameters.GitHub
	if github.EventName == nil || *github.EventName != "workflow_dispatch" || github.RepositoryID == nil || *github.RepositoryID != strconv.FormatInt(release.RepositoryID, 10) || github.RepositoryOwnerID == nil || *github.RepositoryOwnerID != strconv.FormatInt(release.RepositoryOwnerID, 10) || github.RunnerEnvironment == nil || *github.RunnerEnvironment != "github-hosted" {
		return errors.New("attestation provenance has a different GitHub identity")
	}
	dependency := (*definition.ResolvedDependencies)[0]
	if dependency.URI == nil || *dependency.URI != "git+https://github.com/"+RepositoryName+"@refs/heads/main" || dependency.Digest == nil || len(*dependency.Digest) != 1 || (*dependency.Digest)["gitCommit"] != release.SourceSHA {
		return errors.New("attestation provenance does not bind the release source")
	}
	if *run.Builder.ID != workflowIdentity(release) || *run.Metadata.InvocationID != invocationIdentity(release) {
		return errors.New("attestation provenance does not bind the release run")
	}
	return nil
}

// verifyTransparencyEntry returns integratedTime only after all local Rekor
// entry bindings have been validated. The preceding pinned gh verifier
// authenticates the same entry's inclusion proof and checkpoint.
func verifyTransparencyEntry(raw json.RawMessage, certificateDER, payload []byte, signatureBase64 string) (time.Time, error) {
	if err := verifyTransparencyEntryBindings(raw, certificateDER, payload, signatureBase64); err != nil {
		return time.Time{}, err
	}
	var entry transparencyLogEntry
	if err := decodeJSON(raw, &entry); err != nil || entry.IntegratedTime == nil {
		return time.Time{}, errors.New("attestation transparency log entry is malformed")
	}
	integratedUnix, err := parsePositiveInt64(*entry.IntegratedTime, "transparency log integrated time")
	if err != nil {
		return time.Time{}, errors.New("attestation transparency log time is invalid")
	}
	return time.Unix(integratedUnix, 0).UTC(), nil
}

func verifyTransparencyEntryBindings(raw json.RawMessage, certificateDER, payload []byte, signatureBase64 string) error {
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return errors.New("attestation transparency log entry is missing")
	}
	var entry transparencyLogEntry
	if err := decodeJSON(raw, &entry); err != nil || entry.LogIndex == nil || entry.LogID == nil || entry.LogID.KeyID == nil || entry.KindVersion == nil || entry.KindVersion.Kind == nil || entry.KindVersion.Version == nil || entry.IntegratedTime == nil || entry.InclusionProof == nil || entry.CanonicalizedBody == nil {
		return errors.New("attestation transparency log entry is malformed")
	}
	if _, err := parseNonNegativeInt64(*entry.LogIndex, "transparency log index"); err != nil || *entry.KindVersion.Kind != "dsse" || *entry.KindVersion.Version != "0.0.1" {
		return errors.New("attestation transparency log identity is invalid")
	}
	if _, err := parsePositiveInt64(*entry.IntegratedTime, "transparency log integrated time"); err != nil {
		return errors.New("attestation transparency log time is invalid")
	}
	keyID, err := decodeBoundedBase64(*entry.LogID.KeyID, 64)
	if err != nil || len(keyID) != sha256.Size {
		return errors.New("attestation transparency log key ID is invalid")
	}
	proof := entry.InclusionProof
	if proof.LogIndex == nil || proof.RootHash == nil || proof.TreeSize == nil || proof.Hashes == nil || proof.Checkpoint == nil || proof.Checkpoint.Envelope == nil || *proof.Checkpoint.Envelope == "" || strings.ContainsRune(*proof.Checkpoint.Envelope, '\x00') {
		return errors.New("attestation transparency inclusion proof is incomplete")
	}
	proofIndex, err := parseNonNegativeInt64(*proof.LogIndex, "transparency proof index")
	if err != nil {
		return errors.New("attestation transparency inclusion proof index is invalid")
	}
	treeSize, err := parsePositiveInt64(*proof.TreeSize, "transparency tree size")
	if err != nil || proofIndex >= treeSize {
		return errors.New("attestation transparency inclusion proof size is invalid")
	}
	rootHash, err := decodeBoundedBase64(*proof.RootHash, 64)
	if err != nil || len(rootHash) != sha256.Size || len(*proof.Hashes) > 64 {
		return errors.New("attestation transparency inclusion proof hash is invalid")
	}
	for _, encodedHash := range *proof.Hashes {
		hash, err := decodeBoundedBase64(encodedHash, 64)
		if err != nil || len(hash) != sha256.Size {
			return errors.New("attestation transparency inclusion proof contains an invalid hash")
		}
	}
	canonicalBody, err := decodeBoundedBase64(*entry.CanonicalizedBody, maxAttestationPayload)
	if err != nil {
		return errors.New("attestation transparency log body is invalid")
	}
	var body rekorDSSEBody
	if err := decodeJSON(canonicalBody, &body); err != nil || body.APIVersion == nil || *body.APIVersion != "0.0.1" || body.Kind == nil || *body.Kind != "dsse" || body.Spec == nil || body.Spec.PayloadHash == nil || body.Spec.PayloadHash.Algorithm == nil || body.Spec.PayloadHash.Value == nil || body.Spec.Signatures == nil || len(*body.Spec.Signatures) != 1 {
		return errors.New("attestation transparency log body is malformed")
	}
	payloadHash := sha256.Sum256(payload)
	if *body.Spec.PayloadHash.Algorithm != "sha256" || *body.Spec.PayloadHash.Value != hex.EncodeToString(payloadHash[:]) {
		return errors.New("attestation transparency log body does not bind the DSSE payload")
	}
	rekorSignature := (*body.Spec.Signatures)[0]
	if rekorSignature.Signature == nil || *rekorSignature.Signature != signatureBase64 || rekorSignature.Verifier == nil {
		return errors.New("attestation transparency log body does not bind the DSSE signature")
	}
	verifierPEM, err := decodeBoundedBase64(*rekorSignature.Verifier, maxAttestationCertificate*2)
	if err != nil {
		return errors.New("attestation transparency log verifier is invalid")
	}
	block, remainder := pem.Decode(verifierPEM)
	if block == nil || block.Type != "CERTIFICATE" || len(remainder) != 0 || !bytes.Equal(block.Bytes, certificateDER) {
		return errors.New("attestation transparency log body does not bind the signing certificate")
	}
	return nil
}

func decodeBoundedBase64(value string, maximum int) ([]byte, error) {
	if value == "" || len(value) > base64.StdEncoding.EncodedLen(maximum) {
		return nil, errors.New("base64 value exceeds its safety bound")
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || len(decoded) == 0 || len(decoded) > maximum {
		return nil, errors.New("invalid base64 value")
	}
	return decoded, nil
}

func parseNonNegativeInt64(raw, name string) (int64, error) {
	if raw == "0" {
		return 0, nil
	}
	return parsePositiveInt64(raw, name)
}

func workflowIdentity(release Context) string {
	return "https://github.com/" + release.Repository + "/" + releaseWorkflowPath + "@refs/heads/main"
}

func invocationIdentity(release Context) string {
	return fmt.Sprintf("https://github.com/%s/actions/runs/%d/attempts/%d", release.Repository, release.RunID, release.RunAttempt)
}
