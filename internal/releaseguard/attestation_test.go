package releaseguard

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

type testAttestationOptions struct {
	mutateStatement         func(*inTotoStatement)
	mutateClaims            func(map[string]string)
	certificateURI          string
	invalidSignature        bool
	omitTLog                bool
	integratedTime          *string
	omitIntegratedTime      bool
	duplicateIntegratedTime bool
}

func TestVerifyAttestationBundle(t *testing.T) {
	release := loadTestContext(t, validEnvironment())
	binding := mustTestBinding(t, release)
	now := time.Unix(1_800_000_000, 0).UTC()
	bundle := makeTestAttestationBundle(t, release, binding, now, testAttestationOptions{})
	if err := verifyAttestationBundle(release, binding, bundle, now); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyAttestationBundleUsesRekorIntegratedTime(t *testing.T) {
	release := loadTestContext(t, validEnvironment())
	binding := mustTestBinding(t, release)
	integratedTime := time.Unix(1_800_000_000, 0).UTC()
	bundle := makeTestAttestationBundle(t, release, binding, integratedTime, testAttestationOptions{})

	// Fulcio leaves are intentionally short-lived. Historical verification must
	// use the authenticated Rekor inclusion time, not the later observation time.
	if err := verifyAttestationBundle(release, binding, bundle, integratedTime.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyAttestationBundleRejectsIntegratedTimeOutsideCertificateValidity(t *testing.T) {
	release := loadTestContext(t, validEnvironment())
	binding := mustTestBinding(t, release)
	certificateTime := time.Unix(1_800_000_000, 0).UTC()
	tests := []struct {
		name           string
		integratedTime time.Time
		observedAt     time.Time
	}{
		{name: "before not-before", integratedTime: certificateTime.Add(-2 * time.Minute), observedAt: certificateTime},
		{name: "after not-after", integratedTime: certificateTime.Add(2 * time.Minute), observedAt: certificateTime.Add(3 * time.Minute)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			encodedTime := strconv.FormatInt(test.integratedTime.Unix(), 10)
			bundle := makeTestAttestationBundle(t, release, binding, certificateTime, testAttestationOptions{integratedTime: &encodedTime})
			if err := verifyAttestationBundle(release, binding, bundle, test.observedAt); err == nil {
				t.Fatal("attestation with an out-of-validity integrated time unexpectedly succeeded")
			}
		})
	}
}

func TestVerifyAttestationBundleIntegratedTimeFailsClosed(t *testing.T) {
	release := loadTestContext(t, validEnvironment())
	binding := mustTestBinding(t, release)
	now := time.Unix(1_800_000_000, 0).UTC()
	malformed := "not-an-integer"
	negative := "-1"
	tests := []struct {
		name    string
		options testAttestationOptions
	}{
		{name: "malformed", options: testAttestationOptions{integratedTime: &malformed}},
		{name: "missing", options: testAttestationOptions{omitIntegratedTime: true}},
		{name: "negative", options: testAttestationOptions{integratedTime: &negative}},
		{name: "duplicate", options: testAttestationOptions{duplicateIntegratedTime: true}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			bundle := makeTestAttestationBundle(t, release, binding, now, test.options)
			if err := verifyAttestationBundle(release, binding, bundle, now); err == nil {
				t.Fatal("attestation with an invalid integrated time unexpectedly succeeded")
			}
		})
	}
}

func TestVerifyAttestationBundleFailsClosed(t *testing.T) {
	release := loadTestContext(t, validEnvironment())
	binding := mustTestBinding(t, release)
	now := time.Unix(1_800_000_000, 0).UTC()
	tests := []struct {
		name    string
		options testAttestationOptions
	}{
		{
			name: "different subject digest",
			options: testAttestationOptions{mutateStatement: func(statement *inTotoStatement) {
				(*(*statement.Subject)[0].Digest)["sha256"] = strings.Repeat("b", 64)
			}},
		},
		{
			name: "different source commit",
			options: testAttestationOptions{mutateStatement: func(statement *inTotoStatement) {
				(*(*statement.Predicate.BuildDefinition.ResolvedDependencies)[0].Digest)["gitCommit"] = strings.Repeat("b", 40)
			}},
		},
		{
			name: "different workflow",
			options: testAttestationOptions{mutateStatement: func(statement *inTotoStatement) {
				other := ".github/workflows/other.yml"
				statement.Predicate.BuildDefinition.ExternalParameters.Workflow.Path = &other
			}},
		},
		{
			name: "different run attempt",
			options: testAttestationOptions{mutateStatement: func(statement *inTotoStatement) {
				other := strings.TrimSuffix(invocationIdentity(release), "/1") + "/2"
				statement.Predicate.RunDetails.Metadata.InvocationID = &other
			}},
		},
		{
			name: "different repository owner id",
			options: testAttestationOptions{mutateStatement: func(statement *inTotoStatement) {
				other := "9"
				statement.Predicate.BuildDefinition.InternalParameters.GitHub.RepositoryOwnerID = &other
			}},
		},
		{
			name:    "wrong certificate workflow URI",
			options: testAttestationOptions{certificateURI: "https://github.com/attacker/repository/.github/workflows/release.yml@refs/heads/main"},
		},
		{
			name: "wrong certificate source claim",
			options: testAttestationOptions{mutateClaims: func(claims map[string]string) {
				claims["1.3.6.1.4.1.57264.1.13"] = strings.Repeat("b", 40)
			}},
		},
		{name: "invalid DSSE signature", options: testAttestationOptions{invalidSignature: true}},
		{name: "missing transparency entry", options: testAttestationOptions{omitTLog: true}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			bundle := makeTestAttestationBundle(t, release, binding, now, test.options)
			if err := verifyAttestationBundle(release, binding, bundle, now); err == nil {
				t.Fatal("invalid attestation unexpectedly succeeded")
			}
		})
	}
	if err := verifyAttestationBundle(release, binding, []byte(`{"mediaType":`), now); err == nil {
		t.Fatal("malformed bundle unexpectedly succeeded")
	}
}

func TestVerifyAttestationFileBoundsAndPath(t *testing.T) {
	release := loadTestContext(t, validEnvironment())
	binding := mustTestBinding(t, release)
	now := time.Unix(1_800_000_000, 0).UTC()
	directory := t.TempDir()
	validPath := filepath.Join(directory, "attestation.json")
	if err := os.WriteFile(validPath, makeTestAttestationBundle(t, release, binding, now, testAttestationOptions{}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifyAttestationFile(release, binding, validPath, now); err != nil {
		t.Fatal(err)
	}
	linkPath := filepath.Join(directory, "link.json")
	if err := os.Symlink(validPath, linkPath); err != nil {
		t.Fatal(err)
	}
	if err := verifyAttestationFile(release, binding, linkPath, now); err == nil {
		t.Fatal("symlinked bundle unexpectedly succeeded")
	}
	largePath := filepath.Join(directory, "large.json")
	if err := os.WriteFile(largePath, make([]byte, maxAttestationBundleSize+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifyAttestationFile(release, binding, largePath, now); err == nil {
		t.Fatal("oversized bundle unexpectedly succeeded")
	}
}

func TestVerifyAttestationRepeatsRemoteTrust(t *testing.T) {
	environment, release, guard, _, closeServer := setupReservedRelease(t)
	defer closeServer()
	binding := mustTestBinding(t, release)
	path := filepath.Join(t.TempDir(), "attestation.json")
	if err := os.WriteFile(path, makeTestAttestationBundle(t, release, binding, time.Now(), testAttestationOptions{}), 0o600); err != nil {
		t.Fatal(err)
	}
	environment["N2U_ATTESTATION_BUNDLE"] = path
	if err := guard.VerifyAttestation(t.Context(), release, mapLookup(environment)); err != nil {
		t.Fatal(err)
	}
}

func makeTestAttestationBundle(t *testing.T, release Context, binding bindingInput, now time.Time, options testAttestationOptions) []byte {
	t.Helper()
	statement := testProvenanceStatement(release, binding)
	if options.mutateStatement != nil {
		options.mutateStatement(&statement)
	}
	statementJSON, err := json.Marshal(statement)
	if err != nil {
		t.Fatal(err)
	}
	claims := testCertificateClaims(release)
	if options.mutateClaims != nil {
		options.mutateClaims(claims)
	}
	certificateURI := options.certificateURI
	if certificateURI == "" {
		certificateURI = workflowIdentity(release)
	}
	privateKey, certificateDER := makeTestCertificate(t, now, certificateURI, claims)
	pae := []byte("DSSEv1 " + strconv.Itoa(len(dssePayloadType)) + " " + dssePayloadType + " " + strconv.Itoa(len(statementJSON)) + " ")
	pae = append(pae, statementJSON...)
	digest := sha256.Sum256(pae)
	signature, err := ecdsa.SignASN1(rand.Reader, privateKey, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	if options.invalidSignature {
		signature[len(signature)-1] ^= 1
	}
	signatureBase64 := base64.StdEncoding.EncodeToString(signature)
	payloadHash := sha256.Sum256(statementJSON)
	verifier := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER}))
	rekorBody, err := json.Marshal(map[string]any{
		"apiVersion": "0.0.1",
		"kind":       "dsse",
		"spec": map[string]any{
			"payloadHash": map[string]string{"algorithm": "sha256", "value": hex.EncodeToString(payloadHash[:])},
			"signatures":  []any{map[string]string{"signature": signatureBase64, "verifier": base64.StdEncoding.EncodeToString([]byte(verifier))}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	integratedTime := strconv.FormatInt(now.Unix(), 10)
	if options.integratedTime != nil {
		integratedTime = *options.integratedTime
	}
	tlogEntry := map[string]any{
		"logIndex":       "7",
		"logId":          map[string]string{"keyId": base64.StdEncoding.EncodeToString(make([]byte, sha256.Size))},
		"kindVersion":    map[string]string{"kind": "dsse", "version": "0.0.1"},
		"integratedTime": integratedTime,
		"inclusionProof": map[string]any{
			"logIndex": "7", "rootHash": base64.StdEncoding.EncodeToString(make([]byte, sha256.Size)),
			"treeSize": "8", "hashes": []string{}, "checkpoint": map[string]string{"envelope": "rekor.example - 1\n8\nroot\n"},
		},
		"canonicalizedBody": base64.StdEncoding.EncodeToString(rekorBody),
	}
	if options.omitIntegratedTime {
		delete(tlogEntry, "integratedTime")
	}
	tlogEntryJSON, err := json.Marshal(tlogEntry)
	if err != nil {
		t.Fatal(err)
	}
	if options.duplicateIntegratedTime {
		needle := []byte(`"integratedTime":"` + integratedTime + `"`)
		replacement := []byte(`"integratedTime":"` + integratedTime + `","integratedTime":"` + integratedTime + `"`)
		withDuplicate := bytes.Replace(tlogEntryJSON, needle, replacement, 1)
		if bytes.Equal(withDuplicate, tlogEntryJSON) {
			t.Fatal("test fixture did not contain integratedTime")
		}
		tlogEntryJSON = withDuplicate
	}
	tlogEntries := []json.RawMessage{tlogEntryJSON}
	if options.omitTLog {
		tlogEntries = nil
	}
	bundle := map[string]any{
		"mediaType": sigstoreBundleMediaType,
		"verificationMaterial": map[string]any{
			"certificate": map[string]string{"rawBytes": base64.StdEncoding.EncodeToString(certificateDER)},
			"tlogEntries": tlogEntries,
		},
		"dsseEnvelope": map[string]any{
			"payload": base64.StdEncoding.EncodeToString(statementJSON), "payloadType": dssePayloadType,
			"signatures": []any{map[string]string{"sig": signatureBase64}},
		},
	}
	encoded, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func testProvenanceStatement(release Context, binding bindingInput) inTotoStatement {
	typeValue := inTotoStatementType
	name := ImageName
	digests := map[string]string{"sha256": strings.TrimPrefix(binding.digest, "sha256:")}
	predicateType := slsaProvenanceType
	buildType := githubWorkflowBuildType
	ref := "refs/heads/main"
	repository := "https://github.com/" + RepositoryName
	path := releaseWorkflowPath
	event := "workflow_dispatch"
	repositoryID := strconv.FormatInt(release.RepositoryID, 10)
	ownerID := strconv.FormatInt(release.RepositoryOwnerID, 10)
	runner := "github-hosted"
	dependencyURI := "git+https://github.com/" + RepositoryName + "@refs/heads/main"
	dependencyDigests := map[string]string{"gitCommit": release.SourceSHA}
	builder := workflowIdentity(release)
	invocation := invocationIdentity(release)
	return inTotoStatement{
		Type: &typeValue, Subject: &[]inTotoSubject{{Name: &name, Digest: &digests}}, PredicateType: &predicateType,
		Predicate: &provenancePredicate{
			BuildDefinition: &provenanceBuildDefinition{
				BuildType:            &buildType,
				ExternalParameters:   &provenanceExternalParameters{Workflow: &provenanceWorkflow{Ref: &ref, Repository: &repository, Path: &path}},
				InternalParameters:   &provenanceInternalParameters{GitHub: &provenanceGitHub{EventName: &event, RepositoryID: &repositoryID, RepositoryOwnerID: &ownerID, RunnerEnvironment: &runner}},
				ResolvedDependencies: &[]provenanceDependency{{URI: &dependencyURI, Digest: &dependencyDigests}},
			},
			RunDetails: &provenanceRunDetails{Builder: &provenanceBuilder{ID: &builder}, Metadata: &provenanceMetadata{InvocationID: &invocation}},
		},
	}
}

func testCertificateClaims(release Context) map[string]string {
	return map[string]string{
		"1.3.6.1.4.1.57264.1.8":  "https://token.actions.githubusercontent.com",
		"1.3.6.1.4.1.57264.1.9":  workflowIdentity(release),
		"1.3.6.1.4.1.57264.1.10": release.SourceSHA,
		"1.3.6.1.4.1.57264.1.11": "github-hosted",
		"1.3.6.1.4.1.57264.1.12": "https://github.com/" + RepositoryName,
		"1.3.6.1.4.1.57264.1.13": release.SourceSHA,
		"1.3.6.1.4.1.57264.1.14": "refs/heads/main",
		"1.3.6.1.4.1.57264.1.15": strconv.FormatInt(release.RepositoryID, 10),
		"1.3.6.1.4.1.57264.1.16": "https://github.com/" + RepositoryOwner,
		"1.3.6.1.4.1.57264.1.17": strconv.FormatInt(release.RepositoryOwnerID, 10),
		"1.3.6.1.4.1.57264.1.18": workflowIdentity(release),
		"1.3.6.1.4.1.57264.1.19": release.SourceSHA,
		"1.3.6.1.4.1.57264.1.20": "workflow_dispatch",
		"1.3.6.1.4.1.57264.1.21": invocationIdentity(release),
		"1.3.6.1.4.1.57264.1.22": "public",
	}
}

func makeTestCertificate(t *testing.T, now time.Time, identity string, claims map[string]string) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issuerTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{Organization: []string{"sigstore.dev"}, CommonName: "sigstore-intermediate"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	issuerDER, err := x509.CreateCertificate(rand.Reader, issuerTemplate, issuerTemplate, &issuerKey.PublicKey, issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := x509.ParseCertificate(issuerDER)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	parsedURI, err := url.Parse(identity)
	if err != nil {
		t.Fatal(err)
	}
	extensions := make([]pkix.Extension, 0, len(claims))
	for oid, value := range claims {
		extensions = append(extensions, testExtension(t, oid, value))
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Minute),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		URIs: []*url.URL{parsedURI}, ExtraExtensions: extensions,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, issuer, &leafKey.PublicKey, issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	return leafKey, leafDER
}

func testExtension(t *testing.T, oid, value string) pkix.Extension {
	t.Helper()
	identifier := make(asn1.ObjectIdentifier, 0, 8)
	for _, component := range strings.Split(oid, ".") {
		number, err := strconv.Atoi(component)
		if err != nil {
			t.Fatal(err)
		}
		identifier = append(identifier, number)
	}
	encoded, err := asn1.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return pkix.Extension{Id: identifier, Value: encoded}
}
