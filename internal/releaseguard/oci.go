package releaseguard

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
)

const (
	maxOCIIndexSize                 = 1 << 20
	ociIndexMediaType               = "application/vnd.oci.image.index.v1+json"
	ociImageManifestMediaType       = "application/vnd.oci.image.manifest.v1+json"
	attestationReferenceDigest      = "vnd.docker.reference.digest"
	attestationReferenceType        = "vnd.docker.reference.type"
	attestationReferenceTypeValue   = "attestation-manifest"
	expectedOCIIndexDescriptorCount = 8
)

type ociIndexDocument struct {
	SchemaVersion *int                  `json:"schemaVersion"`
	MediaType     *string               `json:"mediaType"`
	Manifests     *[]ociIndexDescriptor `json:"manifests"`
}

type ociIndexDescriptor struct {
	MediaType   *string         `json:"mediaType"`
	Digest      *string         `json:"digest"`
	Size        *int64          `json:"size"`
	Platform    *ociPlatform    `json:"platform"`
	Annotations json.RawMessage `json:"annotations,omitempty"`
}

type ociPlatform struct {
	Architecture *string `json:"architecture"`
	OS           *string `json:"os"`
	Variant      *string `json:"variant,omitempty"`
}

// VerifyIndex validates the exact multi-platform OCI index produced for a
// release. It intentionally has no GitHub context or credential dependency so
// the raw registry response can be checked before any later release action.
func VerifyIndex(getenv func(string) string) error {
	if getenv == nil {
		return errors.New("OCI index environment is unavailable")
	}
	path := getenv("N2U_OCI_INDEX_PATH")
	if path == "" {
		return errors.New("N2U_OCI_INDEX_PATH is required")
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("N2U_OCI_INDEX_PATH must be an absolute canonical path")
	}
	expectedDigest := getenv("N2U_IMAGE_DIGEST")
	if !validDigest(expectedDigest) {
		return errors.New("N2U_IMAGE_DIGEST must be a lowercase sha256 digest")
	}

	payload, err := snapshotOCIIndex(path)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(payload)
	if "sha256:"+hex.EncodeToString(digest[:]) != expectedDigest {
		return errors.New("OCI index content does not match N2U_IMAGE_DIGEST")
	}
	return verifyOCIIndex(payload)
}

func snapshotOCIIndex(path string) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Size() <= 0 || before.Size() > maxOCIIndexSize {
		return nil, errors.New("OCI index is not a bounded regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("open OCI index")
	}
	after, statErr := file.Stat()
	if statErr != nil || !os.SameFile(before, after) {
		file.Close()
		return nil, errors.New("OCI index changed while opening")
	}
	payload, readErr := io.ReadAll(io.LimitReader(file, maxOCIIndexSize+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || int64(len(payload)) != after.Size() || len(payload) > maxOCIIndexSize {
		return nil, errors.New("read OCI index")
	}
	return payload, nil
}

func verifyOCIIndex(payload []byte) error {
	var document ociIndexDocument
	if err := decodeStrictOCIJSON(payload, &document); err != nil {
		return errors.New("OCI index is malformed")
	}
	if document.SchemaVersion == nil || *document.SchemaVersion != 2 || document.MediaType == nil || *document.MediaType != ociIndexMediaType || document.Manifests == nil {
		return errors.New("OCI index has an unsupported envelope")
	}
	if len(*document.Manifests) != expectedOCIIndexDescriptorCount {
		return errors.New("OCI index does not contain the exact manifest topology")
	}

	expectedPlatforms := map[string]struct{}{
		"linux/386":    {},
		"linux/amd64":  {},
		"linux/arm/v7": {},
		"linux/arm64":  {},
	}
	runnableDigests := make(map[string]string, len(expectedPlatforms))
	attestationLinks := make(map[string]struct{}, len(expectedPlatforms))
	allDigests := make(map[string]struct{}, expectedOCIIndexDescriptorCount)

	for _, descriptor := range *document.Manifests {
		if descriptor.MediaType == nil || *descriptor.MediaType != ociImageManifestMediaType || descriptor.Digest == nil || !validDigest(*descriptor.Digest) || descriptor.Size == nil || *descriptor.Size <= 0 || descriptor.Platform == nil || descriptor.Platform.OS == nil || descriptor.Platform.Architecture == nil {
			return errors.New("OCI index contains a malformed manifest descriptor")
		}
		if _, duplicate := allDigests[*descriptor.Digest]; duplicate {
			return errors.New("OCI index contains a duplicate manifest digest")
		}
		allDigests[*descriptor.Digest] = struct{}{}

		platform := descriptor.Platform
		if *platform.OS == "unknown" && *platform.Architecture == "unknown" {
			if platform.Variant != nil {
				return errors.New("OCI attestation descriptor has an unexpected platform variant")
			}
			link, err := validateAttestationAnnotations(descriptor.Annotations)
			if err != nil {
				return err
			}
			if _, duplicate := attestationLinks[link]; duplicate {
				return errors.New("OCI index contains duplicate attestation links")
			}
			attestationLinks[link] = struct{}{}
			continue
		}

		if len(descriptor.Annotations) != 0 && !bytes.Equal(bytes.TrimSpace(descriptor.Annotations), []byte("null")) {
			return errors.New("OCI runnable manifest has unexpected annotations")
		}
		platformName, ok := runnablePlatformName(platform)
		if !ok {
			return errors.New("OCI index contains an unexpected runnable platform")
		}
		if _, wanted := expectedPlatforms[platformName]; !wanted {
			return errors.New("OCI index contains an unexpected runnable platform")
		}
		if _, duplicate := runnableDigests[platformName]; duplicate {
			return errors.New("OCI index contains a duplicate runnable platform")
		}
		runnableDigests[platformName] = *descriptor.Digest
	}

	if len(runnableDigests) != len(expectedPlatforms) || len(attestationLinks) != len(expectedPlatforms) {
		return errors.New("OCI index does not contain the exact manifest topology")
	}
	for platform, digest := range runnableDigests {
		if _, linked := attestationLinks[digest]; !linked {
			return errors.New("OCI index attestation does not bind a runnable manifest")
		}
		delete(expectedPlatforms, platform)
	}
	if len(expectedPlatforms) != 0 {
		return errors.New("OCI index is missing a required runnable platform")
	}
	return nil
}

func decodeStrictOCIJSON(payload []byte, destination any) error {
	if len(payload) == 0 || rejectDuplicateJSONKeys(payload) != nil {
		return errors.New("invalid JSON")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON content")
	}
	return nil
}

func runnablePlatformName(platform *ociPlatform) (string, bool) {
	if platform == nil || platform.OS == nil || platform.Architecture == nil || *platform.OS != "linux" {
		return "", false
	}
	switch *platform.Architecture {
	case "386", "amd64", "arm64":
		if platform.Variant != nil {
			return "", false
		}
		return "linux/" + *platform.Architecture, true
	case "arm":
		if platform.Variant == nil || *platform.Variant != "v7" {
			return "", false
		}
		return "linux/arm/v7", true
	default:
		return "", false
	}
}

func validateAttestationAnnotations(raw json.RawMessage) (string, error) {
	if len(raw) == 0 {
		return "", errors.New("OCI attestation descriptor is missing annotations")
	}
	var annotations map[string]string
	if err := json.Unmarshal(raw, &annotations); err != nil || annotations == nil || len(annotations) != 2 {
		return "", errors.New("OCI attestation descriptor has malformed annotations")
	}
	link, hasLink := annotations[attestationReferenceDigest]
	referenceType, hasType := annotations[attestationReferenceType]
	if !hasLink || !hasType || !validDigest(link) || referenceType != attestationReferenceTypeValue {
		return "", errors.New("OCI attestation descriptor has malformed annotations")
	}
	return link, nil
}
