package releaseguard

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifyIndexAcceptsExactFourPlatformTopology(t *testing.T) {
	payload := validOCIIndexPayload(t)
	path := filepath.Join(t.TempDir(), "index.json")
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(payload)
	environment := map[string]string{
		"N2U_OCI_INDEX_PATH": path,
		"N2U_IMAGE_DIGEST":   "sha256:" + hex.EncodeToString(digest[:]),
	}
	if err := VerifyIndex(func(name string) string { return environment[name] }); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyOCIIndexRejectsTopologyAndDescriptorSubstitution(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*ociIndexDocument)
	}{
		{
			name: "missing runnable platform",
			mutate: func(document *ociIndexDocument) {
				manifests := *document.Manifests
				*document.Manifests = append(manifests[:3], manifests[4:]...)
			},
		},
		{
			name: "duplicate runnable platform",
			mutate: func(document *ociIndexDocument) {
				duplicate := (*document.Manifests)[0]
				duplicate.Digest = stringPointer("sha256:" + strings.Repeat("9", 64))
				(*document.Manifests)[1] = duplicate
			},
		},
		{
			name: "unexpected runnable platform",
			mutate: func(document *ociIndexDocument) {
				(*document.Manifests)[0].Platform.Architecture = stringPointer("s390x")
			},
		},
		{
			name: "wrong attestation link",
			mutate: func(document *ociIndexDocument) {
				(*document.Manifests)[4].Annotations = mustJSON(t, map[string]string{
					attestationReferenceDigest: "sha256:" + strings.Repeat("f", 64),
					attestationReferenceType:   attestationReferenceTypeValue,
				})
			},
		},
		{
			name: "malformed attestation digest",
			mutate: func(document *ociIndexDocument) {
				(*document.Manifests)[4].Digest = stringPointer("sha256:not-a-digest")
			},
		},
		{
			name: "duplicate attestation link",
			mutate: func(document *ociIndexDocument) {
				(*document.Manifests)[5].Annotations = append(json.RawMessage(nil), (*document.Manifests)[4].Annotations...)
			},
		},
		{
			name: "unexpected descriptor media type",
			mutate: func(document *ociIndexDocument) {
				(*document.Manifests)[0].MediaType = stringPointer("application/vnd.docker.distribution.manifest.v2+json")
			},
		},
		{
			name: "non-positive descriptor size",
			mutate: func(document *ociIndexDocument) {
				(*document.Manifests)[0].Size = int64Pointer(0)
			},
		},
		{
			name: "extra attestation annotation",
			mutate: func(document *ociIndexDocument) {
				(*document.Manifests)[4].Annotations = mustJSON(t, map[string]string{
					attestationReferenceDigest: "sha256:" + strings.Repeat("1", 64),
					attestationReferenceType:   attestationReferenceTypeValue,
					"unexpected":               "value",
				})
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			document := validOCIIndexDocument(t)
			test.mutate(&document)
			payload, err := json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			if err := verifyOCIIndex(payload); err == nil {
				t.Fatal("invalid OCI index unexpectedly succeeded")
			}
		})
	}
}

func TestVerifyOCIIndexRejectsMalformedOrAmbiguousJSON(t *testing.T) {
	valid := validOCIIndexPayload(t)
	tests := [][]byte{
		nil,
		[]byte(`{"schemaVersion":2,"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[]}`),
		[]byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[],"unexpected":true}`),
		append(append([]byte(nil), valid...), []byte(" trailing")...),
	}
	for _, payload := range tests {
		if err := verifyOCIIndex(payload); err == nil {
			t.Fatalf("verifyOCIIndex(%q) unexpectedly succeeded", payload)
		}
	}
}

func TestVerifyIndexRejectsUnsafeFileAndDigestInputs(t *testing.T) {
	payload := validOCIIndexPayload(t)
	directory := t.TempDir()
	path := filepath.Join(directory, "index.json")
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(payload)
	validDigest := "sha256:" + hex.EncodeToString(digest[:])

	tests := []struct {
		name        string
		path        string
		digest      string
		preparePath func() string
	}{
		{name: "relative path", path: "index.json", digest: validDigest},
		{name: "noncanonical path", path: directory + "/./nested/../index.json", digest: validDigest},
		{name: "wrong digest", path: path, digest: "sha256:" + strings.Repeat("f", 64)},
		{name: "malformed digest", path: path, digest: "sha256:bad"},
		{
			name:   "symbolic link",
			digest: validDigest,
			preparePath: func() string {
				link := filepath.Join(directory, "index-link.json")
				if err := os.Symlink(path, link); err != nil {
					t.Fatal(err)
				}
				return link
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			testPath := test.path
			if test.preparePath != nil {
				testPath = test.preparePath()
			}
			environment := map[string]string{
				"N2U_OCI_INDEX_PATH": testPath,
				"N2U_IMAGE_DIGEST":   test.digest,
			}
			if err := VerifyIndex(func(name string) string { return environment[name] }); err == nil {
				t.Fatal("unsafe OCI index input unexpectedly succeeded")
			}
		})
	}
}

func validOCIIndexPayload(t *testing.T) []byte {
	t.Helper()
	payload, err := json.Marshal(validOCIIndexDocument(t))
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func validOCIIndexDocument(t *testing.T) ociIndexDocument {
	t.Helper()
	runnable := []struct {
		architecture string
		variant      *string
		digest       string
	}{
		{architecture: "amd64", digest: "sha256:" + strings.Repeat("1", 64)},
		{architecture: "arm64", digest: "sha256:" + strings.Repeat("2", 64)},
		{architecture: "arm", variant: stringPointer("v7"), digest: "sha256:" + strings.Repeat("3", 64)},
		{architecture: "386", digest: "sha256:" + strings.Repeat("4", 64)},
	}
	manifests := make([]ociIndexDescriptor, 0, expectedOCIIndexDescriptorCount)
	for index, item := range runnable {
		var annotations json.RawMessage
		if index == 0 {
			annotations = json.RawMessage("null")
		}
		manifests = append(manifests, ociIndexDescriptor{
			MediaType:   stringPointer(ociImageManifestMediaType),
			Digest:      stringPointer(item.digest),
			Size:        int64Pointer(int64(1_000 + index)),
			Annotations: annotations,
			Platform: &ociPlatform{
				Architecture: stringPointer(item.architecture),
				OS:           stringPointer("linux"),
				Variant:      item.variant,
			},
		})
	}
	for index, item := range runnable {
		manifests = append(manifests, ociIndexDescriptor{
			MediaType: stringPointer(ociImageManifestMediaType),
			Digest:    stringPointer("sha256:" + strings.Repeat(string(rune('a'+index)), 64)),
			Size:      int64Pointer(int64(2_000 + index)),
			Platform: &ociPlatform{
				Architecture: stringPointer("unknown"),
				OS:           stringPointer("unknown"),
			},
			Annotations: mustJSON(t, map[string]string{
				attestationReferenceDigest: item.digest,
				attestationReferenceType:   attestationReferenceTypeValue,
			}),
		})
	}
	version := 2
	return ociIndexDocument{
		SchemaVersion: &version,
		MediaType:     stringPointer(ociIndexMediaType),
		Manifests:     &manifests,
	}
}

func mustJSON(t *testing.T, value any) json.RawMessage {
	t.Helper()
	payload, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func stringPointer(value string) *string {
	return &value
}

func int64Pointer(value int64) *int64 {
	return &value
}
