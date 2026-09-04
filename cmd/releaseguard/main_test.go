package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunRejectsUsageWithoutNetworkAccess(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), nil, func(string) string { return "" }, &stdout, &stderr); code != 2 {
		t.Fatalf("run() = %d, want 2", code)
	}
	if stdout.Len() != 0 || !strings.Contains(stderr.String(), "usage:") {
		t.Fatal("usage failure output mismatch")
	}
}

func TestRunDoesNotEchoInvalidEnvironmentValues(t *testing.T) {
	const sentinel = "credential-sentinel-never-echo"
	environment := map[string]string{
		"GITHUB_REPOSITORY":        "attacker/repository",
		"GH_TOKEN":                 sentinel,
		"N2U_RELEASE_POLICY_TOKEN": sentinel,
	}
	getenv := func(name string) string { return environment[name] }
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"trust"}, getenv, &stdout, &stderr); code != 2 {
		t.Fatalf("run() = %d, want 2", code)
	}
	if strings.Contains(stderr.String(), sentinel) || stdout.Len() != 0 {
		t.Fatal("invalid environment output exposed a credential")
	}
}

func TestRunVerifyIndexDoesNotRequireGitHubContextOrTokens(t *testing.T) {
	payload := []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111","size":1,"platform":{"architecture":"amd64","os":"linux"}},{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:2222222222222222222222222222222222222222222222222222222222222222","size":2,"platform":{"architecture":"arm64","os":"linux"}},{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:3333333333333333333333333333333333333333333333333333333333333333","size":3,"platform":{"architecture":"arm","os":"linux","variant":"v7"}},{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:4444444444444444444444444444444444444444444444444444444444444444","size":4,"platform":{"architecture":"386","os":"linux"}},{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size":5,"platform":{"architecture":"unknown","os":"unknown"},"annotations":{"vnd.docker.reference.digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111","vnd.docker.reference.type":"attestation-manifest"}},{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","size":6,"platform":{"architecture":"unknown","os":"unknown"},"annotations":{"vnd.docker.reference.digest":"sha256:2222222222222222222222222222222222222222222222222222222222222222","vnd.docker.reference.type":"attestation-manifest"}},{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","size":7,"platform":{"architecture":"unknown","os":"unknown"},"annotations":{"vnd.docker.reference.digest":"sha256:3333333333333333333333333333333333333333333333333333333333333333","vnd.docker.reference.type":"attestation-manifest"}},{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","size":8,"platform":{"architecture":"unknown","os":"unknown"},"annotations":{"vnd.docker.reference.digest":"sha256:4444444444444444444444444444444444444444444444444444444444444444","vnd.docker.reference.type":"attestation-manifest"}}]}`)
	path := filepath.Join(t.TempDir(), "index.json")
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(payload)
	environment := map[string]string{
		"N2U_OCI_INDEX_PATH": path,
		"N2U_IMAGE_DIGEST":   "sha256:" + hex.EncodeToString(digest[:]),
	}
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"verify-index"}, func(name string) string { return environment[name] }, &stdout, &stderr); code != 0 {
		t.Fatalf("run() = %d, stderr = %q", code, stderr.String())
	}
	if stderr.Len() != 0 || stdout.String() != "releaseguard: verify-index verified\n" {
		t.Fatal("verify-index success output mismatch")
	}
}
