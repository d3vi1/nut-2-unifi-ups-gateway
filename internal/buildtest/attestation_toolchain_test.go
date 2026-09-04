package buildtest

import (
	"strings"
	"testing"
)

const (
	pinnedGHVersion       = "2.100.0"
	pinnedGHArchiveSHA256 = "e4d4bb4498e8d007abe545b6568926793ace1b6447da598294a610018cb164be"
	pinnedRootCommit      = "c9bda74ad2221f938f7d2e0295ca3aad2da710a8"
	pinnedTrustedRootSHA  = "6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66"
	pinnedRootJSONLSHA    = "3c2cc7f357dc064ec527fdcd78da6e9245c21a381e1abaa0f2b62b186bcac1a1"
)

func TestAttestationVerifierAndTrustRootArePinned(t *testing.T) {
	release := readRepositoryFile(t, ".github", "workflows", "release.yml")
	for name, want := range map[string]string{
		"GitHub CLI version":          `gh_version="` + pinnedGHVersion + `"`,
		"GitHub CLI archive digest":   `gh_sha256="` + pinnedGHArchiveSHA256 + `"`,
		"trusted root source commit":  `trusted_root_commit="` + pinnedRootCommit + `"`,
		"trusted root digest":         `trusted_root_sha256="` + pinnedTrustedRootSHA + `"`,
		"trusted root JSONL digest":   `trusted_root_jsonl_sha256="` + pinnedRootJSONLSHA + `"`,
		"immutable archive URL":       `https://github.com/cli/cli/releases/download/v${gh_version}/gh_${gh_version}_linux_amd64.tar.gz`,
		"immutable trusted-root URL":  `https://raw.githubusercontent.com/sigstore/root-signing/${trusted_root_commit}/targets/trusted_root.json`,
		"archive checksum validation": `sha256sum --check --strict -`,
		"vendored trusted root":       `--custom-trusted-root "$N2U_SIGSTORE_TRUST_ROOT"`,
		"offline bundle input":        `attestation verify "$N2U_OCI_INDEX_PATH"`,
	} {
		if !strings.Contains(release, want) {
			t.Errorf("release workflow is missing %s %q", name, want)
		}
	}
	if strings.Contains(release, "\n          gh attestation verify ") {
		t.Fatal("release workflow invokes the unpinned runner GitHub CLI")
	}

}
