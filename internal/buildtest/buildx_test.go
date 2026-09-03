package buildtest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	pinnedBuildxVersion  = "v0.37.0"
	pinnedBuildxSHA256   = "ae43fa08c796b44efc86d7a63c55f73f7c35f3101188dea7bf93bcd6f99577ba"
	pinnedBuildKitImage  = "moby/buildkit:v0.33.0@sha256:6c2fa84a6b61ccd72899dde4239f8d5717f05f9a8ca6f3cad185fb1a95a94de3"
	pinnedSBOMGenerator  = "docker.io/docker/buildkit-syft-scanner:1.12.0@sha256:ae4f3b554449e7e25548e7d8ccc029d17357348e30c6e3df01b92bc93654d6a9"
	localBuildxAction    = "uses: ./.github/actions/setup-pinned-buildx"
	remoteBuildxAction   = "docker/setup-buildx-action@"
	buildxBuilderBinding = "builder: ${{ steps.buildx.outputs.builder }}"
)

func TestBuildxAndBuildKitAreImmutable(t *testing.T) {
	action := readRepositoryFile(t, ".github", "actions", "setup-pinned-buildx", "action.yml")

	for name, want := range map[string]string{
		"Buildx version":           `buildx_version="` + pinnedBuildxVersion + `"`,
		"Buildx asset checksum":    `buildx_sha256="` + pinnedBuildxSHA256 + `"`,
		"BuildKit image digest":    `buildkit_image="` + pinnedBuildKitImage + `"`,
		"checksum verification":    "sha256sum --check --strict -",
		"digest-pinned driver use": `--driver-opt "image=$buildkit_image"`,
	} {
		if !strings.Contains(action, want) {
			t.Errorf("local Buildx action is missing %s %q", name, want)
		}
	}

	wantURL := `https://github.com/docker/buildx/releases/download/${buildx_version}/buildx-${buildx_version}.linux-amd64`
	if !strings.Contains(action, wantURL) {
		t.Errorf("local Buildx action is missing reviewed download URL %q", wantURL)
	}

	ordered := []string{
		"curl --fail --location",
		"sha256sum --check --strict -",
		`install -m 0755 "$download_path" "$plugin_path"`,
		"docker buildx version",
		"docker buildx create",
		`docker buildx inspect "$builder_name" --bootstrap`,
	}
	previous := -1
	for _, marker := range ordered {
		position := strings.Index(action, marker)
		if position < 0 {
			t.Errorf("local Buildx action is missing ordered operation %q", marker)
			continue
		}
		if position <= previous {
			t.Errorf("local Buildx action executes %q out of the reviewed order", marker)
		}
		previous = position
	}
}

func TestPublishingBuildIsCacheColdAndPinsItsSBOMGenerator(t *testing.T) {
	release := readRepositoryFile(t, ".github", "workflows", "release.yml")
	start := strings.Index(release, "      - name: Build and push image with SBOM and provenance\n")
	end := strings.Index(release, "\n  publish-release:\n")
	if start < 0 || end <= start {
		t.Fatal("cannot isolate the publishing build step")
	}
	publishBuild := release[start:end]

	for name, want := range map[string]string{
		"push output":           "          push: true\n",
		"cold build":            "          no-cache: true\n",
		"attestation block":     "          attests: |\n",
		"pinned SBOM generator": "type=sbom,generator=" + pinnedSBOMGenerator,
	} {
		if got := strings.Count(publishBuild, want); got != 1 {
			t.Errorf("publishing build contains %d %s markers %q; want 1", got, name, want)
		}
	}
	for name, forbidden := range map[string]string{
		"remote cache import":     "cache-from:",
		"cache export":            "cache-to:",
		"dedicated SBOM override": "\n          sbom:",
	} {
		if strings.Contains(publishBuild, forbidden) {
			t.Errorf("publishing build contains forbidden %s %q", name, forbidden)
		}
	}
}

func TestWorkflowsUseOnlyThePinnedLocalBuilder(t *testing.T) {
	for _, workflow := range []string{"ci.yml", "release.yml"} {
		contents := readRepositoryFile(t, ".github", "workflows", workflow)
		if strings.Contains(contents, remoteBuildxAction) {
			t.Errorf("%s must not invoke the mutable remote Buildx setup action", workflow)
		}
		if got := strings.Count(contents, localBuildxAction); got != 1 {
			t.Errorf("%s contains %d local Buildx setup actions; want 1", workflow, got)
		}
		if got := strings.Count(contents, buildxBuilderBinding); got != 1 {
			t.Errorf("%s contains %d pinned builder bindings; want 1", workflow, got)
		}
	}
}

func readRepositoryFile(t *testing.T, elements ...string) string {
	t.Helper()
	path := filepath.Clean(filepath.Join(append([]string{"..", ".."}, elements...)...))
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(contents)
}
