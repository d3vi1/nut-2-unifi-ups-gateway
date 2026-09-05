package buildtest

import (
	"strings"
	"testing"
)

func TestReleaseControllerRunsOnlyFromLiveDefaultBranchWorkflow(t *testing.T) {
	release := readRepositoryFile(t, ".github", "workflows", "release.yml")

	for name, want := range map[string]string{
		"main push trigger":          "  push:\n    branches: [main]\n",
		"manual release trigger":     "  workflow_dispatch:\n",
		"explicit release input":     "      release_tag:\n",
		"serialized release group":   "group: publish-${{ github.event_name == 'workflow_dispatch' && 'release' || github.ref }}",
		"release trust preflight":    "run: go run ./cmd/releaseguard trust",
		"attestation verification":   "run: go run ./cmd/releaseguard verify-attestation",
		"Sigstore root verification": "\"$N2U_GH_ATTEST\" attestation verify \"$N2U_OCI_INDEX_PATH\"",
		"pinned attestation action":  "uses: actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6 # v4.2.2",
	} {
		if !strings.Contains(release, want) {
			t.Errorf("release workflow is missing %s %q", name, want)
		}
	}
	for name, forbidden := range map[string]string{
		"tag push trigger": "    tags: [\"v*\"]",
		"always condition": "always()",
		"tag-ref release":  "github.ref_type == 'tag'",
	} {
		if strings.Contains(release, forbidden) {
			t.Errorf("release workflow contains forbidden %s %q", name, forbidden)
		}
	}
}

func TestReleaseJobsAreMonotonicAndPermissionIsolated(t *testing.T) {
	release := readRepositoryFile(t, ".github", "workflows", "release.yml")
	ordered := []string{
		"  verify:\n",
		"  publish-edge:\n",
		"  reserve-release:\n",
		"  publish-release-image:\n",
		"  bind-release:\n",
		"  finalize-release:\n",
	}
	previous := -1
	for _, marker := range ordered {
		position := strings.Index(release, marker)
		if position < 0 {
			t.Errorf("release workflow is missing job %q", marker)
			continue
		}
		if position <= previous {
			t.Errorf("release job %q is out of monotonic order", marker)
		}
		previous = position
	}

	reserve := isolateWorkflowJob(t, release, "reserve-release", "publish-release-image")
	image := isolateWorkflowJob(t, release, "publish-release-image", "bind-release")
	bind := isolateWorkflowJob(t, release, "bind-release", "finalize-release")
	finalize := release[strings.Index(release, "  finalize-release:\n"):]

	assertContainsExactly(t, reserve, "contents: write", 1)
	assertContainsExactly(t, reserve, "packages: write", 0)
	assertContainsExactly(t, reserve, "go run ./cmd/releaseguard reserve", 1)

	assertContainsExactly(t, image, "packages: write", 1)
	assertContainsExactly(t, image, "contents: write", 0)
	assertContainsExactly(t, image, "attestations: write", 1)
	assertContainsExactly(t, image, "go run ./cmd/releaseguard verify-reserved", 0)
	assertContainsExactly(t, image, "go run ./cmd/releaseguard verify-image-source", 1)
	assertContainsExactly(t, image, "N2U_RELEASE_ID:", 0)
	assertContainsExactly(t, image, "go run ./cmd/releaseguard verify-attestation", 1)

	assertContainsExactly(t, bind, "contents: write", 1)
	assertContainsExactly(t, bind, "packages: write", 0)
	assertContainsExactly(t, bind, "go run ./cmd/releaseguard bind", 1)

	assertContainsExactly(t, finalize, "contents: write", 1)
	assertContainsExactly(t, finalize, "packages: write", 0)
	assertContainsExactly(t, finalize, "go run ./cmd/releaseguard upload-assets", 1)
	assertContainsExactly(t, finalize, "go run ./cmd/releaseguard publish", 1)
}

func TestReleaseRerunsAndMissingOutputsFailBeforeMutation(t *testing.T) {
	release := readRepositoryFile(t, ".github", "workflows", "release.yml")
	if got := strings.Count(release, "if: github.event_name == 'workflow_dispatch' && github.run_attempt == 1"); got != 4 {
		t.Fatalf("release workflow has %d job-level first-attempt guards; want 4", got)
	}
	if got := strings.Count(release, "\"$GITHUB_RUN_ATTEMPT\" != \"1\""); got != 5 {
		t.Fatalf("release workflow has %d first-attempt guards; want 5", got)
	}
	for _, output := range []string{
		"reservation_attempt",
		"publication_attempt",
		"binding_attempt",
	} {
		if got := strings.Count(release, output); got < 3 {
			t.Errorf("release workflow does not propagate and recheck %s; found %d references", output, got)
		}
	}

	image := isolateWorkflowJob(t, release, "publish-release-image", "bind-release")
	guard := strings.Index(image, "Refuse missing, stale, or rerun reservation state")
	login := strings.Index(image, "Log in to GHCR")
	push := strings.Index(image, "Build and push release image")
	if guard < 0 || login <= guard || push <= login {
		t.Fatal("release image mutation is not preceded by the rerun guard")
	}
}

func TestReleaseImageHasNoVersionAliasAndUsesPermanentUniqueAnchor(t *testing.T) {
	release := readRepositoryFile(t, ".github", "workflows", "release.yml")
	image := isolateWorkflowJob(t, release, "publish-release-image", "bind-release")
	edge := isolateWorkflowJob(t, release, "publish-edge", "reserve-release")

	assertContainsExactly(t, edge, "type=raw,value=edge", 1)
	assertContainsExactly(t, image, "tags: ${{ env.IMAGE_NAME }}:${{ needs.reserve-release.outputs.oci_tag }}", 1)

	for name, forbidden := range map[string]string{
		"SemVer metadata tag": "type=semver",
		"latest tag":          "value=latest",
		"major/minor alias":   "pattern={{major}}",
		"release edge alias":  "type=raw,value=edge",
		"ref-derived alias":   "type=ref",
		"SHA alias":           "type=sha",
	} {
		if strings.Contains(image, forbidden) {
			t.Errorf("release image job contains forbidden %s %q", name, forbidden)
		}
	}
	if got := strings.Count(release, "imagetools inspect"); got != 2 {
		t.Fatalf("release workflow performs %d OCI anchor readbacks; want 2", got)
	}
	if got := strings.Count(release, "go run ./cmd/releaseguard verify-index"); got != 2 {
		t.Fatalf("release workflow performs %d OCI topology verifications; want 2", got)
	}

	attest := strings.Index(image, "Attest the published image digest")
	logout := strings.Index(image, "Remove the GHCR publication credential")
	installVerifier := strings.Index(image, "Install the pinned GitHub attestation verifier")
	verifyRoots := strings.Index(image, "Verify attestation roots and exact workflow identity")
	verify := strings.Index(image, "Verify exact attestation semantics and remote bindings")
	export := strings.Index(image, "Export bound publication identity")
	if attest < 0 || logout <= attest || installVerifier <= logout || verifyRoots <= installVerifier || verify <= verifyRoots || export <= verify {
		t.Fatal("release identity is exported before its attestation bundle is verified")
	}
	credentialRemovalStep := image[logout:installVerifier]
	for _, want := range []string{
		"docker logout ghcr.io",
		`[[ ! -f "$docker_config_file" ]]`,
		`(has("ghcr.io") | not)`,
		`[[ ! -x "$DOCKER_CONFIG/cli-plugins/docker-buildx" ]]`,
	} {
		if !strings.Contains(credentialRemovalStep, want) {
			t.Errorf("GHCR credential removal is missing %q", want)
		}
	}
	for _, forbidden := range []string{
		`rm -rf "$DOCKER_CONFIG"`,
		`rm -f "$DOCKER_CONFIG/config.json"`,
	} {
		if strings.Contains(credentialRemovalStep, forbidden) {
			t.Errorf("GHCR credential removal destroys dedicated Docker state with %q", forbidden)
		}
	}
	verifierInstallStep := image[installVerifier:verifyRoots]
	for _, want := range []string{
		"unset GH_TOKEN GITHUB_TOKEN GH_ENTERPRISE_TOKEN GITHUB_ENTERPRISE_TOKEN",
		"unset ACTIONS_ID_TOKEN_REQUEST_TOKEN ACTIONS_ID_TOKEN_REQUEST_URL ACTIONS_RUNTIME_TOKEN ACTIONS_RUNTIME_URL ACTIONS_CACHE_URL ACTIONS_RESULTS_URL",
	} {
		if !strings.Contains(verifierInstallStep, want) {
			t.Errorf("attestation verifier installation retains a publication credential: missing %q", want)
		}
	}
	rootVerificationStep := image[verifyRoots:verify]
	for _, want := range []string{
		"unset GH_TOKEN GITHUB_TOKEN GH_ENTERPRISE_TOKEN GITHUB_ENTERPRISE_TOKEN",
		"unset ACTIONS_ID_TOKEN_REQUEST_TOKEN ACTIONS_ID_TOKEN_REQUEST_URL ACTIONS_RUNTIME_TOKEN ACTIONS_RUNTIME_URL ACTIONS_CACHE_URL ACTIONS_RESULTS_URL",
		`install -d -m 0700 "$verifier_home"`,
		"/usr/bin/env -i",
		`HOME="$verifier_home"`,
		"PATH=/usr/bin:/bin",
		"--digest-alg sha256",
		"--repo d3vi1/nut-2-unifi-ups-gateway",
		"--bundle \"$N2U_ATTESTATION_BUNDLE\"",
		"--custom-trusted-root \"$N2U_SIGSTORE_TRUST_ROOT\"",
		"--cert-identity \"https://github.com/d3vi1/nut-2-unifi-ups-gateway/.github/workflows/release.yml@refs/heads/main\"",
		"--source-ref refs/heads/main",
		"--source-digest \"$GITHUB_SHA\"",
		"--signer-digest \"$GITHUB_SHA\"",
		"--deny-self-hosted-runners",
		"--format json > \"$verification\"",
		"jq --exit-status 'length == 1' \"$verification\" > /dev/null",
	} {
		if !strings.Contains(rootVerificationStep, want) {
			t.Errorf("Sigstore root verification is missing %q", want)
		}
	}
	if strings.Contains(image, "N2U_RELEASE_ID:") {
		t.Fatal("image job must not require private-draft access")
	}
}

func TestReleaseUsesNumericReservationAndExactAssetSet(t *testing.T) {
	release := readRepositoryFile(t, ".github", "workflows", "release.yml")
	for _, want := range []string{
		"N2U_RELEASE_ID: ${{ needs.reserve-release.outputs.release_id }}",
		"N2U_RELEASE_ASSETS: |-",
		"go run ./cmd/releaseguard verify-bound",
		"go run ./cmd/releaseguard upload-assets",
		"go run ./cmd/releaseguard publish",
		"N2U_RELEASE_POLICY_TOKEN: ${{ secrets.N2U_RELEASE_POLICY_TOKEN }}",
	} {
		if !strings.Contains(release, want) {
			t.Errorf("release workflow is missing fail-closed reservation marker %q", want)
		}
	}
	for _, forbidden := range []string{
		"gh release create",
		"gh release upload",
		"gh release edit",
		"--clobber",
		"+            --",
	} {
		if strings.Contains(release, forbidden) {
			t.Errorf("release workflow bypasses numeric reservation helper with %q", forbidden)
		}
	}
	if !strings.Contains(release, "tar --sort=name --mtime=\"@$source_date_epoch\" --owner=0 --group=0 --numeric-owner -czf \"$bundle_path\" -C \"$staging_root\" \"$bundle_name\"") {
		t.Error("release bundle is not assembled with the expected deterministic tar command")
	}
}

func isolateWorkflowJob(t *testing.T, workflow, startName, endName string) string {
	t.Helper()
	start := strings.Index(workflow, "  "+startName+":\n")
	end := strings.Index(workflow, "  "+endName+":\n")
	if start < 0 || end <= start {
		t.Fatalf("cannot isolate workflow job %s before %s", startName, endName)
	}
	return workflow[start:end]
}

func assertContainsExactly(t *testing.T, contents, needle string, want int) {
	t.Helper()
	if got := strings.Count(contents, needle); got != want {
		t.Errorf("found %d occurrences of %q; want %d", got, needle, want)
	}
}
