package releaseguard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const markerPrefix = "<!-- n2u-release-reservation:v1 "

type releaseMarker struct {
	RepositoryID       int64         `json:"repository_id"`
	Repository         string        `json:"repository"`
	Tag                string        `json:"tag"`
	SourceSHA          string        `json:"source_sha"`
	RunID              int64         `json:"run_id"`
	RunAttempt         int64         `json:"run_attempt"`
	OCITag             string        `json:"oci_tag"`
	Image              *imageBinding `json:"image,omitempty"`
	PublicationAttempt *int64        `json:"publication_attempt,omitempty"`
}

type imageBinding struct {
	Name           string `json:"name"`
	Digest         string `json:"digest"`
	AttestationID  int64  `json:"attestation_id"`
	AttestationURL string `json:"attestation_url"`
}

type bindingInput struct {
	digest             string
	attestationID      int64
	attestationURL     string
	publicationAttempt int64
}

type releaseWire struct {
	ID              *int64          `json:"id"`
	TagName         *string         `json:"tag_name"`
	TargetCommitish *string         `json:"target_commitish"`
	Name            *string         `json:"name"`
	Body            *string         `json:"body"`
	Draft           *bool           `json:"draft"`
	Prerelease      *bool           `json:"prerelease"`
	Immutable       *bool           `json:"immutable"`
	Assets          *[]releaseAsset `json:"assets"`
}

type releaseAsset struct {
	ID     *int64  `json:"id"`
	Name   *string `json:"name"`
	State  *string `json:"state"`
	Size   *int64  `json:"size"`
	Digest *string `json:"digest"`
}

// Reserve atomically reserves the version with a lightweight tag, then creates
// its numeric draft release. Any ambiguous or partial result is terminal and
// is never reconciled.
func (g *Guard) Reserve(ctx context.Context, release Context) error {
	if err := validateOutputPath(release.OutputPath); err != nil {
		return err
	}
	if err := g.Trust(ctx, release); err != nil {
		return err
	}
	// Repeat both checks immediately before the atomic create-ref boundary.
	if err := g.requireMainTip(ctx, release); err != nil {
		return err
	}
	if err := g.requireTagAbsent(ctx, release); err != nil {
		return err
	}
	if err := g.requireReleaseTagAbsent(ctx, release); err != nil {
		return err
	}
	refRequest := struct {
		Ref string `json:"ref"`
		SHA string `json:"sha"`
	}{Ref: "refs/tags/" + release.Tag, SHA: release.SourceSHA}
	refResponse, err := g.github.apiJSON(ctx, release.token, http.MethodPost, repoPath()+"/git/refs", nil, refRequest, http.StatusCreated)
	if err != nil {
		return errors.New("release tag reservation failed; inspect the remote state before retrying")
	}
	if err := validateCreatedRef(refResponse.body, release); err != nil {
		return errors.New("release tag creation returned invalid metadata; inspect the remote state")
	}
	if err := g.trustReserved(ctx, release); err != nil {
		return errors.New("release trust root changed after tag creation; inspect the remote state")
	}

	body := reservationBody(release)
	request := struct {
		TagName         string `json:"tag_name"`
		TargetCommitish string `json:"target_commitish"`
		Name            string `json:"name"`
		Body            string `json:"body"`
		Draft           bool   `json:"draft"`
		Prerelease      bool   `json:"prerelease"`
		MakeLatest      string `json:"make_latest"`
	}{
		TagName:         release.Tag,
		TargetCommitish: release.SourceSHA,
		Name:            releaseTitle(release),
		Body:            body,
		Draft:           true,
		Prerelease:      release.Prerelease,
		MakeLatest:      "false",
	}
	apiResponse, err := g.github.apiJSON(ctx, release.token, http.MethodPost, repoPath()+"/releases", nil, request, http.StatusCreated)
	if err != nil {
		return errors.New("draft release creation failed; inspect the reserved tag before retrying")
	}
	reserved, err := decodeRelease(apiResponse.body)
	if err != nil || reserved.ID == nil || *reserved.ID <= 0 {
		return errors.New("draft release creation returned invalid metadata; inspect the remote state")
	}
	releaseID := *reserved.ID
	if err := validateRelease(reserved, releaseID, release, body, true, false, nil); err != nil {
		return errors.New("draft release did not match the reservation; inspect the remote state")
	}
	if err := g.trustReserved(ctx, release); err != nil {
		return errors.New("release trust root changed after draft creation; inspect the remote state")
	}
	remote, err := g.getRelease(ctx, release, releaseID)
	if err != nil || validateRelease(remote, releaseID, release, body, true, false, nil) != nil {
		return errors.New("reserved release changed before output binding; inspect the remote state")
	}
	return writeReservationOutputs(release.OutputPath, releaseID, release)
}

// VerifyReserved verifies that the numeric release ID still names the exact,
// untouched draft reserved by this workflow invocation.
func (g *Guard) VerifyReserved(ctx context.Context, release Context, getenv func(string) string) error {
	releaseID, err := loadReleaseID(getenv)
	if err != nil {
		return err
	}
	if err := g.trustReserved(ctx, release); err != nil {
		return err
	}
	remote, err := g.getRelease(ctx, release, releaseID)
	if err != nil {
		return err
	}
	if err := validateRelease(remote, releaseID, release, reservationBody(release), true, false, nil); err != nil {
		return errors.New("reserved release state does not match this workflow")
	}
	return nil
}

// Bind records the immutable image digest and GitHub attestation identity in
// the draft marker before any release asset may be uploaded.
func (g *Guard) Bind(ctx context.Context, release Context, getenv func(string) string) error {
	releaseID, err := loadReleaseID(getenv)
	if err != nil {
		return err
	}
	binding, err := loadBinding(release, getenv)
	if err != nil {
		return err
	}
	if err := g.trustReserved(ctx, release); err != nil {
		return err
	}
	if err := g.requireImageBinding(ctx, release, binding); err != nil {
		return err
	}
	remote, err := g.getRelease(ctx, release, releaseID)
	if err != nil {
		return err
	}
	if err := validateRelease(remote, releaseID, release, reservationBody(release), true, false, nil); err != nil {
		return errors.New("only the untouched reserved draft can be bound")
	}
	body := boundBody(release, binding)
	patchResponse, err := g.github.apiJSON(ctx, release.token, http.MethodPatch, releasePath(releaseID), nil, struct {
		Body string `json:"body"`
	}{Body: body}, http.StatusOK)
	if err != nil {
		return errors.New("image binding failed; inspect the remote draft before retrying")
	}
	updated, err := decodeRelease(patchResponse.body)
	if err != nil || validateRelease(updated, releaseID, release, body, true, false, nil) != nil {
		return errors.New("image binding returned an unexpected draft state")
	}
	readback, err := g.getRelease(ctx, release, releaseID)
	if err != nil || validateRelease(readback, releaseID, release, body, true, false, nil) != nil {
		return errors.New("image binding did not read back as the exact bound draft")
	}
	return nil
}

// VerifyBound checks the exact digest-and-attestation binding without
// modifying the draft. It is intended for the boundary between jobs.
func (g *Guard) VerifyBound(ctx context.Context, release Context, getenv func(string) string) error {
	releaseID, err := loadReleaseID(getenv)
	if err != nil {
		return err
	}
	binding, err := loadBinding(release, getenv)
	if err != nil {
		return err
	}
	if err := g.trustReserved(ctx, release); err != nil {
		return err
	}
	if err := g.requireImageBinding(ctx, release, binding); err != nil {
		return err
	}
	remote, err := g.getRelease(ctx, release, releaseID)
	if err != nil {
		return err
	}
	if err := validateRelease(remote, releaseID, release, boundBody(release, binding), true, false, nil); err != nil {
		return errors.New("bound release state does not match this workflow")
	}
	return nil
}

// UploadAssets uploads exactly the two release-specific assets without a
// clobber path and verifies GitHub's name, size, and SHA-256 after each upload.
func (g *Guard) UploadAssets(ctx context.Context, release Context, getenv func(string) string) error {
	releaseID, err := loadReleaseID(getenv)
	if err != nil {
		return err
	}
	binding, err := loadBinding(release, getenv)
	if err != nil {
		return err
	}
	assets, err := loadReleaseAssets(release, binding, getenv)
	if err != nil {
		return err
	}
	if err := g.trustReserved(ctx, release); err != nil {
		return err
	}
	if err := g.requireImageBinding(ctx, release, binding); err != nil {
		return err
	}
	body := boundBody(release, binding)
	remote, err := g.getRelease(ctx, release, releaseID)
	if err != nil || validateRelease(remote, releaseID, release, body, true, false, nil) != nil {
		return errors.New("asset upload requires a bound draft with zero assets")
	}
	uploaded := make([]localAsset, 0, len(assets))
	for _, asset := range assets {
		query := url.Values{"name": {asset.name}}
		apiResponse, err := g.github.upload(ctx, release.token, releasePath(releaseID)+"/assets", query, asset.data)
		if err != nil {
			return fmt.Errorf("upload release asset %q failed; inspect the partial draft", asset.name)
		}
		var result releaseAsset
		if err := decodeJSON(apiResponse.body, &result); err != nil || validateAsset(result, asset) != nil {
			return fmt.Errorf("upload release asset %q returned invalid integrity metadata", asset.name)
		}
		uploaded = append(uploaded, asset)
		current, err := g.getRelease(ctx, release, releaseID)
		if err != nil || validateRelease(current, releaseID, release, body, true, false, uploaded) != nil {
			return fmt.Errorf("release state changed after uploading asset %q", asset.name)
		}
	}
	return nil
}

// Publish transitions the fully-bound draft to published and verifies that the
// resulting release was made immutable by GitHub.
func (g *Guard) Publish(ctx context.Context, release Context, getenv func(string) string) error {
	releaseID, err := loadReleaseID(getenv)
	if err != nil {
		return err
	}
	binding, err := loadBinding(release, getenv)
	if err != nil {
		return err
	}
	assets, err := loadReleaseAssets(release, binding, getenv)
	if err != nil {
		return err
	}
	if err := g.trustReserved(ctx, release); err != nil {
		return err
	}
	if err := g.requireImageBinding(ctx, release, binding); err != nil {
		return err
	}
	body := boundBody(release, binding)
	remote, err := g.getRelease(ctx, release, releaseID)
	if err != nil || validateRelease(remote, releaseID, release, body, true, false, assets) != nil {
		return errors.New("publish requires the exact complete bound draft")
	}
	makeLatest := "true"
	if release.Prerelease {
		makeLatest = "false"
	}
	patchResponse, err := g.github.apiJSON(ctx, release.token, http.MethodPatch, releasePath(releaseID), nil, struct {
		TagName         string `json:"tag_name"`
		TargetCommitish string `json:"target_commitish"`
		Name            string `json:"name"`
		Body            string `json:"body"`
		Draft           bool   `json:"draft"`
		Prerelease      bool   `json:"prerelease"`
		MakeLatest      string `json:"make_latest"`
	}{
		TagName:         release.Tag,
		TargetCommitish: release.SourceSHA,
		Name:            releaseTitle(release),
		Body:            body,
		Draft:           false,
		Prerelease:      release.Prerelease,
		MakeLatest:      makeLatest,
	}, http.StatusOK)
	if err != nil {
		return errors.New("release publication failed; inspect the remote state before retrying")
	}
	published, err := decodeRelease(patchResponse.body)
	if err != nil || validateRelease(published, releaseID, release, body, false, true, assets) != nil {
		return errors.New("release publication returned an unexpected state")
	}
	readback, err := g.getRelease(ctx, release, releaseID)
	if err != nil || validateRelease(readback, releaseID, release, body, false, true, assets) != nil {
		return errors.New("published release did not read back as immutable")
	}
	if err := g.trustReserved(ctx, release); err != nil {
		return errors.New("final immutable release trust check failed")
	}
	if err := g.requireImageBinding(ctx, release, binding); err != nil {
		return errors.New("final immutable release OCI binding check failed")
	}
	return nil
}

func marker(release Context, binding *bindingInput) releaseMarker {
	result := releaseMarker{
		RepositoryID: release.RepositoryID,
		Repository:   release.Repository,
		Tag:          release.Tag,
		SourceSHA:    release.SourceSHA,
		RunID:        release.RunID,
		RunAttempt:   release.RunAttempt,
		OCITag:       release.OCITag(),
	}
	if binding != nil {
		result.Image = &imageBinding{
			Name:           ImageName,
			Digest:         binding.digest,
			AttestationID:  binding.attestationID,
			AttestationURL: binding.attestationURL,
		}
		attempt := binding.publicationAttempt
		result.PublicationAttempt = &attempt
	}
	return result
}

func markerLine(release Context, binding *bindingInput) string {
	encoded, err := json.Marshal(marker(release, binding))
	if err != nil {
		panic(err)
	}
	return markerPrefix + string(encoded) + " -->"
}

func reservationBody(release Context) string {
	return markerLine(release, nil) + "\n\nRelease publication is in progress. This draft is reserved to one non-rerunnable workflow invocation."
}

func boundBody(release Context, binding bindingInput) string {
	return fmt.Sprintf("%s\n\n# NUT 2 UniFi UPS Gateway %s\n\n- Source tag: `%s`\n- Source commit: `%s`\n- Multi-platform image: `%s@%s`\n- GitHub attestation: %s\n\nThe attached Compose bundle is pinned to the OCI manifest digest above. Verify its attached SHA256SUMS before extraction.", markerLine(release, &binding), release.Version, release.Tag, release.SourceSHA, ImageName, binding.digest, binding.attestationURL)
}

func releaseTitle(release Context) string {
	return "NUT 2 UniFi UPS Gateway " + release.Version
}

func releasePath(releaseID int64) string {
	return repoPath() + "/releases/" + strconv.FormatInt(releaseID, 10)
}

func (g *Guard) getRelease(ctx context.Context, release Context, releaseID int64) (releaseWire, error) {
	// Draft Releases are visible only to repository writers. Use the separate
	// owner-bound, read-only policy credential for every lookup so the image job
	// never needs contents:write merely to inspect the reservation.
	apiResponse, err := g.github.apiJSON(ctx, release.policyToken, http.MethodGet, releasePath(releaseID), nil, nil, http.StatusOK)
	if err != nil {
		return releaseWire{}, errors.New("numeric release lookup failed")
	}
	result, err := decodeRelease(apiResponse.body)
	if err != nil {
		return releaseWire{}, errors.New("numeric release lookup returned invalid metadata")
	}
	return result, nil
}

func decodeRelease(payload []byte) (releaseWire, error) {
	var release releaseWire
	if err := decodeJSON(payload, &release); err != nil {
		return releaseWire{}, err
	}
	return release, nil
}

func validateRelease(remote releaseWire, releaseID int64, release Context, body string, draft, immutable bool, assets []localAsset) error {
	// GitHub documents target_commitish as unused when tag_name already exists
	// and may normalize it to the default branch. The separately verified
	// lightweight tag and exact marker bind the release to SourceSHA.
	if remote.ID == nil || *remote.ID != releaseID || remote.TagName == nil || *remote.TagName != release.Tag || remote.TargetCommitish == nil || (*remote.TargetCommitish != release.SourceSHA && *remote.TargetCommitish != "main") || remote.Name == nil || *remote.Name != releaseTitle(release) || remote.Body == nil || *remote.Body != body || remote.Draft == nil || *remote.Draft != draft || remote.Prerelease == nil || *remote.Prerelease != release.Prerelease || remote.Immutable == nil || *remote.Immutable != immutable || remote.Assets == nil {
		return errors.New("release identity or state mismatch")
	}
	if len(*remote.Assets) != len(assets) {
		return errors.New("release asset count mismatch")
	}
	expected := make(map[string]localAsset, len(assets))
	for _, asset := range assets {
		expected[asset.name] = asset
	}
	seen := make(map[string]struct{}, len(assets))
	seenIDs := make(map[int64]struct{}, len(assets))
	for _, remoteAsset := range *remote.Assets {
		if remoteAsset.Name == nil || remoteAsset.ID == nil || *remoteAsset.ID <= 0 {
			return errors.New("release asset has an invalid identity")
		}
		asset, exists := expected[*remoteAsset.Name]
		if !exists {
			return errors.New("unexpected release asset")
		}
		if _, duplicate := seen[*remoteAsset.Name]; duplicate {
			return errors.New("duplicate release asset")
		}
		seen[*remoteAsset.Name] = struct{}{}
		if _, duplicate := seenIDs[*remoteAsset.ID]; duplicate {
			return errors.New("duplicate release asset ID")
		}
		seenIDs[*remoteAsset.ID] = struct{}{}
		if err := validateAsset(remoteAsset, asset); err != nil {
			return err
		}
	}
	return nil
}

func validateAsset(remote releaseAsset, local localAsset) error {
	if remote.ID == nil || *remote.ID <= 0 || remote.Name == nil || *remote.Name != local.name || remote.State == nil || *remote.State != "uploaded" || remote.Size == nil || *remote.Size != local.size || remote.Digest == nil || *remote.Digest != local.digest {
		return errors.New("release asset integrity mismatch")
	}
	return nil
}

func validateCreatedRef(payload []byte, release Context) error {
	var reference struct {
		Ref    *string `json:"ref"`
		Object *struct {
			Type *string `json:"type"`
			SHA  *string `json:"sha"`
		} `json:"object"`
	}
	if err := decodeJSON(payload, &reference); err != nil || reference.Ref == nil || reference.Object == nil || reference.Object.Type == nil || reference.Object.SHA == nil {
		return errors.New("invalid git ref response")
	}
	if *reference.Ref != "refs/tags/"+release.Tag || *reference.Object.Type != "commit" || *reference.Object.SHA != release.SourceSHA {
		return errors.New("created git ref mismatch")
	}
	return nil
}

func loadReleaseID(getenv func(string) string) (int64, error) {
	if getenv == nil {
		return 0, errors.New("release environment is unavailable")
	}
	return parsePositiveInt64(getenv("N2U_RELEASE_ID"), "N2U_RELEASE_ID")
}

func loadBinding(release Context, getenv func(string) string) (bindingInput, error) {
	if getenv == nil {
		return bindingInput{}, errors.New("release environment is unavailable")
	}
	digest := getenv("N2U_IMAGE_DIGEST")
	if !validDigest(digest) {
		return bindingInput{}, errors.New("N2U_IMAGE_DIGEST must be a lowercase sha256 digest")
	}
	attestationID, err := parsePositiveInt64(getenv("N2U_ATTESTATION_ID"), "N2U_ATTESTATION_ID")
	if err != nil {
		return bindingInput{}, err
	}
	attestationURL := getenv("N2U_ATTESTATION_URL")
	expectedURL := fmt.Sprintf("https://github.com/%s/attestations/%d", RepositoryName, attestationID)
	if attestationURL != expectedURL {
		return bindingInput{}, errors.New("N2U_ATTESTATION_URL does not match the release repository and attestation ID")
	}
	publicationAttempt, err := parsePositiveInt64(getenv("N2U_PUBLICATION_ATTEMPT"), "N2U_PUBLICATION_ATTEMPT")
	if err != nil {
		return bindingInput{}, err
	}
	if publicationAttempt != release.RunAttempt || publicationAttempt != 1 {
		return bindingInput{}, errors.New("publication attempt does not match the non-rerunnable reservation")
	}
	return bindingInput{digest: digest, attestationID: attestationID, attestationURL: attestationURL, publicationAttempt: publicationAttempt}, nil
}

func validDigest(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, character := range value[len("sha256:"):] {
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
			return false
		}
	}
	return true
}

func validateOutputPath(path string) error {
	if path == "" {
		return errors.New("GITHUB_OUTPUT is required for reserve")
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("GITHUB_OUTPUT must be an absolute canonical path")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return errors.New("GITHUB_OUTPUT is unavailable")
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() != 0 {
		return errors.New("GITHUB_OUTPUT must be an empty regular file")
	}
	return nil
}

func writeReservationOutputs(path string, releaseID int64, release Context) error {
	if err := validateOutputPath(path); err != nil {
		return err
	}
	before, err := os.Lstat(path)
	if err != nil {
		return errors.New("inspect GITHUB_OUTPUT")
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		return errors.New("open GITHUB_OUTPUT")
	}
	after, statErr := file.Stat()
	if statErr != nil || !os.SameFile(before, after) || after.Size() != 0 {
		file.Close()
		return errors.New("GITHUB_OUTPUT changed while opening")
	}
	content := fmt.Sprintf("release_id=%d\noci_tag=%s\nreservation_attempt=%d\n", releaseID, release.OCITag(), release.RunAttempt)
	_, writeErr := file.WriteString(content)
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		return errors.New("write GITHUB_OUTPUT")
	}
	return nil
}
