package releaseguard

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
)

type fakeReleaseState struct {
	id         int64
	tag        string
	target     string
	name       string
	body       string
	draft      bool
	prerelease bool
	immutable  bool
	assets     []fakeAssetState
}

type fakeAssetState struct {
	id     int64
	name   string
	data   []byte
	digest string
}

type fakeImageVersion struct {
	id     int64
	digest string
	tags   []string
}

type fakeGitHub struct {
	t *testing.T

	mu sync.Mutex

	releaseContext Context
	mainSHA        string
	mainProtected  bool
	tagExists      bool
	tagSHA         string
	tagObjectType  string

	repositoryPrivate   bool
	packageVisibility   string
	packageRepositoryID int64
	rulesetEnforcement  string
	rulesetIncludes     []string
	rules               []string
	bypassActors        []map[string]any
	immutableEnabled    bool
	actionsEnabled      bool
	shaPinning          bool
	defaultPermission   string
	canApproveReviews   bool
	comparisonStatus    string
	comparisonBase      string
	comparisonMerge     string
	imageVersions       []fakeImageVersion
	imageVersionPages   [][]fakeImageVersion

	release                *fakeReleaseState
	ambiguousTagCreation   bool
	ambiguousDraftCreation bool
	uploadCount            int
	failSecondUpload       bool
	corruptUploadDigest    bool
	leavePublishedMutable  bool
	publishMakeLatest      string
	releasePaths           []string
}

func newFakeGitHub(t *testing.T, release Context) *fakeGitHub {
	t.Helper()
	return &fakeGitHub{
		t:                   t,
		releaseContext:      release,
		mainSHA:             release.SourceSHA,
		mainProtected:       true,
		tagSHA:              release.SourceSHA,
		tagObjectType:       "commit",
		packageVisibility:   "public",
		packageRepositoryID: release.RepositoryID,
		rulesetEnforcement:  "active",
		rulesetIncludes:     []string{"refs/tags/v*"},
		rules:               []string{"update", "deletion"},
		bypassActors:        []map[string]any{},
		immutableEnabled:    true,
		actionsEnabled:      true,
		shaPinning:          true,
		defaultPermission:   "read",
		comparisonStatus:    "identical",
		comparisonBase:      release.SourceSHA,
		comparisonMerge:     release.SourceSHA,
		imageVersions: []fakeImageVersion{{
			id: 501, digest: "sha256:" + strings.Repeat("a", 64), tags: []string{release.OCITag()},
		}},
		publishMakeLatest: "unset",
	}
}

func (fake *fakeGitHub) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	releaseReadRequest := request.Method == http.MethodGet &&
		(request.URL.Path == repoPath()+"/releases" || strings.HasPrefix(request.URL.Path, repoPath()+"/releases/"))
	policyRequest := releaseReadRequest || strings.Contains(request.URL.Path, "/rulesets") || strings.Contains(request.URL.Path, "/immutable-releases") || strings.Contains(request.URL.Path, "/actions/permissions") || strings.Contains(request.URL.Path, "/branches/main")
	expectedToken := fake.releaseContext.token
	if policyRequest {
		expectedToken = fake.releaseContext.policyToken
	}
	if request.Header.Get("Authorization") != "Bearer "+expectedToken {
		fake.t.Errorf("wrong credential for %s %s", request.Method, request.URL.Path)
		writeJSON(writer, http.StatusUnauthorized, map[string]string{"message": "unauthorized"})
		return
	}
	if request.Header.Get("X-GitHub-Api-Version") != apiVersion {
		fake.t.Errorf("wrong API version for %s", request.URL.Path)
	}

	switch {
	case request.Method == http.MethodGet && request.URL.Path == repoPath():
		writeJSON(writer, http.StatusOK, map[string]any{
			"id": fake.releaseContext.RepositoryID, "full_name": RepositoryName,
			"private": fake.repositoryPrivate, "visibility": visibility(!fake.repositoryPrivate), "default_branch": "main",
			"owner": map[string]any{"id": fake.releaseContext.RepositoryOwnerID, "login": RepositoryOwner},
		})
	case request.Method == http.MethodGet && request.URL.Path == repoPath()+"/commits/main":
		writeJSON(writer, http.StatusOK, map[string]any{"sha": fake.mainSHA})
	case request.Method == http.MethodGet && request.URL.Path == repoPath()+"/branches/main":
		writeJSON(writer, http.StatusOK, map[string]any{
			"name": "main", "protected": fake.mainProtected,
			"protection_url": githubAPIOrigin + repoPath() + "/branches/main/protection",
			"commit":         map[string]any{"sha": fake.mainSHA},
		})
	case request.Method == http.MethodGet && request.URL.Path == repoPath()+"/compare/"+fake.releaseContext.SourceSHA+"...main":
		writeJSON(writer, http.StatusOK, map[string]any{
			"status":            fake.comparisonStatus,
			"base_commit":       map[string]any{"sha": fake.comparisonBase},
			"merge_base_commit": map[string]any{"sha": fake.comparisonMerge},
		})
	case request.Method == http.MethodGet && request.URL.Path == "/users/"+RepositoryOwner+"/packages/container/"+PackageName:
		writeJSON(writer, http.StatusOK, map[string]any{
			"name": PackageName, "package_type": "container", "visibility": fake.packageVisibility,
			"owner":      map[string]any{"id": fake.releaseContext.RepositoryOwnerID, "login": RepositoryOwner},
			"repository": map[string]any{"id": fake.packageRepositoryID, "full_name": RepositoryName},
		})
	case request.Method == http.MethodGet && request.URL.Path == "/users/"+RepositoryOwner+"/packages/container/"+PackageName+"/versions":
		page, err := strconv.Atoi(request.URL.Query().Get("page"))
		if err != nil || page <= 0 || request.URL.Query().Get("per_page") != "100" {
			writeJSON(writer, http.StatusBadRequest, map[string]string{"message": "bad pagination"})
			return
		}
		pageVersions := fake.imageVersions
		hasNext := false
		if fake.imageVersionPages != nil {
			if page > len(fake.imageVersionPages) {
				pageVersions = nil
			} else {
				pageVersions = fake.imageVersionPages[page-1]
				hasNext = page < len(fake.imageVersionPages)
			}
		}
		versions := make([]map[string]any, 0, len(pageVersions))
		for _, version := range pageVersions {
			versions = append(versions, map[string]any{
				"id": version.id, "name": version.digest,
				"metadata": map[string]any{"package_type": "container", "container": map[string]any{"tags": version.tags}},
			})
		}
		if hasNext {
			writer.Header().Set("Link", `<https://api.github.com/next>; rel="next"`)
		}
		writeJSON(writer, http.StatusOK, versions)
	case request.Method == http.MethodGet && request.URL.Path == repoPath()+"/rulesets":
		writeJSON(writer, http.StatusOK, []any{map[string]any{
			"id": int64(9), "name": releaseRulesetName, "target": "tag", "enforcement": fake.rulesetEnforcement,
		}})
	case request.Method == http.MethodGet && request.URL.Path == repoPath()+"/rulesets/9":
		rules := make([]map[string]string, 0, len(fake.rules))
		for _, rule := range fake.rules {
			rules = append(rules, map[string]string{"type": rule})
		}
		writeJSON(writer, http.StatusOK, map[string]any{
			"id": int64(9), "name": releaseRulesetName, "target": "tag", "source_type": "Repository",
			"source": RepositoryName, "enforcement": fake.rulesetEnforcement,
			"bypass_actors": fake.bypassActors,
			"conditions":    map[string]any{"ref_name": map[string]any{"include": fake.rulesetIncludes, "exclude": []string{}}},
			"rules":         rules,
		})
	case request.Method == http.MethodGet && request.URL.Path == repoPath()+"/immutable-releases":
		writeJSON(writer, http.StatusOK, map[string]any{"enabled": fake.immutableEnabled})
	case request.Method == http.MethodGet && request.URL.Path == repoPath()+"/actions/permissions":
		writeJSON(writer, http.StatusOK, map[string]any{"enabled": fake.actionsEnabled, "sha_pinning_required": fake.shaPinning})
	case request.Method == http.MethodGet && request.URL.Path == repoPath()+"/actions/permissions/workflow":
		writeJSON(writer, http.StatusOK, map[string]any{"default_workflow_permissions": fake.defaultPermission, "can_approve_pull_request_reviews": fake.canApproveReviews})
	case request.Method == http.MethodGet && request.URL.Path == repoPath()+"/git/ref/tags/"+fake.releaseContext.Tag:
		if !fake.tagExists {
			writeJSON(writer, http.StatusNotFound, map[string]string{"message": "not found"})
			return
		}
		writeJSON(writer, http.StatusOK, fake.refResponse())
	case request.Method == http.MethodGet && request.URL.Path == repoPath()+"/releases":
		page, err := strconv.Atoi(request.URL.Query().Get("page"))
		if err != nil || page <= 0 || request.URL.Query().Get("per_page") != "100" {
			writeJSON(writer, http.StatusBadRequest, map[string]string{"message": "bad pagination"})
			return
		}
		if fake.release == nil {
			writeJSON(writer, http.StatusOK, []any{})
			return
		}
		writeJSON(writer, http.StatusOK, []any{map[string]any{"id": fake.release.id, "tag_name": fake.release.tag}})
	case request.Method == http.MethodGet && request.URL.Path == repoPath()+"/commits/"+fake.releaseContext.Tag:
		if !fake.tagExists {
			writeJSON(writer, http.StatusNotFound, map[string]string{"message": "not found"})
			return
		}
		writeJSON(writer, http.StatusOK, map[string]any{"sha": fake.tagSHA})
	case request.Method == http.MethodPost && request.URL.Path == repoPath()+"/releases":
		fake.createRelease(writer, request)
	case request.Method == http.MethodPost && request.URL.Path == repoPath()+"/git/refs":
		fake.createTag(writer, request)
	case strings.HasPrefix(request.URL.Path, repoPath()+"/releases/"):
		fake.handleNumericRelease(writer, request)
	default:
		fake.t.Errorf("unexpected GitHub request: %s %s", request.Method, request.URL.RequestURI())
		writeJSON(writer, http.StatusNotFound, map[string]string{"message": "unexpected"})
	}
}

func (fake *fakeGitHub) createRelease(writer http.ResponseWriter, request *http.Request) {
	if !fake.tagExists {
		fake.t.Error("draft release was created before the atomic tag reservation")
		writeJSON(writer, http.StatusConflict, map[string]string{"message": "tag not reserved"})
		return
	}
	if fake.release != nil {
		writeJSON(writer, http.StatusUnprocessableEntity, map[string]string{"message": "already exists"})
		return
	}
	var input struct {
		TagName         string `json:"tag_name"`
		TargetCommitish string `json:"target_commitish"`
		Name            string `json:"name"`
		Body            string `json:"body"`
		Draft           bool   `json:"draft"`
		Prerelease      bool   `json:"prerelease"`
		MakeLatest      string `json:"make_latest"`
	}
	if err := json.NewDecoder(request.Body).Decode(&input); err != nil {
		fake.t.Errorf("decode create release: %v", err)
		writeJSON(writer, http.StatusBadRequest, map[string]string{"message": "bad request"})
		return
	}
	if input.TagName != fake.releaseContext.Tag || input.TargetCommitish != fake.releaseContext.SourceSHA || input.Name != releaseTitle(fake.releaseContext) || input.Body != reservationBody(fake.releaseContext) || !input.Draft || input.Prerelease != fake.releaseContext.Prerelease || input.MakeLatest != "false" {
		fake.t.Error("create release payload mismatch")
		writeJSON(writer, http.StatusUnprocessableEntity, map[string]string{"message": "mismatch"})
		return
	}
	fake.release = &fakeReleaseState{
		id: 42, tag: input.TagName, target: "main", name: input.Name, body: input.Body,
		draft: true, prerelease: input.Prerelease, immutable: false, assets: []fakeAssetState{},
	}
	if fake.ambiguousDraftCreation {
		writeJSON(writer, http.StatusInternalServerError, map[string]string{"message": "simulated ambiguity"})
		return
	}
	writeJSON(writer, http.StatusCreated, fake.releaseResponse())
}

func (fake *fakeGitHub) createTag(writer http.ResponseWriter, request *http.Request) {
	if fake.tagExists {
		writeJSON(writer, http.StatusUnprocessableEntity, map[string]string{"message": "already exists"})
		return
	}
	var input struct {
		Ref string `json:"ref"`
		SHA string `json:"sha"`
	}
	if err := json.NewDecoder(request.Body).Decode(&input); err != nil || input.Ref != "refs/tags/"+fake.releaseContext.Tag || input.SHA != fake.releaseContext.SourceSHA {
		fake.t.Error("create tag payload mismatch")
		writeJSON(writer, http.StatusUnprocessableEntity, map[string]string{"message": "mismatch"})
		return
	}
	fake.tagExists = true
	fake.tagSHA = input.SHA
	fake.tagObjectType = "commit"
	if fake.ambiguousTagCreation {
		writeJSON(writer, http.StatusInternalServerError, map[string]string{"message": "simulated ambiguity"})
		return
	}
	writeJSON(writer, http.StatusCreated, fake.refResponse())
}

func (fake *fakeGitHub) handleNumericRelease(writer http.ResponseWriter, request *http.Request) {
	fake.releasePaths = append(fake.releasePaths, request.URL.Path)
	if fake.release == nil || !strings.HasPrefix(request.URL.Path, releasePath(fake.release.id)) {
		writeJSON(writer, http.StatusNotFound, map[string]string{"message": "not found"})
		return
	}
	if request.Method == http.MethodPost && request.URL.Path == releasePath(fake.release.id)+"/assets" {
		fake.uploadAsset(writer, request)
		return
	}
	if request.URL.Path != releasePath(fake.release.id) {
		writeJSON(writer, http.StatusNotFound, map[string]string{"message": "not found"})
		return
	}
	switch request.Method {
	case http.MethodGet:
		writeJSON(writer, http.StatusOK, fake.releaseResponse())
	case http.MethodPatch:
		var input map[string]json.RawMessage
		if err := json.NewDecoder(request.Body).Decode(&input); err != nil {
			writeJSON(writer, http.StatusBadRequest, map[string]string{"message": "bad request"})
			return
		}
		if _, publishing := input["draft"]; !publishing {
			rawBody, exists := input["body"]
			if !exists {
				writeJSON(writer, http.StatusUnprocessableEntity, map[string]string{"message": "missing body"})
				return
			}
			if len(input) != 1 || json.Unmarshal(rawBody, &fake.release.body) != nil {
				writeJSON(writer, http.StatusUnprocessableEntity, map[string]string{"message": "invalid body"})
				return
			}
		} else {
			var tagName, target, name, body, makeLatest string
			var draft, prerelease bool
			if len(input) != 7 ||
				json.Unmarshal(input["tag_name"], &tagName) != nil ||
				json.Unmarshal(input["target_commitish"], &target) != nil ||
				json.Unmarshal(input["name"], &name) != nil ||
				json.Unmarshal(input["body"], &body) != nil ||
				json.Unmarshal(input["draft"], &draft) != nil ||
				json.Unmarshal(input["prerelease"], &prerelease) != nil ||
				json.Unmarshal(input["make_latest"], &makeLatest) != nil || draft ||
				tagName != fake.releaseContext.Tag || target != fake.releaseContext.SourceSHA ||
				name != releaseTitle(fake.releaseContext) || body != boundBody(fake.releaseContext, mustTestBinding(fake.t, fake.releaseContext)) ||
				prerelease != fake.releaseContext.Prerelease {
				writeJSON(writer, http.StatusUnprocessableEntity, map[string]string{"message": "invalid publish"})
				return
			}
			fake.release.tag = tagName
			fake.release.target = "main"
			fake.release.name = name
			fake.release.body = body
			fake.release.prerelease = prerelease
			fake.publishMakeLatest = makeLatest
			fake.release.draft = false
			fake.release.immutable = !fake.leavePublishedMutable
		}
		writeJSON(writer, http.StatusOK, fake.releaseResponse())
	default:
		writeJSON(writer, http.StatusMethodNotAllowed, map[string]string{"message": "method"})
	}
}

func (fake *fakeGitHub) uploadAsset(writer http.ResponseWriter, request *http.Request) {
	if fake.failSecondUpload && fake.uploadCount == 1 {
		writeJSON(writer, http.StatusInternalServerError, map[string]string{"message": "simulated"})
		return
	}
	name := request.URL.Query().Get("name")
	data, err := io.ReadAll(request.Body)
	if err != nil || name == "" {
		writeJSON(writer, http.StatusBadRequest, map[string]string{"message": "bad asset"})
		return
	}
	for _, existing := range fake.release.assets {
		if existing.name == name {
			writeJSON(writer, http.StatusUnprocessableEntity, map[string]string{"message": "duplicate"})
			return
		}
	}
	digestBytes := sha256.Sum256(data)
	asset := fakeAssetState{
		id: int64(100 + len(fake.release.assets)), name: name, data: data,
		digest: "sha256:" + hex.EncodeToString(digestBytes[:]),
	}
	fake.release.assets = append(fake.release.assets, asset)
	fake.uploadCount++
	response := fake.assetResponse(asset)
	if fake.corruptUploadDigest {
		response["digest"] = "sha256:" + strings.Repeat("0", 64)
	}
	writeJSON(writer, http.StatusCreated, response)
}

func (fake *fakeGitHub) refResponse() map[string]any {
	return map[string]any{
		"ref":    "refs/tags/" + fake.releaseContext.Tag,
		"object": map[string]any{"type": fake.tagObjectType, "sha": fake.tagSHA},
	}
}

func (fake *fakeGitHub) releaseResponse() map[string]any {
	assets := make([]map[string]any, 0, len(fake.release.assets))
	for _, asset := range fake.release.assets {
		assets = append(assets, fake.assetResponse(asset))
	}
	return map[string]any{
		"id": fake.release.id, "tag_name": fake.release.tag, "target_commitish": fake.release.target,
		"name": fake.release.name, "body": fake.release.body, "draft": fake.release.draft,
		"prerelease": fake.release.prerelease, "immutable": fake.release.immutable, "assets": assets,
	}
}

func (fake *fakeGitHub) assetResponse(asset fakeAssetState) map[string]any {
	return map[string]any{
		"id": asset.id, "name": asset.name, "state": "uploaded", "size": len(asset.data), "digest": asset.digest,
	}
}

func visibility(public bool) string {
	if public {
		return "public"
	}
	return "private"
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}

func startFake(t *testing.T, release Context, configure func(*fakeGitHub)) (*Guard, *fakeGitHub, func()) {
	t.Helper()
	fake := newFakeGitHub(t, release)
	if configure != nil {
		configure(fake)
	}
	server := httptest.NewServer(fake)
	github, err := newService(server.Client(), server.URL, server.URL)
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	return newGuard(github), fake, server.Close
}

func loadTestContext(t *testing.T, environment map[string]string) Context {
	t.Helper()
	release, err := LoadContext(mapLookup(environment))
	if err != nil {
		t.Fatal(err)
	}
	return release
}

func makeTestAssets(t *testing.T, environment map[string]string, release Context) []localAsset {
	t.Helper()
	binding := mustTestBinding(t, release)
	writeTestAssetPair(t, environment, release, makeTestComposeBundle(t, release, binding, nil))
	assets, err := loadReleaseAssets(release, binding, mapLookup(environment))
	if err != nil {
		t.Fatal(err)
	}
	return assets
}

func writeTestAssetPair(t *testing.T, environment map[string]string, release Context, bundle []byte) {
	t.Helper()
	directory := t.TempDir()
	bundleName := fmt.Sprintf("nut-2-unifi-ups-gateway-%s-compose.tar.gz", release.Tag)
	checksumName := fmt.Sprintf("nut-2-unifi-ups-gateway-%s-compose.SHA256SUMS", release.Tag)
	bundlePath := filepath.Join(directory, bundleName)
	checksumPath := filepath.Join(directory, checksumName)
	digest := sha256.Sum256(bundle)
	checksum := hex.EncodeToString(digest[:]) + "  " + bundleName + "\n"
	if err := os.WriteFile(bundlePath, bundle, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(checksumPath, []byte(checksum), 0o600); err != nil {
		t.Fatal(err)
	}
	environment["N2U_RELEASE_ASSETS"] = bundlePath + "\n" + checksumPath
}

type testBundleMember struct {
	mode     int64
	typeflag byte
	data     []byte
}

func mustTestBinding(t *testing.T, release Context) bindingInput {
	t.Helper()
	binding, err := loadBinding(release, mapLookup(validEnvironment()))
	if err != nil {
		t.Fatal(err)
	}
	return binding
}

func testComposeMembers(t *testing.T, release Context, binding bindingInput) map[string]testBundleMember {
	t.Helper()
	root := fmt.Sprintf("nut-2-unifi-ups-gateway-%s-compose", release.Tag)
	metadata := fmt.Sprintf("Release tag: %s\nSource commit: %s\nImage: %s@%s\nRetention anchor: %s:%s\nWorkflow run: %d (attempt %d)\n", release.Tag, release.SourceSHA, ImageName, binding.digest, ImageName, release.OCITag(), release.RunID, release.RunAttempt)
	return map[string]testBundleMember{
		root + "/": {mode: 0o755, typeflag: tar.TypeDir},
		root + "/.env": {
			mode: 0o600, typeflag: tar.TypeReg,
			data: []byte(expectedBundleEnvironment(release, binding)),
		},
		root + "/compose.yaml": {
			mode: 0o644, typeflag: tar.TypeReg,
			data: mustReadTestFile(t, "../../deploy/compose/compose.yaml"),
		},
		root + "/compose.auth.yaml": {
			mode: 0o644, typeflag: tar.TypeReg, data: mustReadTestFile(t, "../../deploy/compose/compose.auth.yaml"),
		},
		root + "/RELEASE-METADATA.txt": {
			mode: 0o644, typeflag: tar.TypeReg, data: []byte(metadata),
		},
	}
}

func mustReadTestFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func makeTestComposeBundle(t *testing.T, release Context, binding bindingInput, mutate func(map[string]testBundleMember)) []byte {
	t.Helper()
	members := testComposeMembers(t, release, binding)
	if mutate != nil {
		mutate(members)
	}
	var compressed bytes.Buffer
	gzipWriter := gzip.NewWriter(&compressed)
	tarWriter := tar.NewWriter(gzipWriter)
	root := fmt.Sprintf("nut-2-unifi-ups-gateway-%s-compose", release.Tag)
	order := []string{root + "/", root + "/.env", root + "/compose.yaml", root + "/compose.auth.yaml", root + "/RELEASE-METADATA.txt"}
	for name := range members {
		found := false
		for _, existing := range order {
			if name == existing {
				found = true
			}
		}
		if !found {
			order = append(order, name)
		}
	}
	for _, name := range order {
		member, exists := members[name]
		if !exists {
			continue
		}
		header := &tar.Header{Name: name, Mode: member.mode, Typeflag: member.typeflag, Uid: 0, Gid: 0, Size: int64(len(member.data))}
		if err := tarWriter.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if len(member.data) > 0 {
			if _, err := tarWriter.Write(member.data); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	return compressed.Bytes()
}

func reserveAndBind(t *testing.T, guard *Guard, fake *fakeGitHub, release Context, environment map[string]string) []localAsset {
	t.Helper()
	if err := guard.Reserve(context.Background(), release); err != nil {
		t.Fatal(err)
	}
	if err := guard.VerifyReserved(context.Background(), release, mapLookup(environment)); err != nil {
		t.Fatal(err)
	}
	if err := guard.Bind(context.Background(), release, mapLookup(environment)); err != nil {
		t.Fatal(err)
	}
	if err := guard.VerifyBound(context.Background(), release, mapLookup(environment)); err != nil {
		t.Fatal(err)
	}
	return makeTestAssets(t, environment, release)
}

func TestReleaseLifecycle(t *testing.T) {
	tests := []struct {
		tag        string
		makeLatest string
	}{
		{tag: "v0.9.0", makeLatest: "true"},
		{tag: "v0.9.0-rc.1", makeLatest: "false"},
	}
	for _, test := range tests {
		t.Run(test.tag, func(t *testing.T) {
			environment := validEnvironment()
			environment["N2U_RELEASE_TAG"] = test.tag
			outputPath := filepath.Join(t.TempDir(), "github-output")
			if err := os.WriteFile(outputPath, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			environment["GITHUB_OUTPUT"] = outputPath
			release := loadTestContext(t, environment)
			guard, fake, closeServer := startFake(t, release, nil)
			defer closeServer()

			assets := reserveAndBind(t, guard, fake, release, environment)
			outputs, err := os.ReadFile(outputPath)
			if err != nil {
				t.Fatal(err)
			}
			wantOutputs := "release_id=42\noci_tag=" + release.OCITag() + "\nreservation_attempt=1\n"
			if string(outputs) != wantOutputs {
				t.Fatalf("reservation outputs = %q, want %q", outputs, wantOutputs)
			}
			if !fake.tagExists || fake.release == nil || !strings.HasPrefix(fake.release.body, markerPrefix) {
				t.Fatal("reservation did not bind a tag and machine marker")
			}
			if err := guard.UploadAssets(context.Background(), release, mapLookup(environment)); err != nil {
				t.Fatal(err)
			}
			if err := guard.Publish(context.Background(), release, mapLookup(environment)); err != nil {
				t.Fatal(err)
			}
			if fake.release.draft || !fake.release.immutable || fake.publishMakeLatest != test.makeLatest || len(fake.release.assets) != len(assets) {
				t.Fatal("published release state mismatch")
			}
			for _, path := range fake.releasePaths {
				if !strings.HasPrefix(path, releasePath(42)) {
					t.Fatalf("release operation did not use numeric ID: %q", path)
				}
			}
		})
	}
}

func TestTrustPolicyFailsClosed(t *testing.T) {
	environment := validEnvironment()
	release := loadTestContext(t, environment)
	tests := []struct {
		name      string
		configure func(*fakeGitHub)
		reserved  bool
	}{
		{name: "private repository", configure: func(fake *fakeGitHub) { fake.repositoryPrivate = true }},
		{name: "moved main before reservation", configure: func(fake *fakeGitHub) { fake.mainSHA = strings.Repeat("a", 40) }},
		{name: "unprotected live main", configure: func(fake *fakeGitHub) { fake.mainProtected = false }},
		{name: "private package", configure: func(fake *fakeGitHub) { fake.packageVisibility = "private" }},
		{name: "detached package", configure: func(fake *fakeGitHub) { fake.packageRepositoryID++ }},
		{name: "inactive ruleset", configure: func(fake *fakeGitHub) { fake.rulesetEnforcement = "disabled" }},
		{name: "wide ruleset", configure: func(fake *fakeGitHub) { fake.rulesetIncludes = []string{"refs/tags/*"} }},
		{name: "missing deletion rule", configure: func(fake *fakeGitHub) { fake.rules = []string{"update"} }},
		{name: "unexpected creation restriction", configure: func(fake *fakeGitHub) { fake.rules = []string{"creation", "update", "deletion"} }},
		{name: "unexpected bypass actor", configure: func(fake *fakeGitHub) {
			fake.bypassActors = append(fake.bypassActors, map[string]any{"actor_id": int64(1), "actor_type": "RepositoryRole", "bypass_mode": "always"})
		}},
		{name: "mutable releases", configure: func(fake *fakeGitHub) { fake.immutableEnabled = false }},
		{name: "Actions disabled", configure: func(fake *fakeGitHub) { fake.actionsEnabled = false }},
		{name: "unpinned actions", configure: func(fake *fakeGitHub) { fake.shaPinning = false }},
		{name: "write default token", configure: func(fake *fakeGitHub) { fake.defaultPermission = "write" }},
		{name: "approving workflow token", configure: func(fake *fakeGitHub) { fake.canApproveReviews = true }},
		{name: "existing tag", configure: func(fake *fakeGitHub) { fake.tagExists = true }},
		{name: "existing draft release", configure: func(fake *fakeGitHub) {
			fake.release = &fakeReleaseState{id: 77, tag: fake.releaseContext.Tag}
		}},
		{name: "advanced main after reservation", reserved: true, configure: func(fake *fakeGitHub) {
			fake.tagExists = true
			fake.mainSHA = strings.Repeat("b", 40)
		}},
		{name: "moved tag", reserved: true, configure: func(fake *fakeGitHub) {
			fake.tagExists = true
			fake.tagSHA = strings.Repeat("a", 40)
		}},
		{name: "annotated tag", reserved: true, configure: func(fake *fakeGitHub) {
			fake.tagExists = true
			fake.tagObjectType = "tag"
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			guard, _, closeServer := startFake(t, release, test.configure)
			defer closeServer()
			var err error
			if test.reserved {
				err = guard.trustReserved(context.Background(), release)
			} else {
				err = guard.Trust(context.Background(), release)
			}
			if err == nil {
				t.Fatal("unsafe trust state unexpectedly succeeded")
			}
		})
	}
}

func TestReservedTrustRejectsEveryMainAdvance(t *testing.T) {
	release := loadTestContext(t, validEnvironment())
	guard, _, closeServer := startFake(t, release, func(fake *fakeGitHub) {
		fake.tagExists = true
		fake.mainSHA = strings.Repeat("b", 40)
	})
	defer closeServer()
	if err := guard.trustReserved(context.Background(), release); err == nil {
		t.Fatal("reserved release trusted after live main advanced")
	}
}

func TestTrustAllowsAnUnrelatedExistingRelease(t *testing.T) {
	release := loadTestContext(t, validEnvironment())
	guard, _, closeServer := startFake(t, release, func(fake *fakeGitHub) {
		fake.release = &fakeReleaseState{id: 77, tag: "v0.8.0"}
	})
	defer closeServer()
	if err := guard.Trust(context.Background(), release); err != nil {
		t.Fatal(err)
	}
}

func TestReleaseStateMismatchAndPartialAssetsFailClosed(t *testing.T) {
	t.Run("marker mismatch", func(t *testing.T) {
		environment, release, guard, fake, closeServer := setupReservedRelease(t)
		defer closeServer()
		fake.mu.Lock()
		fake.release.body += "tampered"
		fake.mu.Unlock()
		if err := guard.VerifyReserved(context.Background(), release, mapLookup(environment)); err == nil {
			t.Fatal("tampered marker unexpectedly succeeded")
		}
	})

	t.Run("preexisting partial asset", func(t *testing.T) {
		environment, release, guard, fake, closeServer := setupBoundRelease(t)
		defer closeServer()
		assets := makeTestAssets(t, environment, release)
		fake.mu.Lock()
		fake.release.assets = append(fake.release.assets, fakeAssetFromLocal(100, assets[0]))
		fake.mu.Unlock()
		if err := guard.UploadAssets(context.Background(), release, mapLookup(environment)); err == nil {
			t.Fatal("partial release unexpectedly resumed")
		}
		if fake.uploadCount != 0 {
			t.Fatal("partial release performed another upload")
		}
	})

	t.Run("second upload failure is terminal", func(t *testing.T) {
		environment, release, guard, fake, closeServer := setupBoundRelease(t)
		defer closeServer()
		makeTestAssets(t, environment, release)
		fake.failSecondUpload = true
		if err := guard.UploadAssets(context.Background(), release, mapLookup(environment)); err == nil {
			t.Fatal("simulated partial upload unexpectedly succeeded")
		}
		if len(fake.release.assets) != 1 {
			t.Fatalf("partial upload left %d assets, want 1", len(fake.release.assets))
		}
		if err := guard.UploadAssets(context.Background(), release, mapLookup(environment)); err == nil {
			t.Fatal("partial upload rerun unexpectedly succeeded")
		}
		if len(fake.release.assets) != 1 {
			t.Fatal("partial rerun modified the draft")
		}
	})

	t.Run("upload integrity response mismatch", func(t *testing.T) {
		environment, release, guard, fake, closeServer := setupBoundRelease(t)
		defer closeServer()
		makeTestAssets(t, environment, release)
		fake.corruptUploadDigest = true
		if err := guard.UploadAssets(context.Background(), release, mapLookup(environment)); err == nil {
			t.Fatal("corrupt upload integrity response unexpectedly succeeded")
		}
		if len(fake.release.assets) != 1 {
			t.Fatal("integrity mismatch did not stop after the first mutation")
		}
	})

	t.Run("mutable publish readback", func(t *testing.T) {
		environment, release, guard, fake, closeServer := setupBoundRelease(t)
		defer closeServer()
		makeTestAssets(t, environment, release)
		if err := guard.UploadAssets(context.Background(), release, mapLookup(environment)); err != nil {
			t.Fatal(err)
		}
		fake.leavePublishedMutable = true
		if err := guard.Publish(context.Background(), release, mapLookup(environment)); err == nil {
			t.Fatal("mutable published release unexpectedly succeeded")
		}
	})
}

func TestReservationConflictsAndAmbiguityNeverProduceOutputs(t *testing.T) {
	tests := []struct {
		name      string
		configure func(*fakeGitHub)
		wantTag   bool
	}{
		{name: "existing draft conflict", configure: func(fake *fakeGitHub) {
			fake.release = &fakeReleaseState{id: 77, tag: fake.releaseContext.Tag}
		}},
		{name: "ambiguous tag creation", configure: func(fake *fakeGitHub) {
			fake.ambiguousTagCreation = true
		}, wantTag: true},
		{name: "ambiguous draft creation", configure: func(fake *fakeGitHub) {
			fake.ambiguousDraftCreation = true
		}, wantTag: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			environment := validEnvironment()
			outputPath := filepath.Join(t.TempDir(), "github-output")
			if err := os.WriteFile(outputPath, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			environment["GITHUB_OUTPUT"] = outputPath
			release := loadTestContext(t, environment)
			guard, fake, closeServer := startFake(t, release, test.configure)
			defer closeServer()
			if err := guard.Reserve(context.Background(), release); err == nil {
				t.Fatal("unsafe reservation state unexpectedly succeeded")
			}
			output, err := os.ReadFile(outputPath)
			if err != nil {
				t.Fatal(err)
			}
			if len(output) != 0 {
				t.Fatal("failed reservation emitted downstream outputs")
			}
			if fake.tagExists != test.wantTag {
				t.Fatalf("tag existence = %v, want %v", fake.tagExists, test.wantTag)
			}
			if fake.uploadCount != 0 {
				t.Fatal("failed reservation reached registry publication")
			}
		})
	}
}

func TestReservationRejectsNonemptyOutputFileBeforeNetworkMutation(t *testing.T) {
	environment := validEnvironment()
	outputPath := filepath.Join(t.TempDir(), "github-output")
	if err := os.WriteFile(outputPath, []byte("preexisting=value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	environment["GITHUB_OUTPUT"] = outputPath
	release := loadTestContext(t, environment)
	guard, fake, closeServer := startFake(t, release, nil)
	defer closeServer()
	if err := guard.Reserve(context.Background(), release); err == nil {
		t.Fatal("nonempty GITHUB_OUTPUT unexpectedly succeeded")
	}
	if fake.tagExists || fake.release != nil {
		t.Fatal("invalid output path reached a remote mutation")
	}
}

func TestChecksumAssetMustBindBundle(t *testing.T) {
	environment := validEnvironment()
	release := loadTestContext(t, environment)
	makeTestAssets(t, environment, release)
	paths := strings.Split(environment["N2U_RELEASE_ASSETS"], "\n")
	if err := os.WriteFile(paths[1], []byte(strings.Repeat("0", 64)+"  "+filepath.Base(paths[0])+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadReleaseAssets(release, mustTestBinding(t, release), mapLookup(environment)); err == nil {
		t.Fatal("unbound SHA256SUMS unexpectedly succeeded")
	}
}

func TestComposeBundleMustBindImageAndExactTopology(t *testing.T) {
	release := loadTestContext(t, validEnvironment())
	binding := mustTestBinding(t, release)
	root := fmt.Sprintf("nut-2-unifi-ups-gateway-%s-compose", release.Tag)
	tests := []struct {
		name   string
		mutate func(map[string]testBundleMember)
	}{
		{
			name: "floating image",
			mutate: func(members map[string]testBundleMember) {
				member := members[root+"/.env"]
				member.data = []byte("N2U_IMAGE=" + ImageName + ":latest\n")
				members[root+"/.env"] = member
			},
		},
		{
			name: "duplicate image assignment",
			mutate: func(members map[string]testBundleMember) {
				member := members[root+"/.env"]
				member.data = append(member.data, []byte("export N2U_IMAGE="+ImageName+"@"+binding.digest+"\n")...)
				members[root+"/.env"] = member
			},
		},
		{
			name: "compose override variable",
			mutate: func(members map[string]testBundleMember) {
				member := members[root+"/.env"]
				member.data = append(member.data, []byte("COMPOSE_FILE=attacker.yaml\n")...)
				members[root+"/.env"] = member
			},
		},
		{
			name: "floating compose image with pinned comment",
			mutate: func(members map[string]testBundleMember) {
				member := members[root+"/compose.yaml"]
				member.data = []byte("# image: \"${N2U_IMAGE:?N2U_IMAGE must be set to a verified OCI digest}\"\nservices:\n  gateway:\n    image: " + ImageName + ":latest\n")
				members[root+"/compose.yaml"] = member
			},
		},
		{
			name: "wrong metadata",
			mutate: func(members map[string]testBundleMember) {
				member := members[root+"/RELEASE-METADATA.txt"]
				member.data = []byte("wrong\n")
				members[root+"/RELEASE-METADATA.txt"] = member
			},
		},
		{
			name: "missing compose",
			mutate: func(members map[string]testBundleMember) {
				delete(members, root+"/compose.yaml")
			},
		},
		{
			name: "extra member",
			mutate: func(members map[string]testBundleMember) {
				members[root+"/unexpected"] = testBundleMember{mode: 0o644, typeflag: tar.TypeReg, data: []byte("unexpected")}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			environment := validEnvironment()
			bundle := makeTestComposeBundle(t, release, binding, test.mutate)
			writeTestAssetPair(t, environment, release, bundle)
			if _, err := loadReleaseAssets(release, binding, mapLookup(environment)); err == nil {
				t.Fatal("invalid Compose bundle unexpectedly succeeded")
			}
		})
	}
	t.Run("concatenated gzip stream", func(t *testing.T) {
		environment := validEnvironment()
		bundle := makeTestComposeBundle(t, release, binding, nil)
		bundle = append(bundle, makeTestComposeBundle(t, release, binding, nil)...)
		writeTestAssetPair(t, environment, release, bundle)
		if _, err := loadReleaseAssets(release, binding, mapLookup(environment)); err == nil {
			t.Fatal("concatenated gzip bundle unexpectedly succeeded")
		}
	})
}

func TestReleaseAssetSymlinkIsRejected(t *testing.T) {
	environment := validEnvironment()
	release := loadTestContext(t, environment)
	binding := mustTestBinding(t, release)
	writeTestAssetPair(t, environment, release, makeTestComposeBundle(t, release, binding, nil))
	paths := strings.Split(environment["N2U_RELEASE_ASSETS"], "\n")
	link := filepath.Join(t.TempDir(), filepath.Base(paths[0]))
	if err := os.Symlink(paths[0], link); err != nil {
		t.Fatal(err)
	}
	environment["N2U_RELEASE_ASSETS"] = link + "\n" + paths[1]
	if _, err := loadReleaseAssets(release, binding, mapLookup(environment)); err == nil {
		t.Fatal("symlinked release asset unexpectedly succeeded")
	}
}

func TestReviewedComposeTemplatesRemainAligned(t *testing.T) {
	release := loadTestContext(t, validEnvironment())
	binding := mustTestBinding(t, release)
	compose := mustReadTestFile(t, "../../deploy/compose/compose.yaml")
	composeAuth := mustReadTestFile(t, "../../deploy/compose/compose.auth.yaml")
	composeDigest := sha256.Sum256(compose)
	composeAuthDigest := sha256.Sum256(composeAuth)
	if hex.EncodeToString(composeDigest[:]) != composeSHA256 || hex.EncodeToString(composeAuthDigest[:]) != composeAuthSHA256 {
		t.Fatal("reviewed compose digest constants are stale")
	}
	sourceEnvironment := string(mustReadTestFile(t, "../../deploy/compose/.env.example"))
	generated := fmt.Sprintf("# Generated for %s; keep the OCI manifest digest pinned.\n", release.Tag) + strings.Replace(sourceEnvironment, "N2U_IMAGE="+ImageName+":edge", "N2U_IMAGE="+ImageName+"@"+binding.digest, 1)
	if generated != expectedBundleEnvironment(release, binding) {
		t.Fatal("reviewed environment template is stale")
	}
}

func setupReservedRelease(t *testing.T) (map[string]string, Context, *Guard, *fakeGitHub, func()) {
	t.Helper()
	environment := validEnvironment()
	outputPath := filepath.Join(t.TempDir(), "github-output")
	if err := os.WriteFile(outputPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	environment["GITHUB_OUTPUT"] = outputPath
	release := loadTestContext(t, environment)
	guard, fake, closeServer := startFake(t, release, nil)
	if err := guard.Reserve(context.Background(), release); err != nil {
		closeServer()
		t.Fatal(err)
	}
	return environment, release, guard, fake, closeServer
}

func setupBoundRelease(t *testing.T) (map[string]string, Context, *Guard, *fakeGitHub, func()) {
	t.Helper()
	environment, release, guard, fake, closeServer := setupReservedRelease(t)
	if err := guard.Bind(context.Background(), release, mapLookup(environment)); err != nil {
		closeServer()
		t.Fatal(err)
	}
	return environment, release, guard, fake, closeServer
}

func fakeAssetFromLocal(id int64, local localAsset) fakeAssetState {
	return fakeAssetState{id: id, name: local.name, data: append([]byte(nil), local.data...), digest: local.digest}
}

func TestReservationMarkerIsMachineParseableAndExact(t *testing.T) {
	release := loadTestContext(t, validEnvironment())
	line := strings.SplitN(reservationBody(release), "\n", 2)[0]
	encoded := strings.TrimSuffix(strings.TrimPrefix(line, markerPrefix), " -->")
	var parsed releaseMarker
	if err := decodeJSON([]byte(encoded), &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.RepositoryID != release.RepositoryID || parsed.Repository != RepositoryName || parsed.Tag != release.Tag || parsed.SourceSHA != release.SourceSHA || parsed.RunID != release.RunID || parsed.RunAttempt != 1 || parsed.OCITag != release.OCITag() || parsed.Image != nil || parsed.PublicationAttempt != nil {
		t.Fatal("reservation marker fields mismatch")
	}
}

func TestLoadBindingRejectsRerunAndMismatchedAttestation(t *testing.T) {
	release := loadTestContext(t, validEnvironment())
	tests := []struct {
		key   string
		value string
	}{
		{key: "N2U_PUBLICATION_ATTEMPT", value: "2"},
		{key: "N2U_ATTESTATION_URL", value: "https://github.com/attacker/repository/attestations/7654"},
		{key: "N2U_ATTESTATION_ID", value: "07654"},
		{key: "N2U_IMAGE_DIGEST", value: "sha256:" + strings.Repeat("A", 64)},
	}
	for index, test := range tests {
		t.Run(strconv.Itoa(index), func(t *testing.T) {
			environment := cloneEnvironment(validEnvironment())
			environment[test.key] = test.value
			if _, err := loadBinding(release, mapLookup(environment)); err == nil {
				t.Fatal("invalid binding unexpectedly succeeded")
			}
		})
	}
}

func TestOCIImageBindingFailsClosed(t *testing.T) {
	release := loadTestContext(t, validEnvironment())
	binding, err := loadBinding(release, mapLookup(validEnvironment()))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name      string
		configure func(*fakeGitHub)
	}{
		{name: "missing tag", configure: func(fake *fakeGitHub) {
			fake.imageVersions[0].tags = []string{"other"}
		}},
		{name: "wrong digest", configure: func(fake *fakeGitHub) {
			fake.imageVersions[0].digest = "sha256:" + strings.Repeat("b", 64)
		}},
		{name: "duplicate tag on version", configure: func(fake *fakeGitHub) {
			fake.imageVersions[0].tags = []string{release.OCITag(), release.OCITag()}
		}},
		{name: "floating alias on release version", configure: func(fake *fakeGitHub) {
			fake.imageVersions[0].tags = []string{release.OCITag(), "latest"}
		}},
		{name: "release alias on another version", configure: func(fake *fakeGitHub) {
			fake.imageVersions = append(fake.imageVersions, fakeImageVersion{id: 502, digest: "sha256:" + strings.Repeat("b", 64), tags: []string{release.Tag}})
		}},
		{name: "duplicate tagged versions", configure: func(fake *fakeGitHub) {
			fake.imageVersions = append(fake.imageVersions, fakeImageVersion{id: 502, digest: binding.digest, tags: []string{release.OCITag()}})
		}},
		{name: "duplicate version id on next page", configure: func(fake *fakeGitHub) {
			fake.imageVersionPages = [][]fakeImageVersion{fake.imageVersions, fake.imageVersions}
		}},
		{name: "invalid digest schema", configure: func(fake *fakeGitHub) {
			fake.imageVersions[0].digest = "latest"
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			guard, _, closeServer := startFake(t, release, test.configure)
			defer closeServer()
			if err := guard.requireImageBinding(context.Background(), release, binding); err == nil {
				t.Fatal("invalid OCI binding unexpectedly succeeded")
			}
		})
	}
}

func TestOCIImageBindingFollowsBoundedPagination(t *testing.T) {
	release := loadTestContext(t, validEnvironment())
	binding, err := loadBinding(release, mapLookup(validEnvironment()))
	if err != nil {
		t.Fatal(err)
	}
	guard, _, closeServer := startFake(t, release, func(fake *fakeGitHub) {
		fake.imageVersionPages = [][]fakeImageVersion{
			{{id: 500, digest: "sha256:" + strings.Repeat("b", 64), tags: []string{"unrelated"}}},
			{{id: 501, digest: binding.digest, tags: []string{release.OCITag()}}},
		}
	})
	defer closeServer()
	if err := guard.requireImageBinding(context.Background(), release, binding); err != nil {
		t.Fatal(err)
	}
}
