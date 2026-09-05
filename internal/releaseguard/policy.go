package releaseguard

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
)

const releaseRulesetName = "N2U release tags"

// Guard applies the fail-closed release state machine.
type Guard struct {
	github *service
}

// New returns a guard fixed to GitHub's public API and upload origins.
func New() *Guard {
	return &Guard{github: newGitHubService()}
}

func newGuard(github *service) *Guard {
	return &Guard{github: github}
}

// Trust validates the read-only preflight and requires the tag to be absent.
// It cannot establish private-draft absence: Reserve must repeat that check
// with its ephemeral contents-write token before creating the tag.
func (g *Guard) Trust(ctx context.Context, release Context) error {
	if err := g.verifyPolicy(ctx, release); err != nil {
		return err
	}
	if err := g.requireMainTip(ctx, release); err != nil {
		return err
	}
	return g.requireTagAbsent(ctx, release)
}

// VerifyImageSource checks the source, protected tag and policy before image
// publication, without requiring private-draft access or repository writes.
// Bind rechecks the exact numeric draft before recording any image binding.
func (g *Guard) VerifyImageSource(ctx context.Context, release Context) error {
	return g.trustReserved(ctx, release)
}

func (g *Guard) trustReserved(ctx context.Context, release Context) error {
	if err := g.verifyPolicy(ctx, release); err != nil {
		return err
	}
	if err := g.requireMainTip(ctx, release); err != nil {
		return err
	}
	return g.requireTag(ctx, release)
}

func (g *Guard) verifyPolicy(ctx context.Context, release Context) error {
	if err := g.requireRepository(ctx, release); err != nil {
		return err
	}
	if err := g.requireMainProtection(ctx, release); err != nil {
		return err
	}
	if err := g.requirePublicPackage(ctx, release); err != nil {
		return err
	}
	if err := g.requireRuleset(ctx, release); err != nil {
		return err
	}
	if err := g.requireImmutableReleases(ctx, release); err != nil {
		return err
	}
	if err := g.requireActionsPolicy(ctx, release); err != nil {
		return err
	}
	return nil
}

func (g *Guard) requireMainProtection(ctx context.Context, release Context) error {
	apiResponse, err := g.github.apiJSON(ctx, release.policyToken, http.MethodGet, repoPath()+"/branches/main", nil, nil, http.StatusOK)
	if err != nil {
		return errors.New("live main protection check failed")
	}
	var branch struct {
		Name          *string `json:"name"`
		Protected     *bool   `json:"protected"`
		ProtectionURL *string `json:"protection_url"`
		Commit        *struct {
			SHA *string `json:"sha"`
		} `json:"commit"`
	}
	if err := decodeJSON(apiResponse.body, &branch); err != nil || branch.Name == nil || branch.Protected == nil || branch.ProtectionURL == nil || branch.Commit == nil || branch.Commit.SHA == nil {
		return errors.New("live main protection check returned invalid metadata")
	}
	expectedURL := githubAPIOrigin + repoPath() + "/branches/main/protection"
	if *branch.Name != "main" || !*branch.Protected || *branch.ProtectionURL != expectedURL || !isSHA(*branch.Commit.SHA) {
		return errors.New("live main branch is not protected")
	}
	return nil
}

func (g *Guard) requireRepository(ctx context.Context, release Context) error {
	apiResponse, err := g.github.apiJSON(ctx, release.token, http.MethodGet, repoPath(), nil, nil, http.StatusOK)
	if err != nil {
		return errors.New("repository trust check failed")
	}
	var metadata struct {
		ID            *int64  `json:"id"`
		FullName      *string `json:"full_name"`
		Private       *bool   `json:"private"`
		Visibility    *string `json:"visibility"`
		DefaultBranch *string `json:"default_branch"`
		Owner         *struct {
			ID    *int64  `json:"id"`
			Login *string `json:"login"`
		} `json:"owner"`
	}
	if err := decodeJSON(apiResponse.body, &metadata); err != nil {
		return errors.New("repository trust check returned invalid metadata")
	}
	if metadata.ID == nil || *metadata.ID != release.RepositoryID || metadata.FullName == nil || *metadata.FullName != RepositoryName || metadata.Private == nil || *metadata.Private || metadata.Visibility == nil || *metadata.Visibility != "public" || metadata.DefaultBranch == nil || *metadata.DefaultBranch != "main" || metadata.Owner == nil || metadata.Owner.ID == nil || *metadata.Owner.ID != release.RepositoryOwnerID || metadata.Owner.Login == nil || *metadata.Owner.Login != RepositoryOwner {
		return errors.New("repository trust policy is not satisfied")
	}
	return nil
}

func (g *Guard) requireMainTip(ctx context.Context, release Context) error {
	apiResponse, err := g.github.apiJSON(ctx, release.token, http.MethodGet, repoPath()+"/commits/main", nil, nil, http.StatusOK)
	if err != nil {
		return errors.New("main revision check failed")
	}
	var commit struct {
		SHA *string `json:"sha"`
	}
	if err := decodeJSON(apiResponse.body, &commit); err != nil || commit.SHA == nil || !isSHA(*commit.SHA) {
		return errors.New("main revision check returned invalid metadata")
	}
	if *commit.SHA != release.SourceSHA {
		return errors.New("release source is no longer the live main tip")
	}
	return nil
}

func (g *Guard) requirePublicPackage(ctx context.Context, release Context) error {
	path := "/users/" + RepositoryOwner + "/packages/container/" + PackageName
	apiResponse, err := g.github.apiJSON(ctx, release.token, http.MethodGet, path, nil, nil, http.StatusOK)
	if err != nil {
		return errors.New("container package trust check failed")
	}
	var metadata struct {
		Name        *string `json:"name"`
		PackageType *string `json:"package_type"`
		Visibility  *string `json:"visibility"`
		Owner       *struct {
			ID    *int64  `json:"id"`
			Login *string `json:"login"`
		} `json:"owner"`
		Repository *struct {
			ID       *int64  `json:"id"`
			FullName *string `json:"full_name"`
		} `json:"repository"`
	}
	if err := decodeJSON(apiResponse.body, &metadata); err != nil {
		return errors.New("container package trust check returned invalid metadata")
	}
	if metadata.Name == nil || *metadata.Name != release.Package || metadata.PackageType == nil || *metadata.PackageType != "container" || metadata.Visibility == nil || *metadata.Visibility != "public" || metadata.Owner == nil || metadata.Owner.ID == nil || *metadata.Owner.ID != release.RepositoryOwnerID || metadata.Owner.Login == nil || *metadata.Owner.Login != RepositoryOwner || metadata.Repository == nil || metadata.Repository.ID == nil || *metadata.Repository.ID != release.RepositoryID || metadata.Repository.FullName == nil || *metadata.Repository.FullName != RepositoryName {
		return errors.New("container package trust policy is not satisfied")
	}
	return nil
}

func (g *Guard) requireImageBinding(ctx context.Context, release Context, binding bindingInput) error {
	path := "/users/" + RepositoryOwner + "/packages/container/" + PackageName + "/versions"
	seenIDs := make(map[int64]struct{})
	matches := 0
	for page := 1; page <= 20; page++ {
		query := url.Values{"per_page": {"100"}, "page": {strconv.Itoa(page)}}
		apiResponse, err := g.github.apiJSON(ctx, release.token, http.MethodGet, path, query, nil, http.StatusOK)
		if err != nil {
			return errors.New("OCI image binding check failed")
		}
		var versions *[]struct {
			ID       *int64  `json:"id"`
			Name     *string `json:"name"`
			Metadata *struct {
				PackageType *string `json:"package_type"`
				Container   *struct {
					Tags *[]string `json:"tags"`
				} `json:"container"`
			} `json:"metadata"`
		}
		if err := decodeJSON(apiResponse.body, &versions); err != nil || versions == nil || len(*versions) > 100 {
			return errors.New("OCI image binding check returned invalid metadata")
		}
		for _, version := range *versions {
			if version.ID == nil || *version.ID <= 0 || version.Name == nil || !validDigest(*version.Name) || version.Metadata == nil || version.Metadata.PackageType == nil || *version.Metadata.PackageType != "container" || version.Metadata.Container == nil || version.Metadata.Container.Tags == nil {
				return errors.New("OCI image binding check returned incomplete metadata")
			}
			if _, duplicate := seenIDs[*version.ID]; duplicate {
				return errors.New("OCI image binding check returned a duplicate version")
			}
			seenIDs[*version.ID] = struct{}{}
			seenTags := make(map[string]struct{})
			for _, tag := range *version.Metadata.Container.Tags {
				if tag == "" {
					return errors.New("OCI image binding check returned an empty tag")
				}
				if _, duplicate := seenTags[tag]; duplicate {
					return errors.New("OCI image binding check returned a duplicate tag")
				}
				seenTags[tag] = struct{}{}
				if tag == release.Tag || tag == release.Version || tag == "latest" {
					return errors.New("OCI package contains a forbidden release alias")
				}
				if tag == release.OCITag() {
					matches++
					if len(*version.Metadata.Container.Tags) != 1 {
						return errors.New("permanent OCI version has an unexpected alias tag")
					}
					if *version.Name != binding.digest {
						return errors.New("permanent OCI tag resolves to a different digest")
					}
				}
			}
		}
		next := hasNextPage(apiResponse.header.Get("Link"))
		if !next {
			if matches != 1 {
				return errors.New("permanent OCI tag does not resolve uniquely to the image digest")
			}
			return nil
		}
		if len(*versions) == 0 {
			return errors.New("OCI image binding pagination is invalid")
		}
	}
	return errors.New("OCI image binding pagination exceeds the safety bound")
}

func (g *Guard) requireRuleset(ctx context.Context, release Context) error {
	query := url.Values{"includes_parents": {"false"}, "per_page": {"100"}}
	apiResponse, err := g.github.apiJSON(ctx, release.policyToken, http.MethodGet, repoPath()+"/rulesets", query, nil, http.StatusOK)
	if err != nil {
		return errors.New("release tag ruleset check failed")
	}
	if hasNextPage(apiResponse.header.Get("Link")) {
		return errors.New("release tag ruleset result is ambiguous")
	}
	var summaries []struct {
		ID          *int64  `json:"id"`
		Name        *string `json:"name"`
		Target      *string `json:"target"`
		Enforcement *string `json:"enforcement"`
	}
	if err := decodeJSON(apiResponse.body, &summaries); err != nil {
		return errors.New("release tag ruleset check returned invalid metadata")
	}
	var rulesetID int64
	for _, summary := range summaries {
		if summary.Name != nil && *summary.Name == releaseRulesetName {
			if rulesetID != 0 || summary.ID == nil || *summary.ID <= 0 || summary.Target == nil || *summary.Target != "tag" || summary.Enforcement == nil || *summary.Enforcement != "active" {
				return errors.New("release tag ruleset is ambiguous or inactive")
			}
			rulesetID = *summary.ID
		}
	}
	if rulesetID == 0 {
		return errors.New("release tag ruleset is missing")
	}
	detailResponse, err := g.github.apiJSON(ctx, release.policyToken, http.MethodGet, repoPath()+"/rulesets/"+strconv.FormatInt(rulesetID, 10), nil, nil, http.StatusOK)
	if err != nil {
		return errors.New("release tag ruleset detail check failed")
	}
	var detail struct {
		ID           *int64  `json:"id"`
		Name         *string `json:"name"`
		Target       *string `json:"target"`
		SourceType   *string `json:"source_type"`
		Source       *string `json:"source"`
		Enforcement  *string `json:"enforcement"`
		BypassActors *[]struct {
			ActorID    *int64  `json:"actor_id"`
			ActorType  *string `json:"actor_type"`
			BypassMode *string `json:"bypass_mode"`
		} `json:"bypass_actors"`
		Conditions *struct {
			RefName *struct {
				Include *[]string `json:"include"`
				Exclude *[]string `json:"exclude"`
			} `json:"ref_name"`
		} `json:"conditions"`
		Rules *[]struct {
			Type *string `json:"type"`
		} `json:"rules"`
	}
	if err := decodeJSON(detailResponse.body, &detail); err != nil {
		return errors.New("release tag ruleset detail is invalid")
	}
	if detail.ID == nil || *detail.ID != rulesetID || detail.Name == nil || *detail.Name != releaseRulesetName || detail.Target == nil || *detail.Target != "tag" || detail.SourceType == nil || *detail.SourceType != "Repository" || detail.Source == nil || *detail.Source != RepositoryName || detail.Enforcement == nil || *detail.Enforcement != "active" || detail.BypassActors == nil || detail.Conditions == nil || detail.Conditions.RefName == nil || detail.Conditions.RefName.Include == nil || detail.Conditions.RefName.Exclude == nil || detail.Rules == nil {
		return errors.New("release tag ruleset detail is incomplete")
	}
	if len(*detail.BypassActors) != 0 {
		return errors.New("release tag ruleset has an unexpected bypass actor set")
	}
	includes := *detail.Conditions.RefName.Include
	excludes := *detail.Conditions.RefName.Exclude
	if len(includes) != 1 || includes[0] != "refs/tags/v*" || len(excludes) != 0 {
		return errors.New("release tag ruleset has an unexpected ref condition")
	}
	requiredRules := map[string]bool{"update": false, "deletion": false}
	if len(*detail.Rules) != len(requiredRules) {
		return errors.New("release tag ruleset contains unexpected rules")
	}
	seen := make(map[string]struct{})
	for _, rule := range *detail.Rules {
		if rule.Type == nil || *rule.Type == "" {
			return errors.New("release tag ruleset contains an invalid rule")
		}
		if _, duplicate := seen[*rule.Type]; duplicate {
			return errors.New("release tag ruleset contains a duplicate rule")
		}
		seen[*rule.Type] = struct{}{}
		if _, required := requiredRules[*rule.Type]; required {
			requiredRules[*rule.Type] = true
		}
	}
	for rule, present := range requiredRules {
		if !present {
			return fmt.Errorf("release tag ruleset is missing the %s rule", rule)
		}
	}
	return nil
}

func (g *Guard) requireImmutableReleases(ctx context.Context, release Context) error {
	apiResponse, err := g.github.apiJSON(ctx, release.policyToken, http.MethodGet, repoPath()+"/immutable-releases", nil, nil, http.StatusOK)
	if err != nil {
		return errors.New("immutable release policy check failed")
	}
	var policy struct {
		Enabled *bool `json:"enabled"`
	}
	if err := decodeJSON(apiResponse.body, &policy); err != nil || policy.Enabled == nil {
		return errors.New("immutable release policy check returned invalid metadata")
	}
	if !*policy.Enabled {
		return errors.New("immutable releases are not enabled")
	}
	return nil
}

func (g *Guard) requireActionsPolicy(ctx context.Context, release Context) error {
	permissionsResponse, err := g.github.apiJSON(ctx, release.policyToken, http.MethodGet, repoPath()+"/actions/permissions", nil, nil, http.StatusOK)
	if err != nil {
		return errors.New("Actions policy check failed")
	}
	var permissions struct {
		Enabled            *bool `json:"enabled"`
		SHAPinningRequired *bool `json:"sha_pinning_required"`
	}
	if err := decodeJSON(permissionsResponse.body, &permissions); err != nil || permissions.Enabled == nil || permissions.SHAPinningRequired == nil {
		return errors.New("Actions policy check returned invalid metadata")
	}
	if !*permissions.Enabled || !*permissions.SHAPinningRequired {
		return errors.New("Actions SHA-pinning policy is not satisfied")
	}
	workflowResponse, err := g.github.apiJSON(ctx, release.policyToken, http.MethodGet, repoPath()+"/actions/permissions/workflow", nil, nil, http.StatusOK)
	if err != nil {
		return errors.New("default workflow permission check failed")
	}
	var workflow struct {
		Default    *string `json:"default_workflow_permissions"`
		CanApprove *bool   `json:"can_approve_pull_request_reviews"`
	}
	if err := decodeJSON(workflowResponse.body, &workflow); err != nil || workflow.Default == nil || workflow.CanApprove == nil {
		return errors.New("default workflow permission check returned invalid metadata")
	}
	if *workflow.Default != "read" || *workflow.CanApprove {
		return errors.New("default workflow token permissions are not read-only and non-approving")
	}
	return nil
}

func (g *Guard) requireTagAbsent(ctx context.Context, release Context) error {
	apiResponse, err := g.github.apiJSON(ctx, release.token, http.MethodGet, repoPath()+"/git/ref/tags/"+release.Tag, nil, nil, http.StatusOK, http.StatusNotFound)
	if err != nil {
		return errors.New("release tag absence check failed")
	}
	if apiResponse.status != http.StatusNotFound {
		return errors.New("release tag already exists")
	}
	return nil
}

func (g *Guard) requireReleaseTagAbsent(ctx context.Context, release Context) error {
	path := repoPath() + "/releases"
	seenIDs := make(map[int64]struct{})
	for page := 1; page <= 20; page++ {
		query := url.Values{"per_page": {"100"}, "page": {strconv.Itoa(page)}}
		// Drafts are omitted from lists obtained with a read-only credential.
		// Only Reserve calls this, in an ephemeral contents-write job.
		apiResponse, err := g.github.apiJSON(ctx, release.token, http.MethodGet, path, query, nil, http.StatusOK)
		if err != nil {
			return errors.New("release tag reservation check failed")
		}
		var releases *[]struct {
			ID      *int64  `json:"id"`
			TagName *string `json:"tag_name"`
		}
		if err := decodeJSON(apiResponse.body, &releases); err != nil || releases == nil || len(*releases) > 100 {
			return errors.New("release tag reservation check returned invalid metadata")
		}
		for _, remote := range *releases {
			if remote.ID == nil || *remote.ID <= 0 || remote.TagName == nil || *remote.TagName == "" {
				return errors.New("release tag reservation check returned incomplete metadata")
			}
			if _, duplicate := seenIDs[*remote.ID]; duplicate {
				return errors.New("release tag reservation check returned a duplicate release")
			}
			seenIDs[*remote.ID] = struct{}{}
			if *remote.TagName == release.Tag {
				return errors.New("a release already reserves the requested tag")
			}
		}
		if !hasNextPage(apiResponse.header.Get("Link")) {
			return nil
		}
		if len(*releases) == 0 {
			return errors.New("release tag reservation pagination is invalid")
		}
	}
	return errors.New("release tag reservation pagination exceeds the safety bound")
}

func (g *Guard) requireTag(ctx context.Context, release Context) error {
	apiResponse, err := g.github.apiJSON(ctx, release.token, http.MethodGet, repoPath()+"/git/ref/tags/"+release.Tag, nil, nil, http.StatusOK)
	if err != nil {
		return errors.New("release tag check failed")
	}
	var reference struct {
		Ref    *string `json:"ref"`
		Object *struct {
			Type *string `json:"type"`
			SHA  *string `json:"sha"`
		} `json:"object"`
	}
	if err := decodeJSON(apiResponse.body, &reference); err != nil || reference.Ref == nil || reference.Object == nil || reference.Object.Type == nil || reference.Object.SHA == nil {
		return errors.New("release tag check returned invalid metadata")
	}
	if *reference.Ref != "refs/tags/"+release.Tag || *reference.Object.Type != "commit" || *reference.Object.SHA != release.SourceSHA {
		return errors.New("release tag is not the expected lightweight source tag")
	}
	commitResponse, err := g.github.apiJSON(ctx, release.token, http.MethodGet, repoPath()+"/commits/"+release.Tag, nil, nil, http.StatusOK)
	if err != nil {
		return errors.New("release tag resolution check failed")
	}
	var commit struct {
		SHA *string `json:"sha"`
	}
	if err := decodeJSON(commitResponse.body, &commit); err != nil || commit.SHA == nil || *commit.SHA != release.SourceSHA {
		return errors.New("release tag does not resolve to the release source")
	}
	return nil
}

func hasNextPage(link string) bool {
	return link != "" && (containsLinkRelation(link, `rel="next"`) || containsLinkRelation(link, "rel=next"))
}

func containsLinkRelation(value, relation string) bool {
	for index := 0; index+len(relation) <= len(value); index++ {
		if value[index:index+len(relation)] == relation {
			return true
		}
	}
	return false
}

func repoPath() string {
	return "/repos/" + RepositoryName
}
