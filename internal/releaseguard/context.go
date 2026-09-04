package releaseguard

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

const (
	RepositoryName  = "d3vi1/nut-2-unifi-ups-gateway"
	RepositoryOwner = "d3vi1"
	PackageName     = "nut-2-unifi-ups-gateway"
	ImageName       = "ghcr.io/d3vi1/nut-2-unifi-ups-gateway"
)

// Context is the immutable identity of one release workflow invocation.
type Context struct {
	Repository        string
	RepositoryID      int64
	RepositoryOwnerID int64
	Tag               string
	Version           string
	Prerelease        bool
	SourceSHA         string
	RunID             int64
	RunAttempt        int64
	Package           string
	OutputPath        string

	token       string
	policyToken string
}

// String deliberately omits credentials and runner-local paths.
func (c Context) String() string {
	return fmt.Sprintf("release %s for repository %d at %s (run %d, attempt %d)", c.Tag, c.RepositoryID, c.SourceSHA, c.RunID, c.RunAttempt)
}

// GoString keeps %#v formatting from exposing unexported credential fields.
func (c Context) GoString() string {
	return c.String()
}

// LoadContext validates the GitHub Actions identity before any API access.
func LoadContext(getenv func(string) string) (Context, error) {
	if getenv == nil {
		return Context{}, errors.New("release environment is unavailable")
	}
	required := func(name string) (string, error) {
		value := getenv(name)
		if value == "" {
			return "", fmt.Errorf("%s is required", name)
		}
		return value, nil
	}

	repository, err := required("GITHUB_REPOSITORY")
	if err != nil {
		return Context{}, err
	}
	if repository != RepositoryName {
		return Context{}, errors.New("GITHUB_REPOSITORY is not the release repository")
	}
	if owner, err := required("GITHUB_REPOSITORY_OWNER"); err != nil {
		return Context{}, err
	} else if owner != RepositoryOwner {
		return Context{}, errors.New("GITHUB_REPOSITORY_OWNER is not the release owner")
	}
	if event, err := required("GITHUB_EVENT_NAME"); err != nil {
		return Context{}, err
	} else if event != "workflow_dispatch" {
		return Context{}, errors.New("release commands require workflow_dispatch")
	}
	if ref, err := required("GITHUB_REF"); err != nil {
		return Context{}, err
	} else if ref != "refs/heads/main" {
		return Context{}, errors.New("release commands require refs/heads/main")
	}
	if refType, err := required("GITHUB_REF_TYPE"); err != nil {
		return Context{}, err
	} else if refType != "branch" {
		return Context{}, errors.New("release commands require a branch ref")
	}
	if refName, err := required("GITHUB_REF_NAME"); err != nil {
		return Context{}, err
	} else if refName != "main" {
		return Context{}, errors.New("release commands require the main branch")
	}
	if protected, err := required("GITHUB_REF_PROTECTED"); err != nil {
		return Context{}, err
	} else if protected != "true" {
		return Context{}, errors.New("the live main ref must be protected")
	}
	if serverURL, err := required("GITHUB_SERVER_URL"); err != nil {
		return Context{}, err
	} else if serverURL != "https://github.com" {
		return Context{}, errors.New("release commands require github.com")
	}
	if apiURL, err := required("GITHUB_API_URL"); err != nil {
		return Context{}, err
	} else if apiURL != "https://api.github.com" {
		return Context{}, errors.New("release commands require the public GitHub API")
	}
	if workflowRef, err := required("GITHUB_WORKFLOW_REF"); err != nil {
		return Context{}, err
	} else if workflowRef != RepositoryName+"/.github/workflows/release.yml@refs/heads/main" {
		return Context{}, errors.New("release commands require the canonical release workflow")
	}

	repositoryID, err := parsePositiveInt64(getenv("GITHUB_REPOSITORY_ID"), "GITHUB_REPOSITORY_ID")
	if err != nil {
		return Context{}, err
	}
	repositoryOwnerID, err := parsePositiveInt64(getenv("GITHUB_REPOSITORY_OWNER_ID"), "GITHUB_REPOSITORY_OWNER_ID")
	if err != nil {
		return Context{}, err
	}
	sourceSHA, err := required("GITHUB_SHA")
	if err != nil {
		return Context{}, err
	}
	if !isSHA(sourceSHA) {
		return Context{}, errors.New("GITHUB_SHA must be a lowercase full commit SHA")
	}
	workflowSHA, err := required("GITHUB_WORKFLOW_SHA")
	if err != nil {
		return Context{}, err
	}
	if workflowSHA != sourceSHA {
		return Context{}, errors.New("workflow and release source revisions differ")
	}
	runID, err := parsePositiveInt64(getenv("GITHUB_RUN_ID"), "GITHUB_RUN_ID")
	if err != nil {
		return Context{}, err
	}
	runAttempt, err := parsePositiveInt64(getenv("GITHUB_RUN_ATTEMPT"), "GITHUB_RUN_ATTEMPT")
	if err != nil {
		return Context{}, err
	}
	if runAttempt != 1 {
		return Context{}, errors.New("release commands refuse workflow reruns")
	}

	tag, err := required("N2U_RELEASE_TAG")
	if err != nil {
		return Context{}, err
	}
	version, prerelease, err := parseSemVerTag(tag)
	if err != nil {
		return Context{}, err
	}
	packageName, err := required("N2U_RELEASE_PACKAGE")
	if err != nil {
		return Context{}, err
	}
	if packageName != PackageName {
		return Context{}, errors.New("N2U_RELEASE_PACKAGE is not the release package")
	}
	token, err := required("GH_TOKEN")
	if err != nil {
		return Context{}, err
	}
	if err := validateToken(token, "GH_TOKEN"); err != nil {
		return Context{}, err
	}
	policyToken, err := required("N2U_RELEASE_POLICY_TOKEN")
	if err != nil {
		return Context{}, err
	}
	if err := validateToken(policyToken, "N2U_RELEASE_POLICY_TOKEN"); err != nil {
		return Context{}, err
	}
	if token == policyToken {
		return Context{}, errors.New("release and policy tokens must be separate credentials")
	}

	context := Context{
		Repository:        repository,
		RepositoryID:      repositoryID,
		RepositoryOwnerID: repositoryOwnerID,
		Tag:               tag,
		Version:           version,
		Prerelease:        prerelease,
		SourceSHA:         sourceSHA,
		RunID:             runID,
		RunAttempt:        runAttempt,
		Package:           packageName,
		OutputPath:        getenv("GITHUB_OUTPUT"),
		token:             token,
		policyToken:       policyToken,
	}
	return context, nil
}

// OCITag is unique to one non-rerunnable workflow invocation. It is never a
// floating or SemVer registry tag.
func (c Context) OCITag() string {
	return fmt.Sprintf("release-run-%d-attempt-%d", c.RunID, c.RunAttempt)
}

func parsePositiveInt64(raw, name string) (int64, error) {
	if raw == "" {
		return 0, fmt.Errorf("%s is required", name)
	}
	if len(raw) > 19 || strings.HasPrefix(raw, "+") || (len(raw) > 1 && raw[0] == '0') {
		return 0, fmt.Errorf("%s must be a canonical positive integer", name)
	}
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || value <= 0 {
		return 0, fmt.Errorf("%s must be a canonical positive integer", name)
	}
	return value, nil
}

func isSHA(value string) bool {
	if len(value) != 40 {
		return false
	}
	for _, character := range value {
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
			return false
		}
	}
	return true
}

func parseSemVerTag(tag string) (string, bool, error) {
	if len(tag) < 6 || len(tag) > 96 || tag[0] != 'v' || strings.Contains(tag, "+") {
		return "", false, errors.New("N2U_RELEASE_TAG must be v-prefixed SemVer without build metadata")
	}
	version := tag[1:]
	core := version
	prerelease := ""
	if separator := strings.IndexByte(version, '-'); separator >= 0 {
		core = version[:separator]
		prerelease = version[separator+1:]
		if prerelease == "" {
			return "", false, errors.New("N2U_RELEASE_TAG has an empty prerelease")
		}
	}
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return "", false, errors.New("N2U_RELEASE_TAG must contain major, minor, and patch")
	}
	for _, part := range parts {
		if !canonicalNumericIdentifier(part) {
			return "", false, errors.New("N2U_RELEASE_TAG has a non-canonical numeric component")
		}
	}
	if prerelease != "" {
		for _, identifier := range strings.Split(prerelease, ".") {
			if identifier == "" {
				return "", false, errors.New("N2U_RELEASE_TAG has an empty prerelease identifier")
			}
			numeric := true
			for _, character := range identifier {
				if !((character >= '0' && character <= '9') || (character >= 'A' && character <= 'Z') || (character >= 'a' && character <= 'z') || character == '-') {
					return "", false, errors.New("N2U_RELEASE_TAG has an invalid prerelease identifier")
				}
				if character < '0' || character > '9' {
					numeric = false
				}
			}
			if numeric && !canonicalNumericIdentifier(identifier) {
				return "", false, errors.New("N2U_RELEASE_TAG has a non-canonical numeric prerelease identifier")
			}
		}
	}
	return version, prerelease != "", nil
}

func canonicalNumericIdentifier(value string) bool {
	if value == "" || (len(value) > 1 && value[0] == '0') {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func validateToken(token, name string) error {
	if len(token) < 8 || len(token) > 4096 {
		return fmt.Errorf("%s has an invalid length", name)
	}
	for _, character := range token {
		if character <= 0x20 || character == 0x7f {
			return fmt.Errorf("%s contains an invalid character", name)
		}
	}
	return nil
}
