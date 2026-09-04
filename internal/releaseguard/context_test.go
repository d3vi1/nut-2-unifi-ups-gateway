package releaseguard

import (
	"fmt"
	"strings"
	"testing"
)

const testSHA = "0123456789abcdef0123456789abcdef01234567"

func validEnvironment() map[string]string {
	return map[string]string{
		"GITHUB_REPOSITORY":          RepositoryName,
		"GITHUB_REPOSITORY_OWNER":    RepositoryOwner,
		"GITHUB_REPOSITORY_ID":       "123456",
		"GITHUB_REPOSITORY_OWNER_ID": "654321",
		"GITHUB_EVENT_NAME":          "workflow_dispatch",
		"GITHUB_REF":                 "refs/heads/main",
		"GITHUB_REF_TYPE":            "branch",
		"GITHUB_REF_NAME":            "main",
		"GITHUB_REF_PROTECTED":       "true",
		"GITHUB_SERVER_URL":          "https://github.com",
		"GITHUB_API_URL":             "https://api.github.com",
		"GITHUB_WORKFLOW_REF":        RepositoryName + "/.github/workflows/release.yml@refs/heads/main",
		"GITHUB_SHA":                 testSHA,
		"GITHUB_WORKFLOW_SHA":        testSHA,
		"GITHUB_RUN_ID":              "987654321",
		"GITHUB_RUN_ATTEMPT":         "1",
		"N2U_RELEASE_TAG":            "v0.9.0",
		"N2U_RELEASE_PACKAGE":        PackageName,
		"GH_TOKEN":                   "release-token-value",
		"N2U_RELEASE_POLICY_TOKEN":   "policy-token-value",
		"GITHUB_OUTPUT":              "/tmp/releaseguard-output",
		"N2U_RELEASE_ID":             "42",
		"N2U_IMAGE_DIGEST":           "sha256:" + strings.Repeat("a", 64),
		"N2U_ATTESTATION_ID":         "7654",
		"N2U_ATTESTATION_URL":        "https://github.com/" + RepositoryName + "/attestations/7654",
		"N2U_PUBLICATION_ATTEMPT":    "1",
		"N2U_UNUSED_SECRET_SENTINEL": "never-print-this",
	}
}

func TestContextFormattingRedactsCredentials(t *testing.T) {
	environment := validEnvironment()
	release, err := LoadContext(mapLookup(environment))
	if err != nil {
		t.Fatal(err)
	}
	for _, formatted := range []string{fmt.Sprint(release), fmt.Sprintf("%+v", release), fmt.Sprintf("%#v", release)} {
		if strings.Contains(formatted, environment["GH_TOKEN"]) || strings.Contains(formatted, environment["N2U_RELEASE_POLICY_TOKEN"]) || strings.Contains(formatted, environment["GITHUB_OUTPUT"]) {
			t.Fatal("Context formatting exposed a credential or runner-local path")
		}
	}
}

func mapLookup(values map[string]string) func(string) string {
	return func(name string) string { return values[name] }
}

func cloneEnvironment(source map[string]string) map[string]string {
	result := make(map[string]string, len(source))
	for name, value := range source {
		result[name] = value
	}
	return result
}

func TestLoadContext(t *testing.T) {
	environment := validEnvironment()
	release, err := LoadContext(mapLookup(environment))
	if err != nil {
		t.Fatal(err)
	}
	if release.Tag != "v0.9.0" || release.Version != "0.9.0" || release.Prerelease {
		t.Fatal("unexpected release identity")
	}
	if got, want := release.OCITag(), "release-run-987654321-attempt-1"; got != want {
		t.Fatalf("OCITag() = %q, want %q", got, want)
	}
}

func TestLoadContextAcceptsCanonicalPrerelease(t *testing.T) {
	environment := validEnvironment()
	environment["N2U_RELEASE_TAG"] = "v1.2.3-rc.1"
	release, err := LoadContext(mapLookup(environment))
	if err != nil {
		t.Fatal(err)
	}
	if release.Version != "1.2.3-rc.1" || !release.Prerelease {
		t.Fatal("unexpected prerelease identity")
	}
}

func TestLoadContextFailsClosed(t *testing.T) {
	tests := []struct {
		name  string
		key   string
		value string
	}{
		{name: "wrong repository", key: "GITHUB_REPOSITORY", value: "attacker/repository"},
		{name: "wrong owner", key: "GITHUB_REPOSITORY_OWNER", value: "attacker"},
		{name: "tag push", key: "GITHUB_EVENT_NAME", value: "push"},
		{name: "tag ref", key: "GITHUB_REF", value: "refs/tags/v0.9.0"},
		{name: "wrong ref type", key: "GITHUB_REF_TYPE", value: "tag"},
		{name: "wrong ref name", key: "GITHUB_REF_NAME", value: "release"},
		{name: "unprotected main", key: "GITHUB_REF_PROTECTED", value: "false"},
		{name: "enterprise server", key: "GITHUB_SERVER_URL", value: "https://example.invalid"},
		{name: "alternate API", key: "GITHUB_API_URL", value: "https://example.invalid"},
		{name: "different workflow", key: "GITHUB_WORKFLOW_REF", value: RepositoryName + "/.github/workflows/other.yml@refs/heads/main"},
		{name: "noncanonical repository ID", key: "GITHUB_REPOSITORY_ID", value: "01"},
		{name: "noncanonical owner ID", key: "GITHUB_REPOSITORY_OWNER_ID", value: "01"},
		{name: "short source", key: "GITHUB_SHA", value: "abc"},
		{name: "workflow mismatch", key: "GITHUB_WORKFLOW_SHA", value: strings.Repeat("a", 40)},
		{name: "noncanonical run ID", key: "GITHUB_RUN_ID", value: "+1"},
		{name: "rerun", key: "GITHUB_RUN_ATTEMPT", value: "2"},
		{name: "wrong package", key: "N2U_RELEASE_PACKAGE", value: "other"},
		{name: "token control", key: "GH_TOKEN", value: "valid-but\nunsafe"},
		{name: "same credentials", key: "N2U_RELEASE_POLICY_TOKEN", value: "release-token-value"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			environment := cloneEnvironment(validEnvironment())
			environment[test.key] = test.value
			if _, err := LoadContext(mapLookup(environment)); err == nil {
				t.Fatal("LoadContext unexpectedly succeeded")
			}
		})
	}
}

func TestSemVerTagValidation(t *testing.T) {
	valid := []string{"v0.0.0", "v1.2.3", "v1.2.3-0", "v1.2.3-alpha.1", "v10.20.30-x-y.Z"}
	for _, tag := range valid {
		if _, _, err := parseSemVerTag(tag); err != nil {
			t.Errorf("parseSemVerTag(%q): %v", tag, err)
		}
	}
	invalid := []string{"1.2.3", "v1.2", "v1.2.3+build", "v01.2.3", "v1.02.3", "v1.2.03", "v1.2.3-", "v1.2.3-01", "v1.2.3-a..b", "v1.2.3-a_b", "v1.2.3-+"}
	for _, tag := range invalid {
		if _, _, err := parseSemVerTag(tag); err == nil {
			t.Errorf("parseSemVerTag(%q) unexpectedly succeeded", tag)
		}
	}
}
