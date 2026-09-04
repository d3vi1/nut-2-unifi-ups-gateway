package buildtest

import (
	"crypto/sha256"
	"fmt"
	"regexp"
	"strings"
	"testing"
)

func TestProtocolEvidenceKeepsDeploymentObservationsRedacted(t *testing.T) {
	document := readRepositoryFile(t, "docs", "protocol-evidence.md")

	for _, forbidden := range []string{
		"The current site",
		"then-current configuration",
		"On the live Synology source",
	} {
		if strings.Contains(document, forbidden) {
			t.Errorf("protocol evidence contains unredacted deployment wording %q", forbidden)
		}
	}

	for _, required := range []string{
		"A redacted interoperability observation",
		"a redacted APC/Synology interoperability sample",
		"A redacted same-host Synology/Network sample",
		"The separate opaque `ups.id` value differed from that served name",
		"synthetic served name `ups`",
	} {
		if !strings.Contains(document, required) {
			t.Errorf("protocol evidence is missing redaction boundary %q", required)
		}
	}

	adoption := evidenceParagraph(t, document, "A redacted interoperability observation")
	if matched := regexp.MustCompile(`(?i)\b(?:one|two|three|four|[0-9]+)\s+(?:nvr|gateway|console)s?\b`).FindString(adoption); matched != "" {
		t.Errorf("redacted adoption evidence contains counted device inventory %q", matched)
	}
	if regexp.MustCompile(`\b20[0-9]{2}-[0-9]{2}-[0-9]{2}\b`).MatchString(adoption) {
		t.Error("redacted adoption evidence contains a site-observation date")
	}
	if !strings.Contains(adoption, "Device counts, names, and site identity are\nintentionally omitted.") {
		t.Error("redacted adoption evidence no longer states its identity boundary")
	}

	nutServer := evidenceParagraph(t, document, "A redacted same-host Synology/Network sample")
	if regexp.MustCompile("(?i)`ups\\.id`[^.\\n]*(?:=|\\bwas\\b|\\bis\\b|\\bequals\\b)").MatchString(nutServer) {
		t.Error("redacted NUT evidence assigns a site-derived ups.id value")
	}
	if !strings.Contains(nutServer, "operators must replace it when `LIST UPS` reports a\ndifferent value") {
		t.Error("synthetic served name is not separated from operator configuration")
	}
}

func TestVolatileCfgVersionCompatibilityIsDefaultOffAndBounded(t *testing.T) {
	const option = "N2U_UNIFI_HTTP_GCM_VOLATILE_CFGVERSION_SYNC"

	compose := readRepositoryFile(t, "deploy", "synology", "compose.yaml")
	if !strings.Contains(compose, option+": ${"+option+":-false}") {
		t.Fatalf("Compose does not pass %s through with a false default", option)
	}
	example := readRepositoryFile(t, "deploy", "synology", ".env.example")
	if !strings.Contains(example, option+"=false") {
		t.Fatalf("Synology environment example does not keep %s disabled", option)
	}
	if !strings.Contains(example, "Whether it clears Getting Ready remains CANDIDATE") ||
		!strings.Contains(example, "does not promise a Network UI transition") {
		t.Error("Synology environment example presents the option as established interoperability")
	}

	configuration := singleSpaced(readRepositoryFile(t, "docs", "configuration.md"))
	for _, required := range []string{
		"| `" + option + "` | `false` |",
		"authenticated GCM `setparam` response",
		"must contain exactly one non-empty entry: a syntactically valid",
		"`system_cfg` may accompany that response, but it remains observation-only",
		"not saved to the state file",
		"does not provide request-response correlation",
	} {
		if !strings.Contains(configuration, required) {
			t.Errorf("configuration reference is missing compatibility boundary %q", required)
		}
	}

	security := singleSpaced(readRepositoryFile(t, "SECURITY.md"))
	for _, required := range []string{
		"contains exactly that one non-empty entry",
		"accompanying `system_cfg` remains observed and ignored",
		"Persistent replay nonces remain unchanged",
		"must not be used across an untrusted network",
	} {
		if !strings.Contains(security, required) {
			t.Errorf("security policy is missing compatibility boundary %q", required)
		}
	}

	protocol := readRepositoryFile(t, "docs", "protocol-evidence.md")
	for _, required := range []string{
		"Eligibility requires `mgmt_cfg` to contain exactly one",
		"An accompanying `system_cfg` is still observed",
	} {
		if !strings.Contains(protocol, required) {
			t.Errorf("protocol evidence is missing compatibility boundary %q", required)
		}
	}

	readme := readRepositoryFile(t, "README.md")
	if !strings.Contains(readme, "An observed-symptom case is an already-adopted UPS renamed in Network that remains **Getting Ready**") ||
		!strings.Contains(readme, option+"=true") {
		t.Error("README troubleshooting does not expose the narrow rename recovery option")
	}
	synology := readRepositoryFile(t, "docs", "synology.md")
	if !strings.Contains(synology, "An observed-symptom case is an adopted UPS renamed in Network that remains **Getting Ready**") ||
		!strings.Contains(synology, option+"=true") {
		t.Error("Synology troubleshooting does not expose the narrow rename recovery option")
	}
}

func TestVolatileCfgVersionLiveEfficacyRemainsCandidate(t *testing.T) {
	readme := singleSpaced(readRepositoryFile(t, "README.md"))
	if !strings.Contains(readme, "Whether it clears **Getting Ready** remains **CANDIDATE** until exact-build live acceptance") {
		t.Error("README promotes volatile cfgversion sync beyond exact-build live evidence")
	}

	changelog := singleSpaced(readRepositoryFile(t, "CHANGELOG.md"))
	if !strings.Contains(changelog, "exact-build live efficacy remains **CANDIDATE**") {
		t.Error("changelog promotes volatile cfgversion sync beyond exact-build live evidence")
	}
	if strings.Contains(changelog, "allowing Network to reconcile configuration-only changes") {
		t.Error("changelog still claims unvalidated live reconciliation efficacy")
	}
	synology := singleSpaced(readRepositoryFile(t, "docs", "synology.md"))
	if !strings.Contains(synology, "Whether it clears **Getting Ready** remains **CANDIDATE** until exact-build live acceptance") {
		t.Error("Synology troubleshooting promotes volatile cfgversion sync beyond exact-build live evidence")
	}

	protocol := singleSpaced(readRepositoryFile(t, "docs", "protocol-evidence.md"))
	want := "| Volatile plain-HTTP GCM `cfgversion` synchronization | **CANDIDATE**; explicit default-off compatibility option with automated coverage, pending live rename-recovery acceptance |"
	if !strings.Contains(protocol, want) {
		t.Error("canonical protocol evidence no longer marks volatile cfgversion sync as CANDIDATE")
	}

	configuration := singleSpaced(readRepositoryFile(t, "docs", "configuration.md"))
	if !strings.Contains(configuration, "Whether it clears **Getting Ready** remains **CANDIDATE** until exact-build live acceptance") ||
		!strings.Contains(configuration, "does not establish any Network UI state transition") {
		t.Error("configuration guide promotes volatile cfgversion sync beyond exact-build live evidence")
	}
	for _, overclaim := range []string{
		"default-off escape hatch",
		"before the device leaves **Getting Ready** again",
	} {
		if strings.Contains(configuration, overclaim) {
			t.Errorf("configuration guide retains unvalidated efficacy claim %q", overclaim)
		}
	}

	security := singleSpaced(readRepositoryFile(t, "SECURITY.md"))
	if !strings.Contains(security, "the **CANDIDATE** `N2U_UNIFI_HTTP_GCM_VOLATILE_CFGVERSION_SYNC` interoperability option") ||
		!strings.Contains(security, "it does not establish that Network will clear **Getting Ready**") {
		t.Error("security guidance promotes volatile cfgversion sync beyond exact-build live evidence")
	}
	if strings.Contains(security, "to work around a controller") {
		t.Error("security guidance still presents the CANDIDATE option as an established workaround")
	}

}

func TestVolatileCfgVersionEvidenceSurfacesAreReviewLocked(t *testing.T) {
	// These public files jointly define the CANDIDATE evidence boundary. Lock
	// their exact bytes so every wording change requires an explicit review and
	// digest update instead of relying on an incomplete natural-language parser.
	expected := map[string]string{
		"CHANGELOG.md":                 "f82f8e1127dddd6a0424aa4cabb50bbeea3d39dbf1c5f10bb18c490f44b9c683",
		"README.md":                    "bb59ffc4338a57b0a37c1a203f04ce2dd0595d290044d62e69041d7867975a4c",
		"SECURITY.md":                  "275f4f6e2e850093ca7cd9ee87064d772384a4579f4844b336b4d3de0d6a2e7d",
		"deploy/synology/.env.example": "3ee6debc3bf6cc0cc1e2d28c802b51a8152a06f15980356b591bef0a96862852",
		"docs/configuration.md":        "7e13d83a40e41650e76d282a08c46f0488bc8c968dac197029c0693a00e0d1c8",
		"docs/protocol-evidence.md":    "983cc39d313bef76b49a6440bc7607767a4008c281deaa9a743b63d5e9172ff1",
		"docs/synology.md":             "2d91d86ea1541ff617e5e9793d0042ada733ce6b416ed4b7147710a462b53788",
	}
	for path, want := range expected {
		document := readRepositoryFile(t, strings.Split(path, "/")...)
		got := fmt.Sprintf("%x", sha256.Sum256([]byte(document)))
		if got != want {
			t.Errorf("%s changed outside the reviewed cfgversion evidence snapshot: got %s want %s", path, got, want)
		}
	}
}

func TestSynologyUpdateAndRollbackUseVersionMatchedDeploymentSets(t *testing.T) {
	document := readRepositoryFile(t, "docs", "synology.md")
	update := singleSpaced(markdownSection(t, document, "## Update", "## Roll back"))
	rollback := singleSpaced(markdownSection(t, document, "## Roll back", ""))

	for name, section := range map[string]string{"update": update, "rollback": rollback} {
		for _, required := range []string{
			"`compose.yaml`",
			"`compose.auth.yaml`",
			"digest-pinned `N2U_IMAGE`",
			"same verified versioned release bundle",
			"site-owned `.env`",
			"existing named state volume",
		} {
			if !strings.Contains(section, required) {
				t.Errorf("%s guidance is missing version-matched deployment boundary %q", name, required)
			}
		}
	}

	for _, required := range []string{
		"protected backup directory",
		"separate versioned staging directory",
		"Never pair a new image line with an older `compose.yaml` or `compose.auth.yaml`",
	} {
		if !strings.Contains(update, required) {
			t.Errorf("update guidance is missing staging or backup boundary %q", required)
		}
	}
	for _, required := range []string{
		"Restore the complete protected prior deployment set",
		"Never mix either previous Compose file with a different release's image line",
		"never pass `--volumes`",
	} {
		if !strings.Contains(rollback, required) {
			t.Errorf("rollback guidance is missing restoration boundary %q", required)
		}
	}

	if regexp.MustCompile(`(?m)^docker compose[^\n]*--volumes(?:\s|$)`).MatchString(document) {
		t.Error("Synology guide contains a destructive Compose command with --volumes")
	}
}

func evidenceParagraph(t *testing.T, document, prefix string) string {
	t.Helper()
	start := strings.Index(document, prefix)
	if start < 0 {
		t.Fatalf("protocol evidence is missing paragraph %q", prefix)
	}
	end := strings.Index(document[start:], "\n\n")
	if end < 0 {
		t.Fatalf("protocol evidence paragraph %q has no boundary", prefix)
	}
	return document[start : start+end]
}

func markdownSection(t *testing.T, document, startHeading, endHeading string) string {
	t.Helper()
	start := strings.Index(document, startHeading+"\n")
	if start < 0 {
		t.Fatalf("document is missing section %q", startHeading)
	}
	if endHeading == "" {
		return document[start:]
	}
	end := strings.Index(document[start+len(startHeading):], endHeading+"\n")
	if end < 0 {
		t.Fatalf("section %q has no %q boundary", startHeading, endHeading)
	}
	return document[start : start+len(startHeading)+end]
}

func singleSpaced(value string) string {
	return strings.Join(strings.Fields(value), " ")
}
