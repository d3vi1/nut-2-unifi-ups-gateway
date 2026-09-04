package buildtest

import (
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
