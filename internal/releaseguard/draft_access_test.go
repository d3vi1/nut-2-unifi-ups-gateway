package releaseguard

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadOnlyPreflightDoesNotClaimDraftAbsence(t *testing.T) {
	environment := validEnvironment()
	output := filepath.Join(t.TempDir(), "outputs")
	if err := os.WriteFile(output, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	environment["GITHUB_OUTPUT"] = output
	release := loadTestContext(t, environment)
	guard, fake, closeServer := startFake(t, release, func(fake *fakeGitHub) {
		fake.release = &fakeReleaseState{id: 77, tag: release.Tag, draft: true}
	})
	defer closeServer()
	if err := guard.Trust(t.Context(), release); err != nil {
		t.Fatal(err)
	}
	if fake.releaseListReads != 0 || len(fake.releasePaths) != 0 {
		t.Fatal("read-only preflight attempted private-draft inspection")
	}
	if err := guard.Reserve(t.Context(), release); err == nil {
		t.Fatal("existing draft was not caught by writer pre-reservation check")
	}
	if fake.releaseListReads != 1 || fake.tagExists || fake.release.id != 77 {
		t.Fatal("private draft absence was not verified before tag mutation")
	}
}

func TestReservationReadFailureIsClassifiedWithoutSecrets(t *testing.T) {
	for _, code := range []int{http.StatusForbidden, http.StatusNotFound, http.StatusInternalServerError} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			environment := validEnvironment()
			output := filepath.Join(t.TempDir(), "outputs")
			if err := os.WriteFile(output, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			environment["GITHUB_OUTPUT"] = output
			release := loadTestContext(t, environment)
			guard, fake, closeServer := startFake(t, release, func(fake *fakeGitHub) { fake.numericReadStatus = code })
			defer closeServer()
			err := guard.Reserve(t.Context(), release)
			if err == nil || !strings.Contains(err.Error(), "readback failed") || !strings.Contains(err.Error(), fmt.Sprintf("HTTP %d", code)) {
				t.Fatalf("missing safe read failure classification: %v", err)
			}
			for _, forbidden := range []string{release.token, release.policyToken, "response-body-must-not-leak", "reserved release changed"} {
				if strings.Contains(err.Error(), forbidden) {
					t.Fatal("read error exposes private data or incorrectly claims mutation")
				}
			}
			data, readErr := os.ReadFile(output)
			if readErr != nil || len(data) != 0 || !fake.tagExists || fake.release == nil || !fake.release.draft || fake.releasePatchCount != 0 {
				t.Fatal("ambiguous reservation exported outputs or mutated beyond creation")
			}
		})
	}
}

func TestImageSourceNeedsNoDraftButBindingStillFailsClosed(t *testing.T) {
	for _, scenario := range []string{"deleted", "changed", "forbidden", "not-found"} {
		t.Run(scenario, func(t *testing.T) {
			environment, release, guard, fake, closeServer := setupReservedRelease(t)
			defer closeServer()
			fake.mu.Lock()
			switch scenario {
			case "deleted":
				fake.release = nil
			case "changed":
				fake.release.body += "unexpected edit"
			case "forbidden":
				fake.numericReadStatus = http.StatusForbidden
			case "not-found":
				fake.numericReadStatus = http.StatusNotFound
			}
			fake.releasePaths = nil
			fake.releaseListReads = 0
			fake.mu.Unlock()
			if err := guard.VerifyImageSource(context.Background(), release); err != nil {
				t.Fatal(err)
			}
			if len(fake.releasePaths) != 0 || fake.releaseListReads != 0 {
				t.Fatal("image-source gate attempted private-draft access")
			}
			if err := guard.Bind(t.Context(), release, mapLookup(environment)); err == nil {
				t.Fatal("unsafe draft was accepted for image binding")
			}
			if fake.releasePatchCount != 0 {
				t.Fatal("binding wrote before checking the exact draft")
			}
		})
	}
}
