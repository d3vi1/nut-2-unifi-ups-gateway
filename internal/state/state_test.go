package state

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

const testKey = "ba86f2bbe107c7c57eb5f2690775c712"

func TestLoadOrCreateIsStableAndPrivate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "state.json")
	a, err := LoadOrCreate(path, "", "", "http://unifi:8080/inform", testKey)
	if err != nil {
		t.Fatal(err)
	}
	b, err := LoadOrCreate(path, "", "", "http://unifi:8080/inform", testKey)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a, b) {
		t.Fatal("persistent state changed across load")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("state mode = %o, want 600", info.Mode().Perm())
	}
}

func TestExplicitIdentityMismatchFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if _, err := LoadOrCreate(path, "02:00:00:00:00:01", "SERIAL1", "http://unifi:8080/inform", testKey); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreate(path, "02:00:00:00:00:02", "SERIAL1", "http://unifi:8080/inform", testKey); err == nil {
		t.Fatal("expected identity mismatch")
	}
}

func TestPendingURLFollowsConfigurationButManagedURLWins(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	pending, err := LoadOrCreate(path, "", "", "http://unifi:8080/inform", testKey)
	if err != nil {
		t.Fatal(err)
	}
	pending, err = LoadOrCreate(path, "", "", "http://192.0.2.10:8080/inform", testKey)
	if err != nil {
		t.Fatal(err)
	}
	if pending.Adoption.InformURL != "http://192.0.2.10:8080/inform" {
		t.Fatalf("pending inform URL was not repaired: %+v", pending.Adoption)
	}
	pending.Adoption.Adopted = true
	pending.Adoption.AuthKey = "00112233445566778899aabbccddeeff"
	if err := Save(path, pending); err != nil {
		t.Fatal(err)
	}
	managed, err := LoadOrCreate(path, "", "", "http://192.0.2.99:8080/inform", testKey)
	if err != nil {
		t.Fatal(err)
	}
	if managed.Adoption.InformURL != "http://192.0.2.10:8080/inform" {
		t.Fatalf("managed inform URL was overwritten by configuration: %+v", managed.Adoption)
	}
}

func TestValidateRejectsMulticastMAC(t *testing.T) {
	s := State{
		Version:  currentVersion,
		Identity: Identity{MAC: "01:00:00:00:00:01", Serial: "x", GUID: "x"},
		Adoption: Adoption{AuthKey: testKey, InformURL: "http://unifi:8080/inform", CfgVersion: "0"},
	}
	if err := s.Validate(); err == nil {
		t.Fatal("expected multicast MAC to fail")
	}
}

func TestLoadRejectsUnsafeFilesystemObjects(t *testing.T) {
	dir := t.TempDir()
	valid := filepath.Join(dir, "valid.json")
	if _, err := LoadOrCreate(valid, "", "", "http://unifi:8080/inform", testKey); err != nil {
		t.Fatal(err)
	}

	t.Run("permissive mode", func(t *testing.T) {
		if err := os.Chmod(valid, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadOrCreate(valid, "", "", "http://unifi:8080/inform", testKey); err == nil {
			t.Fatal("expected permissive state file rejection")
		}
		if err := os.Chmod(valid, 0o600); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("symlink", func(t *testing.T) {
		link := filepath.Join(dir, "linked.json")
		if err := os.Symlink(valid, link); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadOrCreate(link, "", "", "http://unifi:8080/inform", testKey); err == nil {
			t.Fatal("expected symlink rejection")
		}
	})
}

func TestLoadRejectsUnknownAndTrailingJSON(t *testing.T) {
	for name, body := range map[string]string{
		"unknown":  `{"version":1,"identity":{},"adoption":{},"extra":true}`,
		"trailing": `{"version":1} {"version":1}`,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "state.json")
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadOrCreate(path, "", "", "http://unifi:8080/inform", testKey); err == nil {
				t.Fatal("expected strict state decode failure")
			}
		})
	}
}

func TestLegacyVersionOneStateWithoutReplayWindowLoads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	legacy := []byte(`{
  "version": 1,
  "identity": {
    "mac": "02:00:00:00:00:01",
    "serial": "LEGACY1",
    "guid": "00000000-0000-4000-8000-000000000001"
  },
  "adoption": {
    "auth_key": "00112233445566778899aabbccddeeff",
    "inform_url": "http://unifi:8080/inform",
    "cfg_version": "legacy",
    "adopted": true,
    "use_aes_gcm": true
  }
}`)
	if err := os.WriteFile(path, legacy, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadOrCreate(path, "", "", "http://ignored:8080/inform", testKey)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Adoption.GCMReplayNonces) != 0 || !loaded.Adoption.UseAESGCM {
		t.Fatalf("legacy replay state changed on load: %+v", loaded.Adoption)
	}
}

func TestValidateBoundsAndChecksGCMReplayWindow(t *testing.T) {
	base := State{
		Version: currentVersion,
		Identity: Identity{
			MAC: "02:00:00:00:00:01", Serial: "REPLAY1",
			GUID: "00000000-0000-4000-8000-000000000001",
		},
		Adoption: Adoption{
			AuthKey: "00112233445566778899aabbccddeeff", InformURL: "http://unifi:8080/inform",
			CfgVersion: "1", Adopted: true, UseAESGCM: true,
		},
	}
	for index := 0; index < MaxGCMReplayNonces; index++ {
		base.Adoption.GCMReplayNonces = append(base.Adoption.GCMReplayNonces, fmt.Sprintf("%032x", index+1))
	}
	if err := base.Validate(); err != nil {
		t.Fatalf("maximum replay window rejected: %v", err)
	}

	tests := map[string]func(State) State{
		"too many": func(s State) State {
			s.Adoption.GCMReplayNonces = append(s.Adoption.GCMReplayNonces, fmt.Sprintf("%032x", MaxGCMReplayNonces+1))
			return s
		},
		"malformed": func(s State) State {
			s.Adoption.GCMReplayNonces = []string{"not-a-nonce"}
			return s
		},
		"duplicate": func(s State) State {
			s.Adoption.GCMReplayNonces = []string{fmt.Sprintf("%032x", 10), fmt.Sprintf("%032X", 10)}
			return s
		},
		"CBC window": func(s State) State {
			s.Adoption.UseAESGCM = false
			s.Adoption.GCMReplayNonces = []string{fmt.Sprintf("%032x", 1)}
			return s
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := base
			candidate.Adoption.GCMReplayNonces = append([]string(nil), base.Adoption.GCMReplayNonces...)
			if err := mutate(candidate).Validate(); err == nil {
				t.Fatal("invalid replay window accepted")
			}
		})
	}
}
