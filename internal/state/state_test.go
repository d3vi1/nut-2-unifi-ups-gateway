package state

import (
	"os"
	"path/filepath"
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
	if a != b {
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
