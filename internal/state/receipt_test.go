package state

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func testReceipt(t *testing.T) Receipt {
	t.Helper()
	return NewReceipt(strings.Repeat("a", 64), "marker-a", Receipt{}, [16]byte{1})
}

func TestReceiptStorageIsPrivateBoundedAndRoundTrips(t *testing.T) {
	path := filepath.Join(t.TempDir(), "receipt.json")
	r := testReceipt(t)
	for i := 2; i < MaxGCMReplayNonces+5; i++ {
		var nonce [16]byte
		binary.BigEndian.PutUint32(nonce[:4], uint32(i))
		r = NewReceipt(r.Epoch, "marker-b", r, nonce)
	}
	if len(r.Nonces) != MaxGCMReplayNonces {
		t.Fatal("unbounded replay history")
	}
	if err := SaveReceipt(path, r); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadReceipt(path)
	if err != nil || !reflect.DeepEqual(loaded, r) {
		t.Fatal("receipt did not round trip")
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 || info.Size() > maxReceiptBytes {
		t.Fatal("unsafe receipt storage")
	}
	if r.Contains([16]byte{1}) {
		t.Fatal("old nonce not evicted")
	}
}

func TestReceiptReadRejectsUnsafeOrAmbiguousFiles(t *testing.T) {
	dir := t.TempDir()
	valid := filepath.Join(dir, "valid.json")
	if err := SaveReceipt(valid, testReceipt(t)); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(valid)
	if err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string][]byte{
		"duplicate": bytes.Replace(b, []byte(`"schema":1`), []byte(`"schema":1,"schema":1`), 1),
		"case":      bytes.Replace(b, []byte(`"schema"`), []byte(`"Schema"`), 1),
		"unknown":   bytes.Replace(b, []byte(`"schema":1`), []byte(`"schema":1,"unknown":false`), 1),
		"trailing":  append(append([]byte(nil), b...), []byte("{}")...),
		"truncated": b[:len(b)/2], "oversized": bytes.Repeat([]byte(" "), maxReceiptBytes+1),
		"null": []byte("null"), "wrong nonce": bytes.Replace(b, []byte(`"nonces":[`), []byte(`"nonces":["invalid",`), 1),
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(dir, name)
			if err := os.WriteFile(path, body, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadReceipt(path); err == nil {
				t.Fatal("unsafe receipt accepted")
			}
		})
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(valid, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadReceipt(link); err == nil {
		t.Fatal("symlink accepted")
	}
	if err := SaveReceipt(link, testReceipt(t)); err == nil {
		t.Fatal("symlink replaced")
	}
	if err := os.Chmod(valid, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadReceipt(valid); err == nil {
		t.Fatal("public receipt accepted")
	}
	if err := os.Chmod(valid, 0o600); err != nil {
		t.Fatal(err)
	}
	hard := filepath.Join(dir, "hard")
	if err := os.Link(valid, hard); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadReceipt(hard); err == nil {
		t.Fatal("multiply linked receipt accepted")
	}
}

func TestReceiptAtomicFailuresNeverLeavePartialFile(t *testing.T) {
	for _, stage := range []string{"create", "write", "file-sync", "close", "rename", "directory-sync"} {
		t.Run(stage, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "receipt.json")
			old := testReceipt(t)
			if err := SaveReceipt(path, old); err != nil {
				t.Fatal(err)
			}
			next := NewReceipt(old.Epoch, "marker-b", old, [16]byte{2})
			err := saveReceipt(path, next, func(at string) error {
				if at == stage {
					return errors.New("injected private failure")
				}
				return nil
			})
			if err == nil {
				t.Fatal("failed commit reported success")
			}
			loaded, err := LoadReceipt(path)
			if err != nil {
				t.Fatal("partial receipt left behind")
			}
			want := old
			if stage == "directory-sync" {
				want = next
			}
			if !reflect.DeepEqual(loaded, want) {
				t.Fatal("unexpected atomic replacement result")
			}
			entries, _ := os.ReadDir(dir)
			if len(entries) != 1 {
				t.Fatal("temporary file leaked")
			}
		})
	}
}

func TestReceiptEpochChangesWithEveryAuthorityContext(t *testing.T) {
	s, err := LoadOrCreate(filepath.Join(t.TempDir(), "state.json"), "", "", "http://192.0.2.1:8080/inform", testKey)
	if err != nil {
		t.Fatal(err)
	}
	s.Adoption.Adopted = true
	s.Adoption.UseAESGCM = true
	epoch, err := ReceiptEpoch(s, "USWDA26")
	if err != nil {
		t.Fatal(err)
	}
	mutations := []func(*State){
		func(s *State) { s.Identity.MAC = "02:00:00:00:00:02" }, func(s *State) { s.Identity.Serial += "2" },
		func(s *State) { s.Identity.GUID = "00000000-0000-4000-8000-000000000000" },
		func(s *State) { s.Adoption.AuthKey = "ffeeddccbbaa99887766554433221100" },
		func(s *State) { s.Adoption.InformURL = "http://192.0.2.2:8080/inform" },
		func(s *State) { s.Adoption.CfgVersion = "next" }, func(s *State) { s.Adoption.UseAESGCM = false }, func(s *State) { s.Adoption.Adopted = false },
	}
	for _, mutate := range mutations {
		next := s
		mutate(&next)
		got, err := ReceiptEpoch(next, "USWDA26")
		if err == nil && got == epoch {
			t.Fatal("receipt survived changed adoption context")
		}
	}
	other, err := ReceiptEpoch(s, "USPDA2C")
	if err != nil || other == epoch {
		t.Fatal("carrier not bound")
	}
	r := testReceipt(t)
	r.Epoch = epoch
	b, _ := json.Marshal(r)
	if bytes.Contains(b, []byte(s.Adoption.AuthKey)) || bytes.Contains(b, []byte(s.Adoption.InformURL)) {
		t.Fatal("receipt contains adoption secrets")
	}
}
