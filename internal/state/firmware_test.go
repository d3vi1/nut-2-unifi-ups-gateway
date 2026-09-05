package state

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestFirmwareReceiptPrivateStorageAndFailures(t *testing.T) {
	r := NewFirmwareReceipt(strings.Repeat("a", 64), "1.6.4.432", FirmwareReceipt{}, [16]byte{1})
	for i := 2; i < 140; i++ {
		var nonce [16]byte
		binary.BigEndian.PutUint32(nonce[:4], uint32(i))
		r = NewFirmwareReceipt(r.Epoch, r.Version, r, nonce)
	}
	if len(r.Nonces) != MaxGCMReplayNonces || r.Contains([16]byte{1}) {
		t.Fatal("unbounded nonces")
	}
	path := filepath.Join(t.TempDir(), "firmware.json")
	if err := SaveFirmwareReceipt(path, r); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadFirmwareReceipt(path)
	if err != nil || !reflect.DeepEqual(loaded, r) {
		t.Fatal("round trip")
	}
	b, _ := os.ReadFile(path)
	if bytes.Contains(b, []byte("cfgversion")) {
		t.Fatal("schema conflates config and firmware")
	}
	for name, body := range map[string][]byte{
		"duplicate": bytes.Replace(b, []byte(`"version":"1.6.4.432"`), []byte(`"version":"1.6.4.432","version":"1.4.12"`), 1),
		"case":      bytes.Replace(b, []byte(`"version"`), []byte(`"Version"`), 1),
		"unknown":   bytes.Replace(b, []byte(`"schema":1`), []byte(`"schema":1,"url":"private"`), 1),
		"invalid":   bytes.Replace(b, []byte("1.6.4.432"), []byte("01.6.4.432"), 1),
		"oversized": bytes.Repeat([]byte(" "), maxReceiptBytes+1),
	} {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "bad")
			if os.WriteFile(p, body, 0600) != nil {
				t.Fatal("write")
			}
			if _, err := LoadFirmwareReceipt(p); err == nil {
				t.Fatal("invalid file accepted")
			}
		})
	}
	for _, stage := range []string{"create", "write", "file-sync", "close", "rename", "directory-sync"} {
		t.Run(stage, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "receipt")
			if SaveFirmwareReceipt(p, r) != nil {
				t.Fatal("seed")
			}
			next := NewFirmwareReceipt(r.Epoch, "1.4.12", r, [16]byte{200})
			err := savePrivateReceipt(p, next, func(at string) error {
				if at == stage {
					return errors.New("injected")
				}
				return nil
			})
			if err == nil {
				t.Fatal("fault accepted")
			}
			got, err := LoadFirmwareReceipt(p)
			if err != nil {
				t.Fatal("partial file")
			}
			want := r
			if stage == "directory-sync" {
				want = next
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatal("atomic boundary violated")
			}
		})
	}
	link := filepath.Join(t.TempDir(), "link")
	if os.Symlink(path, link) != nil {
		t.Fatal("link")
	}
	if _, err := LoadFirmwareReceipt(link); err == nil {
		t.Fatal("symlink accepted")
	}
	if SaveFirmwareReceipt(link, r) == nil {
		t.Fatal("symlink replaced")
	}
	if os.Chmod(path, 0644) != nil {
		t.Fatal("chmod")
	}
	if _, err := LoadFirmwareReceipt(path); err == nil {
		t.Fatal("public cache accepted")
	}
}

func TestFirmwareEpochAuthorityAndSourceNotReportedMarkers(t *testing.T) {
	// Existing generated adoption fixture is initialized independently of receipts.
	s, err := LoadOrCreate(filepath.Join(t.TempDir(), "state.json"), "", "", "http://192.0.2.1:8080/inform", "00112233445566778899aabbccddeeff")
	if err != nil {
		t.Fatal(err)
	}
	s.Adoption.Adopted = true
	s.Adoption.UseAESGCM = true
	a, err := FirmwareEpoch(s, "USWDA26", "source-build")
	if err != nil {
		t.Fatal(err)
	}
	s.Adoption.CfgVersion = "another-configuration"
	b, err := FirmwareEpoch(s, "USWDA26", "source-build")
	if err != nil || a != b {
		t.Fatal("config receipt invalidates firmware")
	}
	for _, change := range []func(*State){func(s *State) { s.Adoption.AuthKey = "ffeeddccbbaa99887766554433221100" }, func(s *State) { s.Adoption.InformURL = "http://192.0.2.2:8080/inform" }, func(s *State) { s.Identity.Serial += "x" }} {
		next := s
		change(&next)
		b, err := FirmwareEpoch(next, "USWDA26", "source-build")
		if err == nil && b == a {
			t.Fatal("authority epoch collision")
		}
	}
	for _, pair := range [][2]string{{"USPDA2C", "source-build"}, {"USWDA26", "another-source-build"}} {
		b, err := FirmwareEpoch(s, pair[0], pair[1])
		if err != nil || b == a {
			t.Fatal("profile epoch collision")
		}
	}
	s.Adoption.UseAESGCM = false
	if _, err := FirmwareEpoch(s, "USWDA26", "source-build"); err == nil {
		t.Fatal("CBC context accepted")
	}
}
