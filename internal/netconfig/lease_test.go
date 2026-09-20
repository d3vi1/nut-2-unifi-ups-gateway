package netconfig

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAddressValidation(t *testing.T) {
	for _, tt := range []struct {
		ip     string
		bits   int
		router string
		valid  bool
	}{
		{"192.0.2.30", 24, "192.0.2.1", true},
		{"192.0.2.0", 24, "192.0.2.1", false},
		{"192.0.2.255", 24, "192.0.2.1", false},
		{"192.0.2.30", 24, "192.0.2.255", false},
		{"192.0.2.30", 24, "192.0.3.1", false},
		{"192.0.2.30", 24, "192.0.2.30", false},
		{"192.0.2.30", 31, "192.0.2.31", false},
		{"169.254.254.30", 24, "169.254.254.1", false},
		{"127.0.0.30", 8, "127.0.0.1", false},
		{"0.0.0.30", 8, "0.0.0.1", false},
		{"::ffff:192.0.2.30", 24, "192.0.2.1", false},
	} {
		if (ValidateAddress(tt.ip, tt.bits, tt.router) == nil) != tt.valid {
			t.Fatalf("wrong validation for synthetic address %s", tt.ip)
		}
	}
}

func TestStatusRejectsStaleMalformedAndWritable(t *testing.T) {
	now := time.Now()
	s := Status{Generation: strings.Repeat("a", 32), Sequence: 1, Address: "192.0.2.30", Prefix: 24, Router: "192.0.2.1", ValidUntil: now.Add(2 * time.Second)}
	p := filepath.Join(t.TempDir(), "status.json")
	b, _ := json.Marshal(s)
	if err := os.WriteFile(p, b, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadStatus(p, now); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadStatus(p, now.Add(3*time.Second)); err == nil {
		t.Fatal("expired status accepted")
	}
	if _, err := ReadStatus(p, now.Add(-time.Minute)); err == nil {
		t.Fatal("clock rollback accepted")
	}
	if err := os.Chmod(p, 0666); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadStatus(p, now); err == nil {
		t.Fatal("writable status accepted")
	}
	if err := os.Chmod(p, 0644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(filepath.Dir(p), "link")
	if err := os.Symlink(p, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadStatus(link, now); err == nil {
		t.Fatal("symlink accepted")
	}
	if err := os.WriteFile(p, append(b, b...), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadStatus(p, now); err == nil {
		t.Fatal("trailing status accepted")
	}
}
