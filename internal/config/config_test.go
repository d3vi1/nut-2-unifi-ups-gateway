package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadDefaults(t *testing.T) {
	clearEnvironment(t)
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.NUT.Address != "127.0.0.1:3493" || c.NUT.UPSName != "ups" {
		t.Fatalf("unexpected NUT defaults: %+v", c.NUT)
	}
	if c.UniFi.InformURL != "http://unifi:8080/inform" {
		t.Fatalf("unexpected inform URL %q", c.UniFi.InformURL)
	}
	if c.UniFi.Model != "USWDA26" {
		t.Fatalf("unexpected default model %q", c.UniFi.Model)
	}
	if c.Runtime.HealthAddress != "127.0.0.1:9199" {
		t.Fatalf("unexpected health default %q", c.Runtime.HealthAddress)
	}
}

func TestRejectsUnknownModel(t *testing.T) {
	clearEnvironment(t)
	t.Setenv("N2U_UNIFI_MODEL", "USP-IMAGINARY")
	if _, err := Load(); err == nil {
		t.Fatal("expected unknown model to fail")
	}
}

func TestSecretFile(t *testing.T) {
	clearEnvironment(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "nut-password")
	if err := os.WriteFile(path, []byte("correct horse\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("N2U_NUT_USERNAME", "monitor")
	t.Setenv("N2U_NUT_PASSWORD_FILE", path)
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.NUT.Password != "correct horse" {
		t.Fatal("secret file was not loaded exactly")
	}
}

func TestRejectsAmbiguousSecret(t *testing.T) {
	clearEnvironment(t)
	t.Setenv("N2U_NUT_PASSWORD", "one")
	t.Setenv("N2U_NUT_PASSWORD_FILE", "/does/not/matter")
	if _, err := Load(); err == nil {
		t.Fatal("expected ambiguous secret to fail")
	}
}

func TestSecretFileIsBoundedAndDoesNotFollowSymlinks(t *testing.T) {
	clearEnvironment(t)
	dir := t.TempDir()
	oversized := filepath.Join(dir, "oversized")
	if err := os.WriteFile(oversized, make([]byte, maxSecretBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("N2U_NUT_USERNAME", "monitor")
	t.Setenv("N2U_NUT_PASSWORD_FILE", oversized)
	if _, err := Load(); err == nil {
		t.Fatal("oversized secret file was accepted")
	}

	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(dir, "symlink")
	if err := os.Symlink(target, symlink); err != nil {
		t.Fatal(err)
	}
	t.Setenv("N2U_NUT_PASSWORD_FILE", symlink)
	if _, err := Load(); err == nil {
		t.Fatal("symlinked secret file was accepted")
	}
}

func TestRejectsRemotePlaintextNUTByDefault(t *testing.T) {
	clearEnvironment(t)
	t.Setenv("N2U_NUT_ADDRESS", "192.0.2.10:3493")
	if _, err := Load(); err == nil {
		t.Fatal("expected remote plaintext NUT rejection")
	}
	t.Setenv("N2U_NUT_ALLOW_INSECURE_REMOTE", "true")
	if _, err := Load(); err != nil {
		t.Fatalf("explicit remote plaintext acknowledgement failed: %v", err)
	}
}

func TestRejectsUnknownEnvironment(t *testing.T) {
	clearEnvironment(t)
	t.Setenv("N2U_ZONE1_OFF_COMAND", "typo")
	if _, err := Load(); err == nil {
		t.Fatal("expected unknown environment variable rejection")
	}
}

func TestRejectsUnverifiedFirmwareVersion(t *testing.T) {
	clearEnvironment(t)
	t.Setenv("N2U_UNIFI_VERSION", "1.6.2")
	if _, err := Load(); err == nil {
		t.Fatal("expected unverified firmware profile to fail")
	}
}

func TestValidateRejectsUnsafeRuntimeDurations(t *testing.T) {
	clearEnvironment(t)
	configuration, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{name: "zero inform interval", mutate: func(c *Config) { c.UniFi.InformInterval = 0 }},
		{name: "long inform interval", mutate: func(c *Config) { c.UniFi.InformInterval = 10*time.Minute + time.Second }},
		{name: "zero discovery interval", mutate: func(c *Config) { c.UniFi.DiscoveryInterval = 0 }},
		{name: "zero poll interval", mutate: func(c *Config) { c.Runtime.PollInterval = 0 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := configuration
			test.mutate(&candidate)
			if err := candidate.Validate(); err == nil {
				t.Fatal("expected invalid duration to be rejected")
			}
		})
	}
}

func clearEnvironment(t *testing.T) {
	t.Helper()
	for _, entry := range os.Environ() {
		name, _, _ := stringsCut(entry, '=')
		if len(name) >= len(envPrefix) && name[:len(envPrefix)] == envPrefix {
			t.Setenv(name, "")
			if err := os.Unsetenv(name); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func stringsCut(s string, sep byte) (string, string, bool) {
	for i := range s {
		if s[i] == sep {
			return s[:i], s[i+1:], true
		}
	}
	return s, "", false
}
