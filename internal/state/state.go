// Package state persists the emulator identity and UniFi adoption material.
// The file contains a controller auth key and must be treated as a secret.
package state

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/d3vi1/nut-2-unifi-ups-gateway/internal/diagnostic"
)

const currentVersion = 1
const maxStateBytes = 1 << 20

// MaxGCMReplayNonces bounds both the persisted and in-memory replay window.
// Nonces are scoped to the auth-key/mode epoch represented by Adoption.
const MaxGCMReplayNonces = 128

type State struct {
	Version  int      `json:"version"`
	Identity Identity `json:"identity"`
	Adoption Adoption `json:"adoption"`
}

type Identity struct {
	MAC    string `json:"mac"`
	Serial string `json:"serial"`
	// GUID is a stable per-instance identity seed retained in state version 1.
	// Device profiles may emit a separate firmware-defined board GUID on wire.
	GUID string `json:"guid"`
}

type Adoption struct {
	AuthKey         string   `json:"auth_key"`
	InformURL       string   `json:"inform_url"`
	CfgVersion      string   `json:"cfg_version"`
	Adopted         bool     `json:"adopted"`
	UseAESGCM       bool     `json:"use_aes_gcm"`
	GCMReplayNonces []string `json:"gcm_replay_nonces,omitempty"`
}

// LoadOrCreate loads path or initializes it with a random locally-administered
// unicast identity. Explicit identity values are honored only at creation; a
// mismatch against existing state fails rather than silently changing identity.
func LoadOrCreate(path, requestedMAC, requestedSerial, informURL, defaultKey string) (result State, resultErr error) {
	defer func() { resultErr = diagnostic.Fallback(diagnostic.StateInvalid, resultErr) }()
	info, err := os.Lstat(path)
	if err == nil {
		if !info.Mode().IsRegular() {
			return State{}, errors.New("state path must be a regular file")
		}
		f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
		if err != nil {
			code := diagnostic.StateRead
			if errors.Is(err, os.ErrPermission) {
				code = diagnostic.StatePermissions
			}
			return State{}, diagnostic.Wrap(code, errors.New("open state safely"))
		}
		defer f.Close()
		openedInfo, err := f.Stat()
		if err != nil || !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) {
			return State{}, errors.New("state file changed while opening")
		}
		if openedInfo.Mode().Perm()&0o077 != 0 {
			return State{}, diagnostic.Wrap(diagnostic.StatePermissions, errors.New("state file must not be accessible by group or others"))
		}
		if openedInfo.Size() < 1 || openedInfo.Size() > maxStateBytes {
			return State{}, errors.New("state file has invalid size")
		}
		var s State
		dec := json.NewDecoder(io.LimitReader(f, maxStateBytes+1))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&s); err != nil {
			return State{}, fmt.Errorf("decode state: %w", err)
		}
		if err := requireJSONEOF(dec); err != nil {
			return State{}, err
		}
		if err := s.Validate(); err != nil {
			return State{}, fmt.Errorf("validate state: %w", err)
		}
		if requestedMAC != "" && !strings.EqualFold(normalizeMAC(requestedMAC), s.Identity.MAC) {
			return State{}, diagnostic.Wrap(diagnostic.IdentityMismatch, errors.New("configured device MAC does not match persistent state"))
		}
		if requestedSerial != "" && requestedSerial != s.Identity.Serial {
			return State{}, diagnostic.Wrap(diagnostic.IdentityMismatch, errors.New("configured device serial does not match persistent state"))
		}
		// A failed first startup may have persisted the firmware-default
		// hostname before it could be resolved. While still pending on the
		// public default key, the operator's configured origin remains
		// authoritative. Once managed, the negotiated state always wins.
		if !s.Adoption.Adopted && strings.EqualFold(s.Adoption.AuthKey, defaultKey) && s.Adoption.InformURL != informURL {
			s.Adoption.InformURL = informURL
			if err := s.Validate(); err != nil {
				return State{}, fmt.Errorf("validate configured pending state: %w", err)
			}
			if err := Save(path, s); err != nil {
				return State{}, fmt.Errorf("update pending state: %w", err)
			}
		}
		return s, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		code := diagnostic.StateRead
		if errors.Is(err, os.ErrPermission) {
			code = diagnostic.StatePermissions
		}
		return State{}, diagnostic.Wrap(code, errors.New("open state safely"))
	}

	mac := requestedMAC
	if mac == "" {
		mac, err = randomMAC()
		if err != nil {
			return State{}, err
		}
	} else {
		mac = normalizeMAC(mac)
	}
	serial := requestedSerial
	if serial == "" {
		serial = strings.ToUpper(strings.ReplaceAll(mac, ":", ""))
	}
	guid, err := randomUUID()
	if err != nil {
		return State{}, err
	}
	s := State{
		Version:  currentVersion,
		Identity: Identity{MAC: mac, Serial: serial, GUID: guid},
		Adoption: Adoption{
			AuthKey: defaultKey, InformURL: informURL, CfgVersion: "0",
		},
	}
	if err := s.Validate(); err != nil {
		return State{}, err
	}
	if err := Save(path, s); err != nil {
		return State{}, err
	}
	return s, nil
}

func (s State) Validate() error {
	if s.Version != currentVersion {
		return fmt.Errorf("unsupported state version %d", s.Version)
	}
	hw, err := net.ParseMAC(s.Identity.MAC)
	if err != nil || len(hw) != 6 || hw[0]&1 != 0 {
		return errors.New("invalid identity MAC")
	}
	if s.Identity.Serial == "" || s.Identity.GUID == "" {
		return errors.New("incomplete identity")
	}
	if !safeText(s.Identity.Serial, 128) || !validUUID(s.Identity.GUID) {
		return errors.New("invalid identity metadata")
	}
	key, err := hex.DecodeString(s.Adoption.AuthKey)
	if err != nil || len(key) != 16 {
		return errors.New("invalid adoption key")
	}
	if !validInformURL(s.Adoption.InformURL) || !safeText(s.Adoption.CfgVersion, 128) {
		return errors.New("incomplete adoption state")
	}
	if !s.Adoption.Adopted && s.Adoption.UseAESGCM {
		return errors.New("pending adoption state cannot use AES-GCM")
	}
	if len(s.Adoption.GCMReplayNonces) > MaxGCMReplayNonces {
		return errors.New("GCM replay window exceeds limit")
	}
	if !s.Adoption.UseAESGCM && len(s.Adoption.GCMReplayNonces) != 0 {
		return errors.New("GCM replay window requires AES-GCM")
	}
	seenNonces := make(map[[16]byte]struct{}, len(s.Adoption.GCMReplayNonces))
	for _, encodedNonce := range s.Adoption.GCMReplayNonces {
		if len(encodedNonce) != 32 {
			return errors.New("invalid GCM replay window entry")
		}
		decodedNonce, err := hex.DecodeString(encodedNonce)
		if err != nil || len(decodedNonce) != 16 {
			return errors.New("invalid GCM replay window entry")
		}
		var nonce [16]byte
		copy(nonce[:], decodedNonce)
		if _, duplicate := seenNonces[nonce]; duplicate {
			return errors.New("duplicate GCM replay window entry")
		}
		seenNonces[nonce] = struct{}{}
	}
	return nil
}

// Save writes state atomically with owner-only permissions and syncs both file
// and containing directory before returning.
func Save(path string, s State) error {
	if err := s.Validate(); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("encode state: %w", err)
	}
	b = append(b, '\n')
	return diagnostic.Wrap(diagnostic.StateWrite, savePrivateBytes(path, b, nil))
}

// savePrivateBytes is shared by adoption state and the independent receipt.
// checkpoint is an internal fault-injection seam; production callers pass nil.
func savePrivateBytes(path string, b []byte, checkpoint func(string) error) error {
	check := func(stage string) error {
		if checkpoint != nil {
			return checkpoint(stage)
		}
		return nil
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return errors.New("create private state directory")
	}
	if err := check("create"); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".state-*")
	if err != nil {
		return fmt.Errorf("create temporary state: %w", err)
	}
	defer f.Close()
	tmp := f.Name()
	keep := false
	defer func() {
		_ = f.Close()
		if !keep {
			_ = os.Remove(tmp)
		}
	}()
	if err := f.Chmod(0o600); err != nil {
		return fmt.Errorf("protect temporary state: %w", err)
	}
	if err := check("write"); err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		return fmt.Errorf("write temporary state: %w", err)
	}
	if err := check("file-sync"); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("sync temporary state: %w", err)
	}
	if err := check("close"); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close temporary state: %w", err)
	}
	if err := check("rename"); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("replace state: %w", err)
	}
	keep = true
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("protect state: %w", err)
	}
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open state directory: %w", err)
	}
	defer d.Close()
	if err := check("directory-sync"); err != nil {
		return err
	}
	if err := d.Sync(); err != nil {
		return fmt.Errorf("sync state directory: %w", err)
	}
	return nil
}

func randomMAC() (string, error) {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate MAC: %w", err)
	}
	b[0] = (b[0] | 0x02) & 0xfe
	return net.HardwareAddr(b).String(), nil
}

func normalizeMAC(v string) string {
	hw, err := net.ParseMAC(v)
	if err != nil {
		return v
	}
	return strings.ToLower(hw.String())
}

func randomUUID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate GUID: %w", err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

func requireJSONEOF(dec *json.Decoder) error {
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("state file contains trailing data")
	}
	return nil
}

func safeText(value string, max int) bool {
	if value == "" || len(value) > max {
		return false
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func validUUID(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return false
	}
	hexText := strings.ReplaceAll(value, "-", "")
	decoded, err := hex.DecodeString(hexText)
	return err == nil && len(decoded) == 16
}

func validInformURL(value string) bool {
	u, err := url.Parse(value)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return false
	}
	return u.Path == "/inform"
}
