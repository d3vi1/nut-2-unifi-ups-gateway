package state

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const receiptSchema = 1
const maxReceiptBytes = 16 << 10

// Receipt contains no controller configuration, credentials, or authority to
// mutate adoption state. Its independent format keeps state v1 rollback-safe.
type Receipt struct {
	Schema     int      `json:"schema"`
	Epoch      string   `json:"epoch"`
	CfgVersion string   `json:"cfgversion"`
	Nonces     []string `json:"nonces"`
}

func (r Receipt) String() string {
	return fmt.Sprintf("configuration receipt replay_entries=%d", len(r.Nonces))
}
func (r Receipt) GoString() string { return r.String() }

func ReceiptPath(statePath string) string {
	return filepath.Join(filepath.Dir(statePath), "controller-receipt.json")
}

// ReceiptEpoch binds the cache to the existing locally trusted adoption and
// projection policy. The opaque binding contains no second copy of its key.
func ReceiptEpoch(s State, carrier string) (string, error) {
	if err := s.Validate(); err != nil {
		return "", errors.New("invalid receipt adoption context")
	}
	if !s.Adoption.Adopted || !s.Adoption.UseAESGCM {
		return "", errors.New("receipt requires managed GCM context")
	}
	key, err := hex.DecodeString(s.Adoption.AuthKey)
	if err != nil {
		return "", errors.New("invalid receipt adoption context")
	}
	defer clear(key)
	// JSON array encoding makes every field unambiguous, including separators.
	context, _ := json.Marshal([]string{"n2u-config-receipt-v1", s.Identity.MAC, s.Identity.Serial, s.Identity.GUID, s.Adoption.InformURL, "gcm", s.Adoption.CfgVersion, carrier})
	digest := hmac.New(sha256.New, key)
	_, _ = digest.Write(context)
	return hex.EncodeToString(digest.Sum(nil)), nil
}

func NewReceipt(epoch, version string, previous Receipt, nonce [16]byte) Receipt {
	r := Receipt{Schema: receiptSchema, Epoch: epoch, CfgVersion: version, Nonces: make([]string, 0, MaxGCMReplayNonces)}
	if previous.Epoch == epoch {
		r.Nonces = append(r.Nonces, previous.Nonces...)
	}
	if len(r.Nonces) == MaxGCMReplayNonces {
		r.Nonces = append([]string(nil), r.Nonces[1:]...)
	}
	r.Nonces = append(r.Nonces, hex.EncodeToString(nonce[:]))
	return r
}

func (r Receipt) Contains(nonce [16]byte) bool {
	want := hex.EncodeToString(nonce[:])
	for _, existing := range r.Nonces {
		if existing == want {
			return true
		}
	}
	return false
}

func (r Receipt) Validate() error {
	bad := errors.New("invalid configuration receipt")
	if r.Schema != receiptSchema || !safeText(r.CfgVersion, 128) || len(r.Epoch) != 64 || len(r.Nonces) == 0 || len(r.Nonces) > MaxGCMReplayNonces {
		return bad
	}
	if _, err := hex.DecodeString(r.Epoch); err != nil || r.Epoch != strings.ToLower(r.Epoch) {
		return bad
	}
	for _, b := range []byte(r.CfgVersion) {
		if b < 0x20 || b > 0x7e {
			return bad
		}
	}
	seen := make(map[string]bool, len(r.Nonces))
	for _, n := range r.Nonces {
		if len(n) != 32 || n != strings.ToLower(n) || seen[n] {
			return bad
		}
		if _, err := hex.DecodeString(n); err != nil {
			return bad
		}
		seen[n] = true
	}
	return nil
}

func privateReceiptInfo(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && info.Mode().IsRegular() && info.Mode().Perm() == 0o600 && stat.Uid == uint32(os.Geteuid()) && stat.Nlink == 1
}

// LoadReceipt returns os.ErrNotExist for an absent cache. Other read errors are
// deliberately identity-free. A caller must separately compare its epoch.
func LoadReceipt(path string) (Receipt, error) {
	bad := errors.New("cannot read private configuration receipt")
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return Receipt{}, os.ErrNotExist
	}
	if err != nil || !privateReceiptInfo(info) || info.Size() < 1 || info.Size() > maxReceiptBytes {
		return Receipt{}, bad
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
	if err != nil {
		return Receipt{}, bad
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !privateReceiptInfo(opened) || !os.SameFile(info, opened) {
		return Receipt{}, bad
	}
	b, err := io.ReadAll(io.LimitReader(f, maxReceiptBytes+1))
	if err != nil || len(b) > maxReceiptBytes {
		return Receipt{}, bad
	}
	// Decode exact field names and reject duplicates in one bounded pass. Go's
	// usual struct decoder accepts case aliases and duplicate last-wins values.
	dec := json.NewDecoder(bytes.NewReader(b))
	opening, err := dec.Token()
	if err != nil || opening != json.Delim('{') {
		return Receipt{}, bad
	}
	seen := map[string]bool{}
	var r Receipt
	for dec.More() {
		tok, err := dec.Token()
		name, ok := tok.(string)
		if err != nil || !ok || seen[name] {
			return Receipt{}, bad
		}
		seen[name] = true
		switch name {
		case "schema":
			err = dec.Decode(&r.Schema)
		case "epoch":
			err = dec.Decode(&r.Epoch)
		case "cfgversion":
			err = dec.Decode(&r.CfgVersion)
		case "nonces":
			err = dec.Decode(&r.Nonces)
		default:
			return Receipt{}, bad
		}
		if err != nil {
			return Receipt{}, bad
		}
	}
	closing, err := dec.Token()
	if err != nil || closing != json.Delim('}') || len(seen) != 4 {
		return Receipt{}, bad
	}
	if err := requireJSONEOF(dec); err != nil {
		return Receipt{}, bad
	}
	if err := r.Validate(); err != nil {
		return Receipt{}, bad
	}
	return r, nil
}

func SaveReceipt(path string, r Receipt) error { return saveReceipt(path, r, nil) }

func saveReceipt(path string, r Receipt, checkpoint func(string) error) error {
	bad := errors.New("cannot commit private configuration receipt")
	if err := r.Validate(); err != nil {
		return bad
	}
	info, err := os.Lstat(path)
	if err == nil && !privateReceiptInfo(info) || err != nil && !errors.Is(err, os.ErrNotExist) {
		return bad
	}
	b, err := json.Marshal(r)
	if err != nil || len(b)+1 > maxReceiptBytes {
		return bad
	}
	if err := savePrivateBytes(path, append(b, '\n'), checkpoint); err != nil {
		return bad
	}
	return nil
}
