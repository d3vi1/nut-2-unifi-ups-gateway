package state

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"

	"github.com/d3vi1/nut-2-unifi-ups-gateway/internal/unifi/firmware"
)

// FirmwareReceipt is independent of adoption and configuration receipts.
type FirmwareReceipt struct {
	Schema  int      `json:"schema"`
	Epoch   string   `json:"epoch"`
	Version string   `json:"version"`
	Nonces  []string `json:"nonces"`
}

func (r FirmwareReceipt) String() string               { return "reported firmware receipt" }
func (r FirmwareReceipt) GoString() string             { return r.String() }
func (r FirmwareReceipt) receipt() Receipt             { return Receipt{r.Schema, r.Epoch, r.Version, r.Nonces} }
func (r FirmwareReceipt) Contains(nonce [16]byte) bool { return r.receipt().Contains(nonce) }
func FirmwareReceiptPath(path string) string {
	return filepath.Join(filepath.Dir(path), "controller-firmware.json")
}

func FirmwareEpoch(s State, carrier, sourceProfile string) (string, error) {
	if err := s.Validate(); err != nil || !s.Adoption.Adopted || !s.Adoption.UseAESGCM {
		return "", errors.New("invalid firmware receipt context")
	}
	key, err := hex.DecodeString(s.Adoption.AuthKey)
	if err != nil {
		return "", errors.New("invalid firmware receipt context")
	}
	defer clear(key)
	context, _ := json.Marshal([]string{"n2u-reported-firmware-v1", s.Identity.MAC, s.Identity.Serial, s.Identity.GUID, s.Adoption.InformURL, "gcm", carrier, sourceProfile})
	digest := hmac.New(sha256.New, key)
	_, _ = digest.Write(context)
	return hex.EncodeToString(digest.Sum(nil)), nil
}

func NewFirmwareReceipt(epoch, version string, previous FirmwareReceipt, nonce [16]byte) FirmwareReceipt {
	r := NewReceipt(epoch, version, previous.receipt(), nonce)
	return FirmwareReceipt{r.Schema, r.Epoch, r.CfgVersion, r.Nonces}
}

func (r FirmwareReceipt) Validate() error {
	if err := r.receipt().Validate(); err != nil || !firmware.ValidVersion(r.Version) {
		return errors.New("invalid reported firmware receipt")
	}
	return nil
}

func LoadFirmwareReceipt(path string) (FirmwareReceipt, error) {
	b, err := readPrivateReceipt(path)
	if err != nil {
		return FirmwareReceipt{}, err
	}
	r, err := decodeReceipt(b, "version")
	if err != nil {
		return FirmwareReceipt{}, err
	}
	value := FirmwareReceipt{r.Schema, r.Epoch, r.CfgVersion, r.Nonces}
	if err := value.Validate(); err != nil {
		return FirmwareReceipt{}, err
	}
	return value, nil
}

func SaveFirmwareReceipt(path string, r FirmwareReceipt) error {
	if err := r.Validate(); err != nil {
		return err
	}
	return savePrivateReceipt(path, r, nil)
}
