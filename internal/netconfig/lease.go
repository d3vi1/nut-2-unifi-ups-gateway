// Package netconfig defines the bounded handoff between the optional network
// agent and the unprivileged UPS gateway. No NUT or adoption secrets belong here.
package netconfig

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"
	"time"
)

const StatusPath = "/run/n2u-network/status.json"

// Status is a short-lived authorization to use an already configured address.
// Sequence increases with every heartbeat; Generation changes on reconfiguration.
// It is NOT a saved DHCP lease and is never sufficient to configure an interface.
type Status struct {
	Generation string    `json:"generation"`
	Sequence   uint64    `json:"sequence"`
	Address    string    `json:"address"`
	Prefix     int       `json:"prefix"`
	Router     string    `json:"router"`
	ValidUntil time.Time `json:"valid_until"`
}

func (s Status) Validate(now time.Time) error {
	if len(s.Generation) != 32 || s.Sequence == 0 || !s.ValidUntil.After(now) || s.ValidUntil.After(now.Add(5*time.Second)) {
		return errors.New("network status is not current")
	}
	for _, r := range s.Generation {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return errors.New("invalid network generation")
		}
	}
	return ValidateAddress(s.Address, s.Prefix, s.Router)
}

func ValidateAddress(address string, bits int, router string) error {
	ip, err := netip.ParseAddr(address)
	if err != nil || !usable(ip) || bits < 1 || bits > 30 {
		return errors.New("invalid network address")
	}
	prefix := netip.PrefixFrom(ip, bits).Masked()
	a := ip.As4()
	n := prefix.Addr().As4()
	x := uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])
	y := uint32(n[0])<<24 | uint32(n[1])<<16 | uint32(n[2])<<8 | uint32(n[3])
	if x == y || x == y|(uint32(1)<<(32-bits)-1) {
		return errors.New("network or broadcast address")
	}
	r, err := netip.ParseAddr(router)
	if err != nil || !usable(r) || !prefix.Contains(r) || r == ip || r == prefix.Addr() {
		return errors.New("invalid network router")
	}
	b := r.As4()
	z := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	if z == y|(uint32(1)<<(32-bits)-1) {
		return errors.New("broadcast router")
	}
	return nil
}

func usable(ip netip.Addr) bool {
	return ip.Is4() && ip.IsGlobalUnicast() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && ip.As4()[0] != 0 && ip.As4()[0] < 224
}

func ReadStatus(path string, now time.Time) (Status, error) {
	var s Status
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || info.Size() > 2048 {
		return s, errors.New("network status unavailable")
	}
	f, err := os.Open(path)
	if err != nil {
		return s, errors.New("network status unavailable")
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return s, errors.New("network status replaced")
	}
	data, err := io.ReadAll(io.LimitReader(f, 2049))
	if err != nil || len(data) > 2048 {
		return s, errors.New("invalid network status")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(&s); err != nil {
		return Status{}, errors.New("invalid network status")
	}
	if d.Decode(new(any)) != io.EOF {
		return Status{}, errors.New("trailing network status")
	}
	return s, s.Validate(now)
}

// SameNetwork excludes heartbeat fields so a renewal with unchanged network
// parameters does not restart the gateway or lose in-memory replay protection.
func (s Status) SameNetwork(other Status) bool {
	return s.Generation == other.Generation && s.Address == other.Address && s.Prefix == other.Prefix && s.Router == other.Router
}
