// Package netagent owns only the explicitly selected container LAN interface.
// DHCP is unauthenticated; deployment requires a trusted, controlled LAN.
package netagent

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"time"

	"github.com/d3vi1/nut-2-unifi-ups-gateway/internal/netconfig"
)

type Lease struct {
	Address  string
	Prefix   int
	Router   string
	Server   string
	Duration time.Duration
	Renew    time.Duration
	Rebind   time.Duration
}

var errAddressConflict = errors.New("address conflict")

// packet builds DHCP messages with one stable Ethernet client identifier. The
// broadcast flag permits receipt before assigning yiaddr to the interface.
func packet(kind byte, xid [4]byte, mac net.HardwareAddr, requested, server, current net.IP) []byte {
	p := make([]byte, 240)
	p[0], p[1], p[2] = 1, 1, 6
	copy(p[4:8], xid[:])
	copy(p[28:34], mac)
	if current.To4() == nil {
		p[10] = 0x80
	} else {
		copy(p[12:16], current.To4())
	}
	copy(p[236:240], []byte{99, 130, 83, 99})
	p = append(p, 53, 1, kind, 61, 7, 1)
	p = append(p, mac...)
	if requested.To4() != nil {
		p = append(p, 50, 4)
		p = append(p, requested.To4()...)
	}
	if server.To4() != nil {
		p = append(p, 54, 4)
		p = append(p, server.To4()...)
	}
	p = append(p, 55, 5, 1, 3, 51, 58, 59, 57, 2, 5, 220, 255)
	for len(p) < 300 {
		p = append(p, 0)
	}
	return p
}

func reply(p []byte, xid [4]byte, mac net.HardwareAddr) (byte, Lease, error) {
	bad := func() (byte, Lease, error) { return 0, Lease{}, errors.New("invalid DHCP reply") }
	if len(p) < 241 || len(p) > 1500 || len(mac) != 6 || p[0] != 2 || p[1] != 1 || p[2] != 6 || !bytes.Equal(p[4:8], xid[:]) || !bytes.Equal(p[28:34], mac) || !bytes.Equal(p[236:240], []byte{99, 130, 83, 99}) {
		return bad()
	}
	opts := map[byte][]byte{}
	ended := false
	for i := 240; i < len(p); {
		code := p[i]
		i++
		if code == 255 {
			ended = true
			break
		}
		if code == 0 {
			continue
		}
		if i >= len(p) {
			return bad()
		}
		size := int(p[i])
		i++
		if size > len(p)-i {
			return bad()
		}
		if _, exists := opts[code]; exists {
			return bad()
		}
		opts[code] = p[i : i+size]
		i += size
	}
	if !ended || len(opts[53]) != 1 || len(opts[54]) != 4 {
		return bad()
	}
	// No ambiguous overloaded fields, classless routes, or mismatching echoed
	// client ID. We do not request routes or silently replace option 121 with 3.
	if _, ok := opts[52]; ok {
		return bad()
	}
	if _, ok := opts[121]; ok {
		return bad()
	}
	if _, ok := opts[249]; ok {
		return bad()
	}
	if id, ok := opts[61]; ok && !bytes.Equal(id, append([]byte{1}, mac...)) {
		return bad()
	}
	l := Lease{Server: net.IP(opts[54]).String()}
	server := net.ParseIP(l.Server)
	if server == nil || !server.IsGlobalUnicast() || server.IsLoopback() || server.IsLinkLocalUnicast() || server.To4()[0] == 0 || server.To4()[0] >= 224 {
		return bad()
	}
	kind := opts[53][0]
	if kind == 6 {
		return kind, l, nil
	}
	if kind != 2 && kind != 5 {
		return bad()
	}
	if len(opts[1]) != 4 || len(opts[3]) != 4 || len(opts[51]) != 4 {
		return bad()
	}
	l.Address = net.IP(p[16:20]).String()
	l.Router = net.IP(opts[3]).String()
	bits, total := net.IPMask(opts[1]).Size()
	if total != 32 {
		return bad()
	}
	l.Prefix = bits
	if netconfig.ValidateAddress(l.Address, l.Prefix, l.Router) != nil {
		return bad()
	}
	seconds := binary.BigEndian.Uint32(opts[51])
	if seconds < 30 || seconds > 7*24*3600 {
		return bad()
	}
	l.Duration = time.Duration(seconds) * time.Second
	l.Renew = l.Duration / 2
	l.Rebind = l.Duration * 7 / 8
	for code, dest := range map[byte]*time.Duration{58: &l.Renew, 59: &l.Rebind} {
		if v, ok := opts[code]; ok {
			if len(v) != 4 {
				return bad()
			}
			*dest = time.Duration(binary.BigEndian.Uint32(v)) * time.Second
		}
	}
	if l.Renew <= 0 || l.Renew >= l.Rebind || l.Rebind >= l.Duration {
		return bad()
	}
	return kind, l, nil
}
