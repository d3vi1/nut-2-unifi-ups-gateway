package netagent

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

var fixtureMAC = net.HardwareAddr{2, 0, 0, 0, 0, 30}
var fixtureXID = [4]byte{1, 2, 3, 4}

func fixtureReply(kind byte) []byte {
	p := make([]byte, 240)
	p[0], p[1], p[2] = 2, 1, 6
	copy(p[4:8], fixtureXID[:])
	copy(p[28:34], fixtureMAC)
	copy(p[16:20], net.ParseIP("192.0.2.30").To4())
	copy(p[236:], []byte{99, 130, 83, 99})
	p = append(p, 53, 1, kind, 54, 4, 192, 0, 2, 1, 1, 4, 255, 255, 255, 0, 3, 4, 192, 0, 2, 1, 51, 4, 0, 0, 0, 120, 255)
	return p
}

func TestDHCPReplyValidation(t *testing.T) {
	k, l, err := reply(fixtureReply(5), fixtureXID, fixtureMAC)
	if err != nil || k != 5 || l.Address != "192.0.2.30" || l.Prefix != 24 || l.Router != "192.0.2.1" || l.Renew != time.Minute || l.Rebind != 105*time.Second {
		t.Fatal("valid ACK rejected")
	}
	tests := map[string]func([]byte) []byte{
		"transaction":     func(p []byte) []byte { p[4]++; return p },
		"client":          func(p []byte) []byte { p[28]++; return p },
		"cookie":          func(p []byte) []byte { p[239]++; return p },
		"no end":          func(p []byte) []byte { return p[:len(p)-1] },
		"broadcast lease": func(p []byte) []byte { p[19] = 255; return p },
		"loopback":        func(p []byte) []byte { p[16] = 127; return p },
		"short option":    func(p []byte) []byte { return append(p[:len(p)-1], 58, 4, 0, 0) },
		"duplicate":       func(p []byte) []byte { return append(p[:len(p)-1], 53, 1, 5, 255) },
		"route option":    func(p []byte) []byte { return append(p[:len(p)-1], 121, 5, 0, 192, 0, 2, 1, 255) },
		"overload":        func(p []byte) []byte { return append(p[:len(p)-1], 52, 1, 1, 255) },
		"client id":       func(p []byte) []byte { return append(p[:len(p)-1], 61, 7, 1, 2, 0, 0, 0, 0, 31, 255) },
		"T1 after T2":     func(p []byte) []byte { return append(p[:len(p)-1], 58, 4, 0, 0, 0, 110, 255) },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			if _, _, err := reply(mutate(fixtureReply(5)), fixtureXID, fixtureMAC); err == nil {
				t.Fatal("malformed ACK accepted")
			}
		})
	}
	for n := 0; n < len(fixtureReply(5)); n++ {
		if _, _, err := reply(fixtureReply(5)[:n], fixtureXID, fixtureMAC); err == nil {
			t.Fatal("truncated ACK accepted")
		}
	}
}

func TestDHCPRequestsUseStableClientAndPhaseFields(t *testing.T) {
	p := packet(1, fixtureXID, fixtureMAC, nil, nil, nil)
	if len(p) < 300 || p[10] != 128 || p[0] != 1 || binary.BigEndian.Uint32(p[12:]) != 0 {
		t.Fatal("invalid discover")
	}
	r := packet(3, fixtureXID, fixtureMAC, nil, nil, net.ParseIP("192.0.2.30"))
	if r[10] != 0 || !net.IP(r[12:16]).Equal(net.ParseIP("192.0.2.30")) {
		t.Fatal("invalid renewal")
	}
	if _, _, err := reply(fixtureReply(6), fixtureXID, fixtureMAC); err != nil {
		t.Fatal("NAK rejected")
	}
}

func FuzzDHCPReply(f *testing.F) {
	f.Add(fixtureReply(5))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, p []byte) { _, _, _ = reply(p, fixtureXID, fixtureMAC) })
}
