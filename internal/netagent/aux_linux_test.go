//go:build linux

package netagent

import (
	"net"
	"syscall"
	"testing"
)

func TestAuxiliaryDefaultExactDockerShape(t *testing.T) {
	a := auxiliaryRoute{iface: net.Interface{Index: 7}, router: net.ParseIP("172.31.253.1").To4()}
	fixture := func() syscall.NetlinkMessage {
		p := []byte{2, 0, 0, 0, 254, 3, 0, 1, 0, 0, 0, 0}
		p = append(p, attr(syscall.RTA_TABLE, u32(254))...)
		p = append(p, attr(syscall.RTA_GATEWAY, a.router)...)
		p = append(p, attr(syscall.RTA_OIF, u32(7))...)
		return syscall.NetlinkMessage{Header: syscall.NlMsghdr{Type: syscall.RTM_NEWROUTE}, Data: p}
	}
	matches := func(m syscall.NetlinkMessage, spec auxiliaryRoute) bool {
		x, err := syscall.ParseNetlinkRouteAttr(&m)
		return err == nil && spec.matches(m, x)
	}
	if !matches(fixture(), a) || matches(fixture(), auxiliaryRoute{}) {
		t.Fatal("explicit route tuple required for exact DSM shape")
	}
	for _, offset := range []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 16, 24, 32} {
		m := fixture()
		m.Data[offset]++
		if matches(m, a) {
			t.Fatalf("changed route field %d accepted", offset)
		}
	}
	for _, kind := range []uint16{syscall.RTA_PRIORITY, syscall.RTA_PREFSRC, syscall.RTA_MULTIPATH, syscall.RTA_GATEWAY, 0x7fff} {
		m := fixture()
		m.Data = append(m.Data, attr(kind, u32(0))...)
		if matches(m, a) {
			t.Fatal("extra route attribute accepted")
		}
	}
	m := fixture()
	// Replace the required table attribute with a duplicate output-interface.
	m.Data[14] = syscall.RTA_OIF
	if matches(m, a) {
		t.Fatal("duplicate attribute accepted")
	}
	m = fixture()
	m.Data = m.Data[:len(m.Data)-1]
	if matches(m, a) {
		t.Fatal("truncated attribute accepted")
	}
}

func TestAuxiliaryTupleRequiresTwoIPv4Literals(t *testing.T) {
	for _, pair := range [][2]string{{"172.31.253.2", ""}, {"", "172.31.253.1"}, {"name", "172.31.253.1"}, {"::1", "::2"}} {
		if _, err := auxiliaryInterface(1, pair[0], pair[1]); err == nil {
			t.Fatal("invalid auxiliary tuple accepted")
		}
	}
	if a, err := auxiliaryInterface(1, "", ""); err != nil || a.iface.Index != 0 {
		t.Fatal("empty tuple should disable auxiliary cleanup")
	}
}
