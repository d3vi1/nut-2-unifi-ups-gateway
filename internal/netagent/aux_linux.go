//go:build linux

package netagent

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"syscall"

	"github.com/d3vi1/nut-2-unifi-ups-gateway/internal/netconfig"
)

// An explicit auxiliary tuple authorizes removal of one Docker-created default
// route, never changes to the auxiliary address, MAC or connected route.
type auxiliaryRoute struct {
	iface   net.Interface
	address string
	prefix  int
	router  net.IP
}

func auxiliaryInterface(lan int, address, router string) (auxiliaryRoute, error) {
	if address == "" && router == "" {
		return auxiliaryRoute{}, nil
	}
	a, r := net.ParseIP(address), net.ParseIP(router)
	if a.To4() == nil || r.To4() == nil || a.String() != address || r.String() != router {
		return auxiliaryRoute{}, errors.New("invalid auxiliary network tuple")
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return auxiliaryRoute{}, errors.New("auxiliary interface inventory unavailable")
	}
	var found auxiliaryRoute
	count := 0
	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			return auxiliaryRoute{}, errors.New("auxiliary address inventory unavailable")
		}
		for _, addr := range addrs {
			n, ok := addr.(*net.IPNet)
			if !ok || !n.IP.Equal(a) {
				continue
			}
			bits, _ := n.Mask.Size()
			count++
			found = auxiliaryRoute{iface: iface, address: address, prefix: bits, router: r.To4()}
		}
	}
	if count != 1 || found.iface.Index == lan || !activeEthernet(found.iface) || requireLinkKind(found.iface, "veth") != nil || netconfig.ValidateAddress(address, found.prefix, router) != nil || !found.unchanged() {
		return auxiliaryRoute{}, errors.New("one explicit auxiliary veth interface is required")
	}
	return found, nil
}

func (a auxiliaryRoute) unchanged() bool {
	if a.iface.Index == 0 {
		return true
	}
	fresh, err := net.InterfaceByIndex(a.iface.Index)
	if err != nil || fresh.Flags != a.iface.Flags || !bytes.Equal(fresh.HardwareAddr, a.iface.HardwareAddr) || requireLinkKind(*fresh, "veth") != nil {
		return false
	}
	addrs, err := fresh.Addrs()
	if err != nil {
		return false
	}
	count := 0
	for _, addr := range addrs {
		n, ok := addr.(*net.IPNet)
		if !ok {
			return false
		}
		if n.IP.To4() == nil && n.IP.IsLinkLocalUnicast() {
			continue
		}
		bits, total := n.Mask.Size()
		if total != 32 || bits != a.prefix || n.IP.String() != a.address {
			return false
		}
		count++
	}
	return count == 1
}

func (a auxiliaryRoute) matches(m syscall.NetlinkMessage, attrs []syscall.NetlinkRouteAttr) bool {
	// Exact Engine 24 rtnetlink shape, including absent metric/extra attributes.
	header := []byte{syscall.AF_INET, 0, 0, 0, syscall.RT_TABLE_MAIN, syscall.RTPROT_BOOT, syscall.RT_SCOPE_UNIVERSE, syscall.RTN_UNICAST, 0, 0, 0, 0}
	if a.iface.Index == 0 || len(m.Data) < 12 || !bytes.Equal(m.Data[:12], header) || len(attrs) != 3 {
		return false
	}
	seen := map[uint16]bool{}
	for _, attr := range attrs {
		if seen[attr.Attr.Type] || len(attr.Value) != 4 {
			return false
		}
		seen[attr.Attr.Type] = true
		switch attr.Attr.Type {
		case syscall.RTA_TABLE:
			if binary.NativeEndian.Uint32(attr.Value) != syscall.RT_TABLE_MAIN {
				return false
			}
		case syscall.RTA_OIF:
			if binary.NativeEndian.Uint32(attr.Value) != uint32(a.iface.Index) {
				return false
			}
		case syscall.RTA_GATEWAY:
			if !bytes.Equal(attr.Value, a.router) {
				return false
			}
		default:
			return false
		}
	}
	return true
}
