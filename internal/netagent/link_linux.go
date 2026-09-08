//go:build linux

package netagent

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"syscall"
	"time"
)

// These rtnetlink operations affect only this process's network namespace. No
// setns, shell, Docker socket, namespace mount, or host route API is used.
func attr(kind uint16, value []byte) []byte {
	n := 4 + len(value)
	p := make([]byte, (n+3)&^3)
	binary.NativeEndian.PutUint16(p, uint16(n))
	binary.NativeEndian.PutUint16(p[2:], kind)
	copy(p[4:], value)
	return p
}
func u32(v uint32) []byte { p := make([]byte, 4); binary.NativeEndian.PutUint32(p, v); return p }

func rtnl(kind uint16, flags uint16, body []byte) error {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.NETLINK_ROUTE)
	if err != nil {
		return errors.New("network control socket unavailable")
	}
	defer syscall.Close(fd)
	if err = syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return errors.New("network control bind failed")
	}
	if err = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &syscall.Timeval{Sec: 1}); err != nil {
		return errors.New("network control deadline failed")
	}
	p := make([]byte, 16)
	binary.NativeEndian.PutUint32(p, uint32(16+len(body)))
	binary.NativeEndian.PutUint16(p[4:], kind)
	binary.NativeEndian.PutUint16(p[6:], flags|syscall.NLM_F_REQUEST|syscall.NLM_F_ACK)
	binary.NativeEndian.PutUint32(p[8:], 1)
	p = append(p, body...)
	if err = syscall.Sendto(fd, p, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return errors.New("network control send failed")
	}
	buf := make([]byte, 4096)
	for {
		n, from, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			return errors.New("network control response failed")
		}
		peer, ok := from.(*syscall.SockaddrNetlink)
		if !ok || peer.Pid != 0 {
			continue
		}
		messages, err := syscall.ParseNetlinkMessage(buf[:n])
		if err != nil {
			return errors.New("network control malformed response")
		}
		for _, m := range messages {
			if m.Header.Seq != 1 {
				continue
			}
			if m.Header.Type == syscall.NLMSG_ERROR {
				if len(m.Data) < 4 {
					return errors.New("network control short response")
				}
				code := int32(binary.NativeEndian.Uint32(m.Data))
				if code != 0 {
					return fmt.Errorf("network configuration rejected: %w", syscall.Errno(-code))
				}
				return nil
			}
		}
	}
}

func address(ifindex int, ip string, bits int, lifetime uint32, remove bool) error {
	p := []byte{syscall.AF_INET, byte(bits), 0, 0}
	p = append(p, u32(uint32(ifindex))...)
	a := net.ParseIP(ip).To4()
	if a == nil {
		return errors.New("invalid interface address")
	}
	p = append(p, attr(syscall.IFA_LOCAL, a)...)
	p = append(p, attr(syscall.IFA_ADDRESS, a)...)
	kind := uint16(syscall.RTM_NEWADDR)
	flags := uint16(syscall.NLM_F_CREATE | syscall.NLM_F_REPLACE)
	if remove {
		kind = syscall.RTM_DELADDR
		flags = 0
	} else {
		// Short kernel lifetime is refreshed with the heartbeat. If the helper
		// dies or freezes, even a static address expires instead of staying live.
		cache := append(u32(lifetime), u32(lifetime)...)
		cache = append(cache, make([]byte, 8)...)
		p = append(p, attr(syscall.IFA_CACHEINFO, cache)...)
	}
	err := rtnl(kind, flags, p)
	if remove && (errors.Is(err, syscall.EADDRNOTAVAIL) || errors.Is(err, syscall.ENOENT)) {
		return nil
	}
	return err
}

func defaultRoute(ifindex int, router string, remove bool) error {
	p := []byte{syscall.AF_INET, 0, 0, 0, syscall.RT_TABLE_MAIN, syscall.RTPROT_STATIC, syscall.RT_SCOPE_UNIVERSE, syscall.RTN_UNICAST, 0, 0, 0, 0}
	p = append(p, attr(syscall.RTA_GATEWAY, net.ParseIP(router).To4())...)
	p = append(p, attr(syscall.RTA_OIF, u32(uint32(ifindex)))...)
	p = append(p, attr(syscall.RTA_PRIORITY, u32(42760))...)
	if remove {
		err := rtnl(syscall.RTM_DELROUTE, 0, p)
		if errors.Is(err, syscall.ESRCH) || errors.Is(err, syscall.ENOENT) {
			return nil
		}
		return err
	}
	// Exclusive create prevents overwriting a route belonging to anything else.
	return rtnl(syscall.RTM_NEWROUTE, syscall.NLM_F_CREATE|syscall.NLM_F_EXCL, p)
}

func selectedInterface(mac net.HardwareAddr) (net.Interface, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return net.Interface{}, errors.New("interface lookup failed")
	}
	var selected net.Interface
	count := 0
	for _, iface := range interfaces {
		if iface.HardwareAddr.String() == mac.String() {
			selected = iface
			count++
		}
	}
	if count == 0 {
		// Some Engine 24 multi-network deployments ignore the requested MAC.
		// Only the dedicated, uniquely identifiable bootstrap macvlan can be
		// used in that case. Never select a host-NUT bridge or a global address.
		for _, iface := range interfaces {
			if !activeEthernet(iface) || requireMacvlan(iface) != nil || !bootstrapInterface(iface) {
				continue
			}
			selected = iface
			count++
		}
	}
	if count != 1 || !activeEthernet(selected) {
		return net.Interface{}, errors.New("one active LAN interface is required")
	}
	if err := requireMacvlan(selected); err != nil {
		return net.Interface{}, err
	}
	return selected, nil
}

func activeEthernet(iface net.Interface) bool {
	return len(iface.HardwareAddr) == 6 && iface.HardwareAddr[0]&1 == 0 && iface.Flags&net.FlagUp != 0 && iface.Flags&net.FlagBroadcast != 0 && iface.Flags&net.FlagLoopback == 0
}

func bootstrapInterface(iface net.Interface) bool {
	addrs, err := iface.Addrs()
	if err != nil {
		return false
	}
	_, subnet, _ := net.ParseCIDR("169.254.254.0/24")
	count := 0
	for _, a := range addrs {
		n, ok := a.(*net.IPNet)
		if !ok {
			return false
		}
		if n.IP.To4() == nil && n.IP.IsLinkLocalUnicast() {
			continue
		}
		bits, total := n.Mask.Size()
		if total != 32 || bits != 24 || !subnet.Contains(n.IP) {
			return false
		}
		count++
	}
	return count == 1
}

func requireMacvlan(selected net.Interface) error {
	// Verify macvlan via the kernel's link metadata, not an eth0 naming guess.
	data, err := syscall.NetlinkRIB(syscall.RTM_GETLINK, syscall.AF_UNSPEC)
	if err != nil {
		return errors.New("link metadata unavailable")
	}
	msgs, err := syscall.ParseNetlinkMessage(data)
	if err != nil {
		return errors.New("invalid link metadata")
	}
	for _, m := range msgs {
		if m.Header.Type != syscall.RTM_NEWLINK || len(m.Data) < 16 || int(int32(binary.NativeEndian.Uint32(m.Data[4:]))) != selected.Index {
			continue
		}
		attrs, err := syscall.ParseNetlinkRouteAttr(&m)
		if err != nil {
			break
		}
		for _, a := range attrs {
			if a.Attr.Type&0x3fff == 18 {
				nested := a.Value
				for len(nested) >= 4 {
					n := int(binary.NativeEndian.Uint16(nested))
					typ := binary.NativeEndian.Uint16(nested[2:]) & 0x3fff
					if n < 4 || n > len(nested) {
						break
					}
					if typ == 1 && string(nested[4:n]) == "macvlan\x00" {
						return nil
					}
					next := (n + 3) &^ 3
					if next > len(nested) {
						break
					}
					nested = nested[next:]
				}
			}
		}
	}
	return errors.New("managed interface must be macvlan")
}

// installMAC follows non-mutating preflight: guards pass before mutation.
// Linux readback, not Docker's possibly stale inspection data, is authoritative.
func installMAC(iface net.Interface, mac net.HardwareAddr) (net.Interface, error) {
	if iface.HardwareAddr.String() != mac.String() {
		p := make([]byte, 16)
		copy(p[4:], u32(uint32(iface.Index)))
		p = append(p, attr(syscall.IFLA_ADDRESS, mac)...)
		if err := rtnl(syscall.RTM_NEWLINK, 0, p); err != nil {
			return net.Interface{}, err
		}
	}
	actual, err := selectedInterface(mac)
	if err != nil || actual.Index != iface.Index || actual.HardwareAddr.String() != mac.String() {
		return net.Interface{}, errors.New("managed MAC readback failed")
	}
	return actual, nil
}

// prepare accepts only Docker's dedicated bootstrap subnet; it never removes
// an arbitrary host/global address. The network must be created --internal so
// Docker installs no default route. It is intentionally a separate network.
func bootstrapAddresses(iface net.Interface) ([]*net.IPNet, error) {
	_, bootstrap, _ := net.ParseCIDR("169.254.254.0/24")
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, errors.New("interface addresses unavailable")
	}
	var remove []*net.IPNet
	for _, a := range addrs {
		n, ok := a.(*net.IPNet)
		if !ok {
			return nil, errors.New("unexpected interface address")
		}
		if n.IP.To4() == nil {
			if n.IP.IsLinkLocalUnicast() {
				continue
			}
			return nil, errors.New("managed LAN must be IPv4 only")
		}
		bits, total := n.Mask.Size()
		if total != 32 || bits != 24 || !bootstrap.Contains(n.IP) {
			return nil, errors.New("refusing to replace an unmanaged address")
		}
		remove = append(remove, n)
	}
	return remove, nil
}

func prepare(iface net.Interface, mac net.HardwareAddr) (net.Interface, error) {
	remove, err := bootstrapAddresses(iface)
	if err != nil {
		return net.Interface{}, err
	}
	recovery := iface.HardwareAddr.String() == mac.String()
	if err := checkRoutes(iface.Index, false, recovery); err != nil {
		return net.Interface{}, err
	}
	actual, err := installMAC(iface, mac)
	if err != nil {
		// A failed MAC mutation must retain the bootstrap address so the
		// next process can still identify the intended interface.
		return net.Interface{}, err
	}
	after, err := bootstrapAddresses(actual)
	if err != nil || len(after) != len(remove) {
		return net.Interface{}, errors.New("bootstrap addresses changed during preparation")
	}
	for i := range after {
		if after[i].String() != remove[i].String() {
			return net.Interface{}, errors.New("bootstrap addresses changed during preparation")
		}
	}
	if err := checkRoutes(actual.Index, true, recovery); err != nil {
		return net.Interface{}, err
	}
	for _, n := range remove {
		if err := address(actual.Index, n.IP.String(), 24, 0, true); err != nil {
			return net.Interface{}, err
		}
	}
	after, err = bootstrapAddresses(actual)
	if err != nil || len(after) != 0 {
		return net.Interface{}, errors.New("bootstrap removal readback failed")
	}
	if err := checkRoutes(actual.Index, false, false); err != nil {
		return net.Interface{}, err
	}
	return actual, nil
}

func noOtherSubnetOverlap(index int, l Lease) error {
	wanted := &net.IPNet{IP: net.ParseIP(l.Address).To4().Mask(net.CIDRMask(l.Prefix, 32)), Mask: net.CIDRMask(l.Prefix, 32)}
	interfaces, err := net.Interfaces()
	if err != nil {
		return errors.New("interface lookup failed")
	}
	for _, iface := range interfaces {
		if iface.Index == index || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			return errors.New("interface addresses unavailable")
		}
		for _, a := range addrs {
			n, ok := a.(*net.IPNet)
			if !ok || n.IP.To4() == nil {
				continue
			}
			if n.Contains(wanted.IP) || wanted.Contains(n.IP.Mask(n.Mask)) {
				return errors.New("LAN overlaps another attached subnet")
			}
		}
	}
	return nil
}

func checkRoutes(index int, cleanup, recovery bool) error {
	data, err := syscall.NetlinkRIB(syscall.RTM_GETROUTE, syscall.AF_INET)
	if err != nil {
		return errors.New("routes unavailable")
	}
	msgs, err := syscall.ParseNetlinkMessage(data)
	if err != nil {
		return errors.New("invalid routes")
	}
	var remove [][]byte
	for _, m := range msgs {
		if m.Header.Type != syscall.RTM_NEWROUTE || len(m.Data) < 12 || m.Data[4] != syscall.RT_TABLE_MAIN {
			continue
		}
		attrs, err := syscall.ParseNetlinkRouteAttr(&m)
		if err != nil {
			return errors.New("invalid route attributes")
		}
		dev := 0
		for _, a := range attrs {
			if a.Attr.Type == syscall.RTA_OIF && len(a.Value) == 4 {
				dev = int(binary.NativeEndian.Uint32(a.Value))
			}
		}
		if m.Data[1] == 0 {
			metric := uint32(0)
			for _, a := range attrs {
				if a.Attr.Type == syscall.RTA_PRIORITY && len(a.Value) == 4 {
					metric = binary.NativeEndian.Uint32(a.Value)
				}
			}
			// This metric is exclusively reserved for this agent in its private
			// namespace. Recover only its previous exact route after a crash.
			if recovery && dev == index && metric == 42760 && m.Data[5] == syscall.RTPROT_STATIC {
				remove = append(remove, m.Data)
				continue
			}
			return errors.New("managed namespace must have no existing default route")
		}
		if dev == index && m.Data[5] != syscall.RTPROT_KERNEL {
			return errors.New("refusing to change a routed LAN interface")
		}
	}
	if cleanup {
		for _, route := range remove {
			if err := rtnl(syscall.RTM_DELROUTE, 0, route); err != nil {
				return err
			}
		}
	}
	return nil
}

type packetSocket struct {
	fd       int
	index    int
	protocol uint16
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }
func openPacket(iface net.Interface, protocol uint16) (*packetSocket, error) {
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, int(htons(protocol)))
	if err != nil {
		return nil, errors.New("packet socket unavailable")
	}
	if err = syscall.Bind(fd, &syscall.SockaddrLinklayer{Protocol: htons(protocol), Ifindex: iface.Index}); err != nil {
		syscall.Close(fd)
		return nil, errors.New("packet socket bind failed")
	}
	if err = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &syscall.Timeval{Usec: 100000}); err != nil {
		syscall.Close(fd)
		return nil, errors.New("packet socket deadline failed")
	}
	return &packetSocket{fd, iface.Index, protocol}, nil
}
func (s *packetSocket) close() { _ = syscall.Close(s.fd) }
func (s *packetSocket) broadcast(p []byte) error {
	to := &syscall.SockaddrLinklayer{Protocol: htons(s.protocol), Ifindex: s.index, Halen: 6, Addr: [8]uint8{255, 255, 255, 255, 255, 255}}
	if syscall.Sendto(s.fd, p, 0, to) != nil {
		return errors.New("packet send failed")
	}
	return nil
}
func (s *packetSocket) read() ([]byte, error) {
	p := make([]byte, 2048)
	n, peer, err := syscall.Recvfrom(s.fd, p, 0)
	if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK || err == syscall.EINTR {
		return nil, nil
	}
	if err != nil {
		return nil, errors.New("packet receive failed")
	}
	link, ok := peer.(*syscall.SockaddrLinklayer)
	if !ok || link.Ifindex != s.index || link.Pkttype == syscall.PACKET_OUTGOING || n == len(p) {
		return nil, nil
	}
	return p[:n], nil
}

func checksum(p []byte) uint16 {
	var sum uint32
	for len(p) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(p))
		p = p[2:]
	}
	if len(p) > 0 {
		sum += uint32(p[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 65535) + (sum >> 16)
	}
	return ^uint16(sum)
}
func ipv4Broadcast(payload []byte) []byte {
	p := make([]byte, 28)
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:], uint16(28+len(payload)))
	p[8] = 64
	p[9] = 17
	copy(p[16:20], []byte{255, 255, 255, 255})
	binary.BigEndian.PutUint16(p[10:], checksum(p[:20]))
	binary.BigEndian.PutUint16(p[20:], 68)
	binary.BigEndian.PutUint16(p[22:], 67)
	binary.BigEndian.PutUint16(p[24:], uint16(8+len(payload)))
	return append(p, payload...)
}
func dhcpPayload(p []byte) []byte {
	if len(p) < 28 || p[0]>>4 != 4 || p[9] != 17 {
		return nil
	}
	h := int(p[0]&15) * 4
	total := int(binary.BigEndian.Uint16(p[2:]))
	if h < 20 || total > len(p) || total < h+8 || binary.BigEndian.Uint16(p[6:])&0x3fff != 0 || checksum(p[:h]) != 0 {
		return nil
	}
	u := p[h:total]
	if binary.BigEndian.Uint16(u) != 67 || binary.BigEndian.Uint16(u[2:]) != 68 || int(binary.BigEndian.Uint16(u[4:])) != len(u) {
		return nil
	}
	if binary.BigEndian.Uint16(u[6:]) != 0 {
		pseudo := append([]byte{}, p[12:20]...)
		pseudo = append(pseudo, 0, 17, u[4], u[5])
		pseudo = append(pseudo, u...)
		if checksum(pseudo) != 0 {
			return nil
		}
	}
	return u[8:]
}

// boundedPause is interruptible and never extends a lease's monotonic deadline.
func boundedPause(done <-chan struct{}, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-done:
		return false
	case <-t.C:
		return true
	}
}
