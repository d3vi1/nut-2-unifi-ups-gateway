//go:build linux

package netagent

import (
	"context"
	"encoding/binary"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/d3vi1/nut-2-unifi-ups-gateway/internal/netconfig"
)

func labLink(t *testing.T, name, kind string, parent int, mac net.HardwareAddr) net.Interface {
	t.Helper()
	p := make([]byte, 16)
	copy(p[8:], u32(syscall.IFF_UP))
	copy(p[12:], u32(syscall.IFF_UP))
	p = append(p, attr(syscall.IFLA_IFNAME, append([]byte(name), 0))...)
	if parent != 0 {
		p = append(p, attr(syscall.IFLA_LINK, u32(uint32(parent)))...)
	}
	if mac != nil {
		p = append(p, attr(syscall.IFLA_ADDRESS, mac)...)
	}
	info := attr(1, append([]byte(kind), 0))
	if kind == "macvlan" {
		info = append(info, attr(2|0x8000, attr(1, u32(4)))...)
	}
	p = append(p, attr(18|0x8000, info)...)
	if err := rtnl(syscall.RTM_NEWLINK, syscall.NLM_F_CREATE|syscall.NLM_F_EXCL, p); err != nil {
		t.Fatal(err)
	}
	iface, err := net.InterfaceByName(name)
	if err != nil {
		t.Fatal(err)
	}
	return *iface
}

// TestLinuxManagedNetworkLab is opt-in and refuses a namespace with any
// non-loopback interface. Run ONLY in a disposable --network none container.
// It never attaches to a physical NIC, DHCP server, NUT, or controller.
func TestLinuxManagedNetworkLab(t *testing.T) {
	if os.Getenv("N2U_ISOLATED_NETWORK_LAB") != "1" {
		t.Skip("requires disposable isolated Linux container")
	}
	if os.Getpid() != 1 {
		t.Fatal("lab must be PID 1 in its disposable container")
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, iface := range interfaces {
		// Synology creates a dormant kernel IPv6-in-IPv4 fallback device even
		// in --network none. It is not a LAN attachment; never configure it.
		if iface.Name == "sit0" && iface.Flags == 0 {
			addrs, err := iface.Addrs()
			if err == nil && len(addrs) == 0 {
				continue
			}
		}
		if iface.Flags&net.FlagLoopback == 0 {
			t.Fatalf("refusing nonempty network namespace: interface=%s flags=%s", iface.Name, iface.Flags)
		}
	}
	// A local bridge supplies an Ethernet parent without a physical uplink.
	// Unlike dummy, bridge support is already required by Docker on Synology.
	parent := labLink(t, "n2u-lab-parent", "bridge", 0, nil)
	client := labLink(t, "n2u-lab-client", "macvlan", parent.Index, fixtureMAC)
	server := labLink(t, "n2u-lab-server", "macvlan", parent.Index, net.HardwareAddr{2, 0, 0, 0, 0, 1})
	if err := address(client.Index, "169.254.254.30", 24, 3600, false); err != nil {
		t.Fatal(err)
	}
	if err := address(server.Index, "198.51.100.1", 24, 3600, false); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var silent atomic.Bool
	var renewals atomic.Int32
	var rebindings atomic.Int32
	serverDone := make(chan error, 1)
	go func() { serverDone <- labDHCPServer(ctx, server, &silent, &renewals, &rebindings) }()
	agentDone := make(chan error, 1)
	go func() { agentDone <- Run(ctx, Config{MAC: fixtureMAC.String(), Mode: "dhcp"}) }()
	var first netconfig.Status
	deadline := time.Now().Add(25 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-agentDone:
			t.Fatalf("agent stopped before lease: %v", err)
		default:
		}
		s, err := netconfig.ReadStatus(netconfig.StatusPath, time.Now())
		if err == nil {
			first = s
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if first.Address != "192.0.2.30" {
		t.Fatal("synthetic DHCP did not bind")
	}
	t.Log("synthetic DHCP acquired; checking renewal without generation change")
	deadline = time.Now().Add(12 * time.Second)
	for renewals.Load() < 1 && time.Now().Before(deadline) {
		select {
		case err := <-agentDone:
			t.Fatalf("agent stopped during renewal: %v", err)
		default:
		}
		time.Sleep(100 * time.Millisecond)
	}
	if renewals.Load() < 1 {
		t.Fatal("no unicast renewal observed")
	}
	s, err := netconfig.ReadStatus(netconfig.StatusPath, time.Now())
	if err != nil || !s.SameNetwork(first) {
		t.Fatal("renewal changed network generation")
	}
	silent.Store(true)
	t.Log("DHCP server disabled; checking fail-closed expiry")
	deadline = time.Now().Add(35 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := netconfig.ReadStatus(netconfig.StatusPath, time.Now()); err != nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if _, err := netconfig.ReadStatus(netconfig.StatusPath, time.Now()); err == nil {
		t.Fatal("status survived lease expiry")
	}
	if rebindings.Load() == 0 {
		t.Fatal("no broadcast rebinding observed before expiry")
	}
	time.Sleep(4 * time.Second)
	addrs, err := client.Addrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range addrs {
		if strings.Contains(a.String(), "192.0.2.30") {
			t.Fatal("address survived lease expiry")
		}
	}
	cancel()
	select {
	case err := <-agentDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("agent did not stop")
	}
	select {
	case err := <-serverDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("server did not stop")
	}
	t.Log("synthetic lease acquisition, renewal, server loss and address expiry passed")

	staticCtx, staticCancel := context.WithCancel(context.Background())
	defer staticCancel()
	staticDone := make(chan error, 1)
	go func() {
		staticDone <- Run(staticCtx, Config{MAC: fixtureMAC.String(), Mode: "static", StaticCIDR: "192.0.2.30/24", Router: "192.0.2.1"})
	}()
	deadline = time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-staticDone:
			t.Fatalf("static agent stopped: %v", err)
		default:
		}
		if s, err := netconfig.ReadStatus(netconfig.StatusPath, time.Now()); err == nil && s.Address == "192.0.2.30" {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if _, err := netconfig.ReadStatus(netconfig.StatusPath, time.Now()); err != nil {
		t.Fatal("static address was not configured")
	}
	staticCancel()
	select {
	case err := <-staticDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("static agent did not stop")
	}
	// Stop heartbeats without withdrawing: the same kernel expiry path as a
	// killed/frozen helper, without extra process-control privileges.
	o := owner{iface: client}
	if err := o.install(Lease{Address: "192.0.2.30", Prefix: 24, Router: "192.0.2.1"}, time.Time{}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Second)
	if _, err := netconfig.ReadStatus(netconfig.StatusPath, time.Now()); err == nil {
		t.Fatal("frozen helper retained live status")
	}
	addrs, err = client.Addrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range addrs {
		if strings.Contains(a.String(), "192.0.2.30") {
			t.Fatal("frozen helper retained kernel address")
		}
	}
	if err := o.withdraw(); err != nil {
		t.Fatal(err)
	}
	t.Log("static configuration, restart and simulated helper-freeze expiry passed")
}

func labDHCPServer(ctx context.Context, iface net.Interface, silent *atomic.Bool, renewals, rebindings *atomic.Int32) error {
	// Use a synthetic server IP that is NOT local to this namespace. Answer
	// its ARP ourselves so unicast renewals genuinely cross the macvlan link
	// instead of being short-circuited through the kernel's local-IP table.
	arp, err := openPacket(iface, 0x0806)
	if err != nil {
		return err
	}
	arpDone := make(chan struct{})
	go func() {
		defer close(arpDone)
		for ctx.Err() == nil {
			p, err := arp.read()
			if err != nil {
				return
			}
			if len(p) < 28 || p[7] != 1 || !net.IP(p[24:28]).Equal(net.ParseIP("192.0.2.2")) {
				continue
			}
			out := arpPacket(iface.HardwareAddr, net.IP(p[14:18]), false)
			out[7] = 2
			copy(out[14:18], net.ParseIP("192.0.2.2").To4())
			copy(out[18:24], p[8:14])
			_ = arp.broadcast(out)
		}
	}()
	defer func() { arp.close(); <-arpDone }()
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{Port: 67})
	if err != nil {
		return err
	}
	defer udp.Close()
	unicast := make(chan []byte, 8)
	go func() {
		for ctx.Err() == nil {
			p := make([]byte, 1500)
			_ = udp.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			n, source, err := udp.ReadFromUDP(p)
			if err != nil {
				continue
			}
			if source.Port != 68 {
				continue
			}
			select {
			case unicast <- p[:n]:
			case <-ctx.Done():
				return
			}
		}
	}()
	s, err := openPacket(iface, 0x0800)
	if err != nil {
		return err
	}
	defer s.close()
	for ctx.Err() == nil {
		p, err := s.read()
		if err != nil {
			return err
		}
		var msg []byte
		if len(p) >= 28 && p[0] == 0x45 && p[9] == 17 && binary.BigEndian.Uint16(p[20:]) == 68 && binary.BigEndian.Uint16(p[22:]) == 67 {
			msg = p[28:]
		}
		select {
		case msg = <-unicast:
		default:
		}
		if len(msg) < 243 || msg[0] != 1 || msg[240] != 53 || msg[241] != 1 {
			continue
		}
		kind := msg[242]
		if kind == 3 && !net.IP(msg[12:16]).Equal(net.IPv4zero) && len(p) >= 20 && net.IP(p[16:20]).Equal(net.IPv4bcast) {
			rebindings.Add(1)
		}
		if silent.Load() {
			continue
		}
		if kind != 1 && kind != 3 {
			continue
		}
		response := fixtureReply(5)
		if kind == 1 {
			response = fixtureReply(2)
		}
		copy(response[4:8], msg[4:8])
		copy(response[28:34], msg[28:34])
		response[248] = 2 // option 54: synthetic, non-local DHCP server
		// 30-second lease, T1=10 and T2=20. Enough time for conflict probes.
		response[len(response)-2] = 30
		response = append(response[:len(response)-1], 58, 4, 0, 0, 0, 10, 59, 4, 0, 0, 0, 20, 255)
		if kind == 3 && !net.IP(msg[12:16]).Equal(net.IPv4zero) {
			renewals.Add(1)
		}
		out := ipv4Broadcast(response)
		copy(out[12:16], net.ParseIP("192.0.2.2").To4())
		binary.BigEndian.PutUint16(out[20:], 67)
		binary.BigEndian.PutUint16(out[22:], 68)
		out[10], out[11] = 0, 0
		binary.BigEndian.PutUint16(out[10:], checksum(out[:20]))
		if err := s.broadcast(out); err != nil {
			return err
		}
	}
	return nil
}

func TestPacketBoundsAndARPConflicts(t *testing.T) {
	p := ipv4Broadcast(fixtureReply(5))
	binary.BigEndian.PutUint16(p[20:], 67)
	binary.BigEndian.PutUint16(p[22:], 68)
	if dhcpPayload(p) == nil {
		t.Fatal("valid UDP envelope rejected")
	}
	for n := 0; n < len(p); n++ {
		if dhcpPayload(p[:n]) != nil {
			t.Fatal("truncated envelope accepted")
		}
	}
	p[10]++
	if dhcpPayload(p) != nil {
		t.Fatal("bad checksum accepted")
	}
	other := net.HardwareAddr{2, 0, 0, 0, 0, 31}
	ip := net.ParseIP("192.0.2.30")
	if !arpConflict(arpPacket(other, ip, false), fixtureMAC, ip, false) {
		t.Fatal("ARP claimant not detected")
	}
	if !arpConflict(arpPacket(other, ip, true), fixtureMAC, ip, true) {
		t.Fatal("simultaneous probe not detected")
	}
	if arpConflict(arpPacket(fixtureMAC, ip, true), fixtureMAC, ip, true) {
		t.Fatal("own probe is conflict")
	}
}
