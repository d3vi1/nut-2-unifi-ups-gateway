package gateway

import (
	"bytes"
	"context"
	"net"
	"os"
	"testing"
	"time"

	"github.com/d3vi1/nut-2-unifi-ups-gateway/internal/diagnostic"
	"github.com/d3vi1/nut-2-unifi-ups-gateway/internal/state"
	"github.com/d3vi1/nut-2-unifi-ups-gateway/internal/unifi/discovery"
)

func testInterface(ip, mask, mac string, flags net.Flags) interfaceObservation {
	hardware, _ := net.ParseMAC(mac)
	return interfaceObservation{flags: flags, mac: hardware, addrs: []net.Addr{&net.IPNet{IP: net.ParseIP(ip), Mask: net.IPMask(net.ParseIP(mask).To4())}}}
}

func TestConfiguredIPv4RequiresRealInterface(t *testing.T) {
	iface := testInterface("192.0.2.20", "255.255.255.0", "02:11:22:33:44:55", net.FlagUp|net.FlagBroadcast)
	identity, err := selectLocalNetworkIdentity("192.0.2.20", []interfaceObservation{iface})
	if err != nil {
		t.Fatal(err)
	}
	if identity.DeviceIP != "192.0.2.20" || identity.MAC != iface.mac.String() || identity.Netmask != "255.255.255.0" {
		t.Fatal("observed interface identity was not preserved")
	}
}

func TestInvalidNetworkIdentityFailsClosed(t *testing.T) {
	good := testInterface("192.0.2.20", "255.255.255.0", "02:11:22:33:44:55", net.FlagUp|net.FlagBroadcast)
	for name, interfaces := range map[string][]interfaceObservation{
		"nonlocal":           nil,
		"duplicate":          {good, good},
		"down":               {testInterface("192.0.2.20", "255.255.255.0", "02:11:22:33:44:55", net.FlagBroadcast)},
		"loopback interface": {testInterface("192.0.2.20", "255.255.255.0", "02:11:22:33:44:55", net.FlagUp|net.FlagBroadcast|net.FlagLoopback)},
		"no broadcast":       {testInterface("192.0.2.20", "255.255.255.0", "02:11:22:33:44:55", net.FlagUp)},
		"no MAC":             {testInterface("192.0.2.20", "255.255.255.0", "", net.FlagUp|net.FlagBroadcast)},
		"zero MAC":           {testInterface("192.0.2.20", "255.255.255.0", "00:00:00:00:00:00", net.FlagUp|net.FlagBroadcast)},
		"multicast MAC":      {testInterface("192.0.2.20", "255.255.255.0", "01:00:5e:00:00:01", net.FlagUp|net.FlagBroadcast)},
		"noncontiguous mask": {testInterface("192.0.2.20", "255.0.255.0", "02:11:22:33:44:55", net.FlagUp|net.FlagBroadcast)},
		"host mask":          {testInterface("192.0.2.20", "255.255.255.255", "02:11:22:33:44:55", net.FlagUp|net.FlagBroadcast)},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := selectLocalNetworkIdentity("192.0.2.20", interfaces)
			if diagnostic.Reason(err, diagnostic.Internal) != "network_identity_invalid" {
				t.Fatal("invalid network accepted or diagnostic lost")
			}
		})
	}
	for _, ip := range []string{"", "bad", "0.0.0.0", "127.0.0.1", "169.254.1.2", "224.0.0.1", "255.255.255.255", "2001:db8::1", "192.0.2.0", "192.0.2.255"} {
		iface := testInterface(ip, "255.255.255.0", "02:11:22:33:44:55", net.FlagUp|net.FlagBroadcast)
		if _, err := selectLocalNetworkIdentity(ip, []interfaceObservation{iface}); err == nil {
			t.Fatal("invalid endpoint accepted")
		}
	}
}

func TestNetworkModesPreserveObservedAndAdoptedIdentity(t *testing.T) {
	for _, mode := range []string{"shared", "separate"} {
		t.Run(mode, func(t *testing.T) {
			c := baseConfig(t)
			c.Device.NetworkMode = mode
			mac := c.Device.MAC
			if mode == "shared" {
				c.Device.MAC = ""
			}
			network := NetworkIdentity{DeviceIP: c.Device.IP, InformIP: "192.0.2.10", Netmask: "255.255.255.0", MAC: mac}
			g, err := New(context.Background(), c, Options{Network: network})
			if err != nil {
				t.Fatal(err)
			}
			if g.persistent.Identity.MAC != mac {
				t.Fatal("invented network MAC")
			}
			stored := g.persistent
			stored.Adoption.Adopted = true
			stored.Adoption.AuthKey = testControllerKey
			stored.Adoption.UseAESGCM = true
			if err := state.Save(c.Runtime.StateFile, stored); err != nil {
				t.Fatal(err)
			}
			before, _ := os.ReadFile(c.Runtime.StateFile)
			g, err = New(context.Background(), c, Options{Network: network})
			if err != nil || g.persistent.Identity.GUID != stored.Identity.GUID || !g.persistent.Adoption.Adopted || g.persistent.Adoption.AuthKey != testControllerKey {
				t.Fatal("restart changed adopted identity")
			}
			after, _ := os.ReadFile(c.Runtime.StateFile)
			if !bytes.Equal(before, after) {
				t.Fatal("ordinary restart rewrote state")
			}
			network.MAC = "02:11:22:33:44:66"
			if _, err := New(context.Background(), c, Options{Network: network}); diagnostic.Reason(err, diagnostic.Internal) != "identity_mismatch" {
				t.Fatal("changed MAC accepted")
			}
			after, _ = os.ReadFile(c.Runtime.StateFile)
			if !bytes.Equal(before, after) {
				t.Fatal("failed migration changed adoption state")
			}
		})
	}
}

func TestNetworkFailurePrecedesStateAndTraffic(t *testing.T) {
	for _, mode := range []string{"shared", "separate"} {
		c := baseConfig(t)
		c.Device.NetworkMode = mode
		c.Device.IP = "127.0.0.1"
		if _, err := New(context.Background(), c, Options{}); diagnostic.Reason(err, diagnostic.Internal) != "network_identity_invalid" {
			t.Fatal("invalid interface accepted")
		}
		if _, err := os.Stat(c.Runtime.StateFile); !os.IsNotExist(err) {
			t.Fatal("invalid interface created state")
		}
	}
	c := baseConfig(t)
	c.Device.MAC = ""
	if _, err := New(context.Background(), c, Options{Network: NetworkIdentity{DeviceIP: c.Device.IP, InformIP: "192.0.2.10", Netmask: "255.255.255.0", MAC: "02:11:22:33:44:55"}}); diagnostic.Reason(err, diagnostic.Internal) != "network_identity_invalid" {
		t.Fatal("separate mode silently selected a MAC")
	}
}

func TestBoundControllerUsesAdvertisedIPv4(t *testing.T) {
	// Construction must not silently fall back when either side is missing.
	for _, addresses := range [][2]string{{"", "127.0.0.1"}, {"127.0.0.1", ""}, {"::1", "127.0.0.1"}} {
		if _, err := newBoundHTTPController(time.Second, addresses[0], addresses[1]); err == nil {
			t.Fatal("invalid binding accepted")
		}
	}
}

func TestNetworkIdentityRequiresControllerIPv4(t *testing.T) {
	_, err := ResolveNetworkIdentity(
		context.Background(),
		"192.0.2.20",
		"http://controller.local:8080/inform",
		staticResolver{addresses: map[string][]net.IP{"controller.local": {net.ParseIP("2001:db8::10")}}},
	)
	if err == nil {
		t.Fatal("IPv6-only controller accepted for an IPv4 discovery profile")
	}
}

func TestDiscoveryBroadcasterBindsConfiguredSourceWithEphemeralPort(t *testing.T) {
	if _, err := openDiscoveryBroadcaster("not-an-ip"); err == nil {
		t.Fatal("invalid discovery source accepted")
	}
	connection, err := openDiscoveryBroadcaster("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	local, ok := connection.LocalAddr().(*net.UDPAddr)
	if !ok || !local.IP.Equal(net.ParseIP("127.0.0.1")) || local.Port == 0 || local.Port == discovery.Port {
		t.Fatalf("discovery socket local address = %v", connection.LocalAddr())
	}
}
