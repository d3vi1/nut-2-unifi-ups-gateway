package gateway

import (
	"context"
	"net"
	"testing"

	"github.com/d3vi1/nut-2-unifi-ups-gateway/internal/unifi/discovery"
)

func TestConfiguredIPv4AvoidsRouteGuessing(t *testing.T) {
	identity, err := ResolveNetworkIdentity(
		context.Background(),
		"192.0.2.20",
		"http://controller.local:8080/inform",
		staticResolver{addresses: map[string][]net.IP{"controller.local": {net.ParseIP("192.0.2.10")}}},
	)
	if err != nil {
		t.Fatal(err)
	}
	if identity.DeviceIP != "192.0.2.20" || identity.InformIP != "192.0.2.10" || identity.Netmask == "" {
		t.Fatalf("unexpected network identity: %+v", identity)
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
