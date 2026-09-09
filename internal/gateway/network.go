package gateway

import (
	"context"
	"errors"
	"net"
	"sort"
	"syscall"

	"github.com/d3vi1/nut-2-unifi-ups-gateway/internal/diagnostic"
)

// NetworkIdentity contains the non-secret IPv4 values projected to discovery
// and inform payloads.
type NetworkIdentity struct {
	DeviceIP string
	InformIP string
	Netmask  string
	MAC      string
}

// ResolveNetworkIdentity resolves the controller and verifies an explicitly
// selected local IPv4 interface. It never invents an IP, mask, or Ethernet MAC.
func ResolveNetworkIdentity(ctx context.Context, configuredIP, informURL string, resolver Resolver) (NetworkIdentity, error) {
	controllerIP, err := controllerIPv4(ctx, informURL, resolver)
	if err != nil {
		return NetworkIdentity{}, err
	}
	identity, err := localNetworkIdentity(configuredIP)
	if err != nil {
		return NetworkIdentity{}, err
	}
	identity.InformIP = controllerIP.String()
	return identity, nil
}

func controllerIPv4(ctx context.Context, informURL string, resolver Resolver) (net.IP, error) {
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	u, err := parseControllerURL(informURL)
	if err != nil {
		return nil, err
	}
	controllerIP, err := resolveIPv4(ctx, resolver, u.Hostname())
	if err != nil {
		return nil, diagnostic.Wrap(diagnostic.ControllerDNS, errors.New("controller has no usable IPv4 address"))
	}
	return controllerIP, nil
}

func resolveIPv4(ctx context.Context, resolver Resolver, host string) (net.IP, error) {
	if literal := net.ParseIP(host).To4(); literal != nil {
		return literal, nil
	}
	addresses, err := resolver.LookupIP(ctx, "ip4", host)
	if err != nil {
		return nil, errors.New("IPv4 lookup failed")
	}
	var candidates []string
	for _, address := range addresses {
		if ipv4 := address.To4(); ipv4 != nil && !ipv4.IsUnspecified() && !ipv4.IsMulticast() {
			candidates = append(candidates, ipv4.String())
		}
	}
	if len(candidates) == 0 {
		return nil, errors.New("IPv4 lookup returned no usable address")
	}
	sort.Strings(candidates)
	return net.ParseIP(candidates[0]).To4(), nil
}

type interfaceObservation struct {
	flags net.Flags
	mac   net.HardwareAddr
	addrs []net.Addr
}

// localNetworkIdentity reads interface metadata only: no raw socket, Docker
// socket, network mutation, or elevated capability is needed. Local consistency
// does not prove LAN-wide uniqueness or absence of external NAT; those remain
// explicit deployment requirements.
func localNetworkIdentity(configuredIP string) (NetworkIdentity, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return NetworkIdentity{}, diagnostic.Wrap(diagnostic.NetworkIdentityInvalid, errors.New("read network interfaces"))
	}
	observations := make([]interfaceObservation, 0, len(interfaces))
	for _, networkInterface := range interfaces {
		addresses, err := networkInterface.Addrs()
		if err != nil {
			return NetworkIdentity{}, diagnostic.Wrap(diagnostic.NetworkIdentityInvalid, errors.New("read interface addresses"))
		}
		observations = append(observations, interfaceObservation{networkInterface.Flags, networkInterface.HardwareAddr, addresses})
	}
	return selectLocalNetworkIdentity(configuredIP, observations)
}

func selectLocalNetworkIdentity(configuredIP string, interfaces []interfaceObservation) (NetworkIdentity, error) {
	fail := func() (NetworkIdentity, error) {
		return NetworkIdentity{}, diagnostic.Wrap(diagnostic.NetworkIdentityInvalid, errors.New("device IP requires one active Ethernet interface with a valid address, mask, and MAC"))
	}
	ip := net.ParseIP(configuredIP).To4()
	if ip == nil || !ip.IsGlobalUnicast() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return fail()
	}
	var identity NetworkIdentity
	matches := 0
	for _, iface := range interfaces {
		for _, address := range iface.addrs {
			ipNetwork, ok := address.(*net.IPNet)
			if !ok || !ipNetwork.IP.Equal(ip) {
				continue
			}
			matches++
			ones, bits := ipNetwork.Mask.Size()
			if iface.flags&net.FlagUp == 0 || iface.flags&net.FlagLoopback != 0 ||
				iface.flags&net.FlagBroadcast == 0 || len(iface.mac) != 6 || iface.mac[0]&1 != 0 ||
				iface.mac.String() == "00:00:00:00:00:00" || bits != 32 || ones < 1 || ones > 30 {
				return fail()
			}
			mask := ipNetwork.Mask
			network := ip.Mask(mask)
			broadcast := append(net.IP(nil), network...)
			for i := range broadcast {
				broadcast[i] |= ^mask[i]
			}
			if ip.Equal(network) || ip.Equal(broadcast) {
				return fail()
			}
			identity = NetworkIdentity{DeviceIP: ip.String(), Netmask: net.IP(mask).String(), MAC: iface.mac.String()}
		}
	}
	if matches != 1 {
		return fail()
	}
	return identity, nil
}

// openDiscoveryBroadcaster mirrors the UPS firmware's send-only discovery
// socket. It binds only the configured source IP with an ephemeral port so a
// multi-homed host cannot route limited broadcasts through the wrong network.
// It deliberately does not bind UDP/10001 or expose a listener.
func openDiscoveryBroadcaster(sourceIP string) (*net.UDPConn, error) {
	source := net.ParseIP(sourceIP).To4()
	if source == nil || source.IsUnspecified() || source.IsMulticast() {
		return nil, errors.New("discovery source requires a usable IPv4 address")
	}
	connection, err := net.ListenUDP("udp4", &net.UDPAddr{IP: source})
	if err != nil {
		return nil, errors.New("open discovery UDP socket")
	}
	if err := enableBroadcast(connection); err != nil {
		_ = connection.Close()
		return nil, err
	}
	return connection, nil
}

func enableBroadcast(connection *net.UDPConn) error {
	raw, err := connection.SyscallConn()
	if err != nil {
		return errors.New("access discovery UDP socket")
	}
	var optionErr error
	if err := raw.Control(func(fileDescriptor uintptr) {
		optionErr = syscall.SetsockoptInt(int(fileDescriptor), syscall.SOL_SOCKET, syscall.SO_BROADCAST, 1)
	}); err != nil || optionErr != nil {
		return errors.New("enable discovery broadcast")
	}
	return nil
}
