package gateway

import (
	"context"
	"errors"
	"net"
	"sort"
	"strconv"
	"syscall"
)

// NetworkIdentity contains the non-secret IPv4 values projected to discovery
// and inform payloads.
type NetworkIdentity struct {
	DeviceIP string
	InformIP string
	Netmask  string
}

// ResolveNetworkIdentity resolves the controller and asks the kernel which
// local IPv4 route it would use. DialUDP performs route selection without
// transmitting a datagram.
func ResolveNetworkIdentity(ctx context.Context, configuredIP, informURL string, resolver Resolver) (NetworkIdentity, error) {
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	u, err := parseControllerURL(informURL)
	if err != nil {
		return NetworkIdentity{}, err
	}
	controllerIP, err := resolveIPv4(ctx, resolver, u.Hostname())
	if err != nil {
		return NetworkIdentity{}, errors.New("controller has no usable IPv4 address")
	}
	deviceIP := net.ParseIP(configuredIP).To4()
	if configuredIP == "" {
		port, err := strconv.Atoi(effectivePort(u))
		if err != nil {
			return NetworkIdentity{}, errors.New("controller has an invalid port")
		}
		deviceIP, err = routeLocalIPv4(controllerIP, port)
		if err != nil {
			return NetworkIdentity{}, err
		}
	}
	if deviceIP == nil || deviceIP.IsUnspecified() || deviceIP.IsMulticast() {
		return NetworkIdentity{}, errors.New("device has no usable IPv4 address")
	}
	mask := net.IPv4(255, 255, 255, 255)
	if discovered := interfaceNetmask(deviceIP); discovered != nil {
		mask = discovered
	}
	return NetworkIdentity{
		DeviceIP: deviceIP.String(),
		InformIP: controllerIP.String(),
		Netmask:  mask.String(),
	}, nil
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

func routeLocalIPv4(controllerIP net.IP, port int) (net.IP, error) {
	connection, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: controllerIP, Port: port})
	if err != nil {
		return nil, errors.New("derive local IPv4 route")
	}
	defer connection.Close()
	local, ok := connection.LocalAddr().(*net.UDPAddr)
	if !ok || local.IP.To4() == nil {
		return nil, errors.New("route did not select a local IPv4 address")
	}
	return append(net.IP(nil), local.IP.To4()...), nil
}

func interfaceNetmask(ip net.IP) net.IP {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	for _, networkInterface := range interfaces {
		if networkInterface.Flags&net.FlagUp == 0 {
			continue
		}
		addresses, err := networkInterface.Addrs()
		if err != nil {
			continue
		}
		for _, address := range addresses {
			ipNetwork, ok := address.(*net.IPNet)
			if !ok || !ipNetwork.IP.Equal(ip) || len(ipNetwork.Mask) != net.IPv4len {
				continue
			}
			return append(net.IP(nil), ipNetwork.Mask...)
		}
	}
	return nil
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
