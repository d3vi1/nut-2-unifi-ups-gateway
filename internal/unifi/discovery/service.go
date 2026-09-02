package discovery

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

// PacketWriter is the small net.PacketConn subset used by Announcer.
type PacketWriter interface {
	WriteTo([]byte, net.Addr) (int, error)
}

// PacketConn is injectable so the responder can be tested without live UDP.
type PacketConn interface {
	PacketWriter
	ReadFrom([]byte) (int, net.Addr, error)
	SetReadDeadline(time.Time) error
}

// DefaultDestinations returns the firmware-faithful IPv4 broadcast target.
// Generic UniFi implementations sometimes also multicast, but USPDA2C does not.
func DefaultDestinations() []net.Addr {
	return []net.Addr{
		&net.UDPAddr{IP: net.ParseIP(BroadcastIPv4).To4(), Port: Port},
	}
}

// Announcer sends a template to injected destinations. It owns the v2
// sequence counter and is safe for concurrent use.
type Announcer struct {
	mu           sync.Mutex
	template     Announcement
	destinations []net.Addr
	nextSequence uint32
}

func NewAnnouncer(template Announcement, destinations []net.Addr) (*Announcer, error) {
	if len(destinations) == 0 {
		destinations = DefaultDestinations()
	}
	for _, destination := range destinations {
		udp, ok := destination.(*net.UDPAddr)
		if !ok || udp.IP.To4() == nil || udp.Port != Port {
			return nil, errors.New("discovery: destination must be IPv4 UDP port 10001")
		}
	}
	if template.Command != CommandAnnouncement {
		return nil, errors.New("discovery: announcer requires command 6")
	}
	if template.Version != V2 {
		return nil, errors.New("discovery: announcer requires version 2")
	}
	if template.Sequence == 0 {
		template.Sequence = 1
	}
	if err := template.ValidateIdentity(); err != nil {
		return nil, err
	}
	return &Announcer{
		template:     cloneAnnouncement(template),
		destinations: append([]net.Addr(nil), destinations...),
		nextSequence: template.Sequence,
	}, nil
}

// Announce performs one send to every destination. All destinations are
// attempted, and failures are joined without including packet contents.
func (a *Announcer) Announce(writer PacketWriter) error {
	if a == nil || writer == nil {
		return errors.New("discovery: announcer and writer are required")
	}
	a.mu.Lock()
	announcement := cloneAnnouncement(a.template)
	if announcement.Version == V2 {
		if a.nextSequence == 0 {
			a.mu.Unlock()
			return errors.New("discovery: announcement sequence exhausted")
		}
		announcement.Sequence = a.nextSequence
		a.nextSequence++
	}
	a.mu.Unlock()

	packet, err := announcement.Marshal()
	if err != nil {
		return err
	}
	var failures []error
	for _, destination := range a.destinations {
		n, err := writer.WriteTo(packet, destination)
		if err != nil {
			failures = append(failures, errors.New("discovery: announce write failed"))
			continue
		}
		if n != len(packet) {
			failures = append(failures, io.ErrShortWrite)
		}
	}
	return errors.Join(failures...)
}

// Run announces immediately and then at interval until ctx is cancelled.
func (a *Announcer) Run(ctx context.Context, writer PacketWriter, interval time.Duration) error {
	if interval <= 0 {
		return errors.New("discovery: announcement interval must be positive")
	}
	if err := a.Announce(writer); err != nil {
		return err
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := a.Announce(writer); err != nil {
				return err
			}
		}
	}
}

// Responder answers exact four-byte version 1 or 2 discovery probes. It does
// not respond to announcements or malformed packets, preventing packet loops.
type Responder struct {
	mu           sync.Mutex
	template     Announcement
	nextSequence uint32
}

func NewResponder(template Announcement) (*Responder, error) {
	// Validate the richer v2 identity even if the caller's proactive template
	// is v1, so every constructed responder can answer both probe versions.
	template.Version = V2
	if template.Sequence == 0 {
		template.Sequence = 1
	}
	if err := template.ValidateIdentity(); err != nil {
		return nil, err
	}
	return &Responder{template: cloneAnnouncement(template), nextSequence: template.Sequence}, nil
}

// ResponseFor is the pure parsing seam used by tests and non-socket callers.
// handled is false for well-formed packets that are not discovery probes.
func (r *Responder) ResponseFor(request []byte) (response []byte, handled bool, err error) {
	if r == nil {
		return nil, false, errors.New("discovery: nil responder")
	}
	parsed, err := Parse(request)
	if err != nil {
		return nil, false, err
	}
	if parsed.Command != CommandDiscover || len(request) != 4 {
		return nil, false, nil
	}
	r.mu.Lock()
	announcement := cloneAnnouncement(r.template)
	announcement.Version = parsed.Version
	announcement.Command = CommandDiscover
	if announcement.Version == V2 {
		if r.nextSequence == 0 {
			r.mu.Unlock()
			return nil, false, errors.New("discovery: response sequence exhausted")
		}
		announcement.Sequence = r.nextSequence
		r.nextSequence++
	}
	r.mu.Unlock()
	packet, err := announcement.Marshal()
	if err != nil {
		return nil, false, err
	}
	return packet, true, nil
}

// Serve responds on an injected packet connection. Parse errors and packets
// from non-private sources are dropped silently; socket failures are returned.
func (r *Responder) Serve(ctx context.Context, conn PacketConn) error {
	if r == nil || conn == nil {
		return errors.New("discovery: responder and connection are required")
	}
	buffer := make([]byte, MaxDatagram+1)
	for {
		if err := conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
			return errors.New("discovery: set read deadline failed")
		}
		n, source, err := conn.ReadFrom(buffer)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				continue
			}
			return errors.New("discovery: read failed")
		}
		if n > MaxDatagram || !privateSource(source) {
			continue
		}
		response, handled, err := r.ResponseFor(buffer[:n])
		if err != nil || !handled {
			continue
		}
		written, err := conn.WriteTo(response, source)
		if err != nil {
			return errors.New("discovery: response write failed")
		}
		if written != len(response) {
			return io.ErrShortWrite
		}
	}
}

func privateSource(source net.Addr) bool {
	udp, ok := source.(*net.UDPAddr)
	if !ok || udp.IP.To4() == nil || udp.Port < 1 {
		return false
	}
	return udp.IP.IsPrivate() || udp.IP.IsLoopback() || udp.IP.IsLinkLocalUnicast()
}

func cloneAnnouncement(value Announcement) Announcement {
	value.MAC = append(net.HardwareAddr(nil), value.MAC...)
	value.SourceMAC = append(net.HardwareAddr(nil), value.SourceMAC...)
	value.Netmask = append(net.IP(nil), value.Netmask...)
	value.IPv4 = append(net.IP(nil), value.IPv4...)
	value.DeviceMAC = append(net.HardwareAddr(nil), value.DeviceMAC...)
	value.Addresses = append([]Address(nil), value.Addresses...)
	for i := range value.Addresses {
		value.Addresses[i].MAC = append(net.HardwareAddr(nil), value.Addresses[i].MAC...)
		value.Addresses[i].IP = append(net.IP(nil), value.Addresses[i].IP...)
	}
	if value.BoardID != nil {
		copyValue := *value.BoardID
		value.BoardID = &copyValue
	}
	if value.Uptime != nil {
		copyValue := *value.Uptime
		value.Uptime = &copyValue
	}
	if value.IsDefault != nil {
		copyValue := *value.IsDefault
		value.IsDefault = &copyValue
	}
	if value.ControllerUUID != nil {
		copyValue := *value.ControllerUUID
		value.ControllerUUID = &copyValue
	}
	if value.HashID != nil {
		copyValue := *value.HashID
		value.HashID = &copyValue
	}
	if value.AnonID != nil {
		copyValue := *value.AnonID
		value.AnonID = &copyValue
	}
	if value.ProfileUUID != nil {
		copyValue := *value.ProfileUUID
		value.ProfileUUID = &copyValue
	}
	if value.Field2C != nil {
		copyValue := *value.Field2C
		value.Field2C = &copyValue
	}
	if value.Field2D != nil {
		copyValue := *value.Field2D
		value.Field2D = &copyValue
	}
	return value
}
