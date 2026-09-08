//go:build linux

package netagent

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/d3vi1/nut-2-unifi-ups-gateway/internal/netconfig"
)

type Config struct {
	MAC        string
	Mode       string
	StaticCIDR string
	Router     string
}

func (c Config) validate() (net.HardwareAddr, Lease, error) {
	mac, err := net.ParseMAC(c.MAC)
	if err != nil || len(mac) != 6 || mac[0]&1 != 0 || bytes.Equal(mac, make([]byte, 6)) {
		return nil, Lease{}, errors.New("invalid managed MAC")
	}
	if c.Mode == "dhcp" && c.StaticCIDR == "" && c.Router == "" {
		return mac, Lease{}, nil
	}
	if c.Mode != "static" {
		return nil, Lease{}, errors.New("invalid address mode")
	}
	ip, prefix, err := net.ParseCIDR(c.StaticCIDR)
	if err != nil {
		return nil, Lease{}, errors.New("invalid static address")
	}
	bits, _ := prefix.Mask.Size()
	l := Lease{Address: ip.String(), Prefix: bits, Router: c.Router}
	if netconfig.ValidateAddress(l.Address, l.Prefix, l.Router) != nil {
		return nil, Lease{}, errors.New("invalid static network")
	}
	return mac, l, nil
}

type owner struct {
	iface   net.Interface
	lease   Lease
	expires time.Time
	status  netconfig.Status
}

func (o *owner) withdraw() error {
	// Invalidate readers before changing kernel configuration. The gateway's
	// independent guard also checks each send and polls every 100ms.
	if err := os.Remove(netconfig.StatusPath); err != nil && !os.IsNotExist(err) {
		return errors.New("network handoff withdrawal failed")
	}
	if o.lease.Address == "" {
		return nil
	}
	errRoute := defaultRoute(o.iface.Index, o.lease.Router, true)
	errAddr := address(o.iface.Index, o.lease.Address, o.lease.Prefix, 0, true)
	o.lease = Lease{}
	if errRoute != nil || errAddr != nil {
		return errors.New("network withdrawal failed")
	}
	return nil
}

func (o *owner) install(l Lease, expires time.Time) error {
	if err := noOtherSubnetOverlap(o.iface.Index, l); err != nil {
		return err
	}
	if l.Address != o.lease.Address || l.Prefix != o.lease.Prefix || l.Router != o.lease.Router {
		if err := o.withdraw(); err != nil {
			return err
		}
		var nonce [16]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return errors.New("network entropy unavailable")
		}
		o.status = netconfig.Status{Generation: hex.EncodeToString(nonce[:]), Address: l.Address, Prefix: l.Prefix, Router: l.Router}
		if err := address(o.iface.Index, l.Address, l.Prefix, 4, false); err != nil {
			return err
		}
		if err := defaultRoute(o.iface.Index, l.Router, false); err != nil {
			_ = address(o.iface.Index, l.Address, l.Prefix, 0, true)
			return err
		}
	}
	o.lease = l
	o.expires = expires
	return o.heartbeat(time.Now())
}

func (o *owner) heartbeat(now time.Time) error {
	if o.lease.Address == "" {
		return nil
	}
	left := 4 * time.Second
	if !o.expires.IsZero() && o.expires.Sub(now) < left {
		left = o.expires.Sub(now)
	}
	seconds := uint32(left / time.Second)
	if seconds < 1 {
		return o.withdraw()
	}
	if err := address(o.iface.Index, o.lease.Address, o.lease.Prefix, seconds, false); err != nil {
		return err
	}
	o.status.Sequence++
	o.status.ValidUntil = now.Add(time.Duration(seconds)*time.Second - time.Second/2)
	data, err := json.Marshal(o.status)
	if err != nil {
		return errors.New("network handoff encoding failed")
	}
	f, err := os.CreateTemp(filepath.Dir(netconfig.StatusPath), ".status-")
	if err != nil {
		return errors.New("network handoff unavailable")
	}
	name := f.Name()
	defer os.Remove(name)
	if err = f.Chmod(0644); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil || closeErr != nil || os.Rename(name, netconfig.StatusPath) != nil {
		return errors.New("network handoff commit failed")
	}
	return nil
}

func arpPacket(mac net.HardwareAddr, ip net.IP, probe bool) []byte {
	p := make([]byte, 28)
	p[1] = 1
	p[2] = 8
	p[4] = 6
	p[5] = 4
	p[7] = 1
	copy(p[8:14], mac)
	if !probe {
		copy(p[14:18], ip.To4())
	}
	copy(p[24:28], ip.To4())
	return p
}
func arpConflict(p []byte, mac net.HardwareAddr, ip net.IP, probing bool) bool {
	if len(p) < 28 || p[0] != 0 || p[1] != 1 || p[2] != 8 || p[3] != 0 || p[4] != 6 || p[5] != 4 || p[6] != 0 || (p[7] != 1 && p[7] != 2) || bytes.Equal(p[8:14], mac) {
		return false
	}
	return bytes.Equal(p[14:18], ip.To4()) || probing && bytes.Equal(p[14:18], []byte{0, 0, 0, 0}) && bytes.Equal(p[24:28], ip.To4())
}

func probe(ctx context.Context, arp *packetSocket, mac net.HardwareAddr, ip net.IP) error {
	var random [1]byte
	if _, err := rand.Read(random[:]); err != nil {
		return errors.New("network entropy unavailable")
	}
	next := time.Now().Add(time.Duration(random[0]) * time.Second / 256)
	sent := 0
	for ctx.Err() == nil {
		if time.Now().After(next) {
			if sent == 3 {
				return nil
			}
			if err := arp.broadcast(arpPacket(mac, ip, true)); err != nil {
				return err
			}
			sent++
			if _, err := rand.Read(random[:]); err != nil {
				return errors.New("network entropy unavailable")
			}
			next = time.Now().Add(time.Second + time.Duration(random[0])*time.Second/256)
			if sent == 3 {
				next = time.Now().Add(2 * time.Second)
			}
		}
		p, err := arp.read()
		if err != nil {
			return err
		}
		if arpConflict(p, mac, ip, true) {
			return errAddressConflict
		}
	}
	return ctx.Err()
}

// Run never enters another namespace and never reads gateway state or secrets.
// DHCP state is intentionally not reused after restart: acquire a fresh lease.
func Run(ctx context.Context, c Config) error {
	mac, static, err := c.validate()
	if err != nil {
		return err
	}
	iface, err := selectedInterface(mac)
	if err != nil {
		return err
	}
	// Allow the previous helper's four-second kernel lifetime to expire. No
	// persisted lease is used to justify deleting a global interface address.
	if !boundedPause(ctx.Done(), 5*time.Second) {
		return nil
	}
	if err := prepare(iface); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(netconfig.StatusPath), 0755); err != nil {
		return errors.New("network handoff directory unavailable")
	}
	o := owner{iface: iface}
	if err := o.withdraw(); err != nil {
		return err
	}
	defer o.withdraw()
	arp, err := openPacket(iface, 0x0806)
	if err != nil {
		return err
	}
	defer arp.close()
	if c.Mode == "static" {
		if err := probe(ctx, arp, mac, net.ParseIP(static.Address)); err != nil {
			return err
		}
		if err := o.install(static, time.Time{}); err != nil {
			return err
		}
		if err := arp.broadcast(arpPacket(mac, net.ParseIP(static.Address), false)); err != nil {
			return err
		}
		next := time.Now().Add(time.Second)
		for ctx.Err() == nil {
			p, err := arp.read()
			if err != nil {
				return err
			}
			if arpConflict(p, mac, net.ParseIP(static.Address), false) {
				return errAddressConflict
			}
			if time.Now().After(next) {
				if err := o.heartbeat(time.Now()); err != nil {
					return err
				}
				next = time.Now().Add(time.Second)
			}
		}
		return nil
	}
	return runDHCP(ctx, &o, mac, arp)
}

func runDHCP(ctx context.Context, o *owner, mac net.HardwareAddr, arp *packetSocket) error {
	packets, err := openPacket(o.iface, 0x0800)
	if err != nil {
		return err
	}
	defer packets.close()
	// Holding port 68 prevents ICMP port-unreachable responses to DHCP replies.
	// The bounded AF_PACKET parser also accepts pre-address unicast replies.
	lc := net.ListenConfig{Control: func(_, _ string, raw syscall.RawConn) error {
		var optionErr error
		err := raw.Control(func(fd uintptr) {
			optionErr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, o.iface.Name)
		})
		if err != nil {
			return err
		}
		return optionErr
	}}
	udp, err := lc.ListenPacket(ctx, "udp4", "0.0.0.0:68")
	if err != nil {
		return errors.New("DHCP client port unavailable")
	}
	defer udp.Close()
	var xid [4]byte
	phase := "init"
	var offered Lease
	var acquired, attempt, next, heartbeat time.Time
	retry := 4 * time.Second
	for ctx.Err() == nil {
		now := time.Now()
		if o.lease.Address != "" {
			if !now.Before(o.expires) {
				if err := o.withdraw(); err != nil {
					return err
				}
				phase = "init"
				next = time.Time{}
			}
			if now.After(heartbeat) {
				if err := o.heartbeat(now); err != nil {
					return err
				}
				heartbeat = now.Add(time.Second)
				if o.lease.Address == "" {
					phase = "init"
					next = time.Time{}
				}
			}
			if o.lease.Address != "" && now.Sub(acquired) >= o.lease.Rebind && phase != "rebinding" {
				phase = "rebinding"
				next = time.Time{}
				attempt = now
				if _, err := rand.Read(xid[:]); err != nil {
					return errors.New("network entropy unavailable")
				}
			}
			if o.lease.Address != "" && now.Sub(acquired) >= o.lease.Renew && phase == "bound" {
				phase = "renewing"
				next = time.Time{}
				attempt = now
				if _, err := rand.Read(xid[:]); err != nil {
					return errors.New("network entropy unavailable")
				}
			}
			p, err := arp.read()
			if err != nil {
				return err
			}
			if o.lease.Address != "" && arpConflict(p, mac, net.ParseIP(o.lease.Address), false) {
				_ = packets.broadcast(ipv4Broadcast(packet(4, xid, mac, net.ParseIP(o.lease.Address), net.ParseIP(o.lease.Server), nil)))
				return errAddressConflict
			}
		}
		if !now.Before(next) {
			switch phase {
			case "init", "selecting":
				if phase == "init" {
					if _, err := rand.Read(xid[:]); err != nil {
						return errors.New("network entropy unavailable")
					}
					retry = 4 * time.Second
				}
				phase = "selecting"
				attempt = now
				if err := packets.broadcast(ipv4Broadcast(packet(1, xid, mac, nil, nil, nil))); err != nil {
					return err
				}
			case "requesting":
				// Restart discovery after a bounded request timeout.
				phase = "init"
				next = time.Time{}
				continue
			case "renewing", "rebinding":
				msg := packet(3, xid, mac, nil, nil, net.ParseIP(o.lease.Address))
				if phase == "renewing" {
					_ = udp.SetWriteDeadline(now.Add(time.Second))
					_, _ = udp.WriteTo(msg, &net.UDPAddr{IP: net.ParseIP(o.lease.Server), Port: 67})
				} else {
					p := ipv4Broadcast(msg)
					copy(p[12:16], net.ParseIP(o.lease.Address).To4())
					p[10], p[11] = 0, 0
					sum := checksum(p[:20])
					p[10], p[11] = byte(sum>>8), byte(sum)
					if err := packets.broadcast(p); err != nil {
						return err
					}
				}
			}
			next = now.Add(retry)
			if retry < 16*time.Second {
				retry *= 2
			}
		}
		p, err := packets.read()
		if err != nil {
			return err
		}
		payload := dhcpPayload(p)
		if payload == nil {
			continue
		}
		kind, l, err := reply(payload, xid, mac)
		if err != nil {
			continue
		}
		if phase == "selecting" && kind == 2 {
			offered = l
			phase = "requesting"
			attempt = time.Now()
			next = attempt.Add(8 * time.Second)
			if err := packets.broadcast(ipv4Broadcast(packet(3, xid, mac, net.ParseIP(l.Address), net.ParseIP(l.Server), nil))); err != nil {
				return err
			}
			continue
		}
		if phase != "requesting" && phase != "renewing" && phase != "rebinding" {
			continue
		}
		if phase == "requesting" && l.Server != offered.Server || phase == "renewing" && l.Server != o.lease.Server {
			continue
		}
		if kind == 6 {
			if err := o.withdraw(); err != nil {
				return err
			}
			phase = "init"
			next = time.Now().Add(time.Second)
			continue
		}
		if kind != 5 || phase == "requesting" && l.Address != offered.Address {
			continue
		}
		// Changes during renewal are withdrawn first; never keep advertising a
		// previous lease while conflict-probing a new address.
		changed := l.Address != o.lease.Address || l.Prefix != o.lease.Prefix || l.Router != o.lease.Router
		if changed {
			if err := o.withdraw(); err != nil {
				return err
			}
			if err := probe(ctx, arp, mac, net.ParseIP(l.Address)); err != nil {
				if ctx.Err() != nil {
					return nil
				}
				if !errors.Is(err, errAddressConflict) {
					return err
				}
				_ = packets.broadcast(ipv4Broadcast(packet(4, xid, mac, net.ParseIP(l.Address), net.ParseIP(l.Server), nil)))
				if !boundedPause(ctx.Done(), 10*time.Second) {
					return nil
				}
				phase = "init"
				next = time.Time{}
				continue
			}
		}
		expires := attempt.Add(l.Duration)
		if !time.Now().Add(5 * time.Second).Before(expires) {
			phase = "init"
			next = time.Time{}
			continue
		}
		if err := o.install(l, expires); err != nil {
			return err
		}
		acquired = attempt
		phase = "bound"
		next = time.Now().Add(l.Renew)
		retry = 4 * time.Second
		if changed {
			if err := arp.broadcast(arpPacket(mac, net.ParseIP(l.Address), false)); err != nil {
				return err
			}
		}
	}
	return nil
}
