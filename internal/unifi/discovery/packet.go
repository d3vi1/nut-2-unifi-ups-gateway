// Package discovery implements the bounded, device-side Ubiquiti discovery
// protocol carried over UDP port 10001.
package discovery

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

const (
	Port        = 10001
	MaxDatagram = 8192

	CommandDiscover     = uint8(0)
	CommandAnnouncement = uint8(6)

	MulticastIPv4 = "233.89.188.1"
	BroadcastIPv4 = "255.255.255.255"
)

type Version uint8

const (
	V1 Version = 1
	V2 Version = 2
)

const (
	tlvMAC            = byte(0x01)
	tlvMACIP          = byte(0x02)
	tlvFirmware       = byte(0x03)
	tlvIPv4           = byte(0x04)
	tlvDeviceMAC      = byte(0x05)
	tlvUptime         = byte(0x0a)
	tlvHostname       = byte(0x0b)
	tlvPlatform       = byte(0x0c)
	tlvESSID          = byte(0x0d)
	tlvWMode          = byte(0x0e)
	tlvBoardID        = byte(0x10)
	tlvSequence       = byte(0x12)
	tlvSourceMAC      = byte(0x13)
	tlvHardware       = byte(0x14)
	tlvModel          = byte(0x15) // Model abbreviation, e.g. UPSPROEU.
	tlvVersion        = byte(0x16)
	tlvIsDefault      = byte(0x17)
	tlvControllerUUID = byte(0x26)
	tlvHashID         = byte(0x27)
	tlvAnonID         = byte(0x2a)
	tlvProfileUUID    = byte(0x2b)
	tlvField2C        = byte(0x2c)
	tlvField2D        = byte(0x2d)
	tlvNetmask        = byte(0x35)
)

// Address is the repeatable 0x02 TLV: a six-byte MAC followed by IPv4.
type Address struct {
	MAC net.HardwareAddr
	IP  net.IP
}

// Announcement contains the identity TLVs emitted by a UniFi device. Marshal
// omits optional empty fields but requires a complete core identity.
type Announcement struct {
	Version        Version
	Command        uint8
	MAC            net.HardwareAddr
	Addresses      []Address
	Firmware       string
	IPv4           net.IP
	DeviceMAC      net.HardwareAddr
	Uptime         *uint32
	Hostname       string
	Platform       string
	Hardware       string
	ESSID          string
	WMode          uint32
	BoardID        *uint16
	Sequence       uint32
	SourceMAC      net.HardwareAddr
	Model          string
	VersionText    string
	IsDefault      *bool
	ControllerUUID *[16]byte
	// USWDA26 emits controller UUID before hash/anonymous IDs, while
	// USPDA2C emits it after the v2 fields. This is wire ordering only.
	ControllerUUIDBeforeOpaqueIDs bool
	HashID                        *[8]byte
	AnonID                        *[16]byte
	ProfileUUID                   *[16]byte
	Field2C                       *byte
	Field2D                       *uint32
	Netmask                       net.IP
}

// Query builds the four-byte discovery probe understood by device responders.
func Query(version Version) ([]byte, error) {
	if !supportedVersion(version) {
		return nil, errors.New("discovery: unsupported version")
	}
	return []byte{byte(version), CommandDiscover, 0, 0}, nil
}

// Marshal renders the 4-byte header followed by type-length-value records.
func (a Announcement) Marshal() ([]byte, error) {
	if err := a.ValidateIdentity(); err != nil {
		return nil, err
	}
	var body []byte
	// Preserve the order emitted by the UPS firmware when the corresponding
	// fields are present. Parsers must not depend on ordering.
	if a.Version == V2 && a.Model != "" {
		body = appendTLV(body, tlvModel, []byte(a.Model))
	}
	if a.Platform != "" {
		body = appendTLV(body, tlvPlatform, []byte(a.Platform))
	}
	if a.Hardware != "" {
		body = appendTLV(body, tlvHardware, []byte(a.Hardware))
	}
	if a.Hostname != "" {
		body = appendTLV(body, tlvHostname, []byte(a.Hostname))
	}
	if a.Uptime != nil {
		body = appendU32(body, tlvUptime, *a.Uptime)
	}
	if a.IPv4 != nil {
		body = appendTLV(body, tlvIPv4, a.IPv4.To4())
	}
	for _, address := range a.Addresses {
		ip := address.IP.To4()
		value := make([]byte, 0, 10)
		value = append(value, address.MAC...)
		value = append(value, ip...)
		body = appendTLV(body, tlvMACIP, value)
	}
	body = appendTLV(body, tlvMAC, a.MAC)
	if a.DeviceMAC != nil {
		body = appendTLV(body, tlvDeviceMAC, a.DeviceMAC)
	}
	if a.Firmware != "" {
		body = appendTLV(body, tlvFirmware, []byte(a.Firmware))
	}
	if a.BoardID != nil {
		body = appendU16(body, tlvBoardID, *a.BoardID)
	}
	if a.IsDefault != nil {
		value := byte(0)
		if *a.IsDefault {
			value = 1
		}
		body = appendTLV(body, tlvIsDefault, []byte{value})
	}
	if a.ControllerUUIDBeforeOpaqueIDs && a.ControllerUUID != nil {
		body = appendTLV(body, tlvControllerUUID, a.ControllerUUID[:])
	}
	if a.HashID != nil {
		body = appendTLV(body, tlvHashID, a.HashID[:])
	}
	if a.AnonID != nil {
		body = appendTLV(body, tlvAnonID, a.AnonID[:])
	}
	if a.ESSID != "" {
		body = appendTLV(body, tlvESSID, []byte(a.ESSID))
	}
	if a.WMode != 0 {
		body = appendU32(body, tlvWMode, a.WMode)
	}
	if a.Version == V2 {
		body = appendU32(body, tlvSequence, a.Sequence)
		body = appendTLV(body, tlvSourceMAC, a.SourceMAC)
		if a.VersionText != "" {
			body = appendTLV(body, tlvVersion, []byte(a.VersionText))
		}
		if a.Field2D != nil {
			body = appendU32(body, tlvField2D, *a.Field2D)
		}
		if !a.ControllerUUIDBeforeOpaqueIDs && a.ControllerUUID != nil {
			body = appendTLV(body, tlvControllerUUID, a.ControllerUUID[:])
		}
		if a.ProfileUUID != nil {
			body = appendTLV(body, tlvProfileUUID, a.ProfileUUID[:])
		}
		if a.Field2C != nil {
			body = appendTLV(body, tlvField2C, []byte{*a.Field2C})
		}
	}
	if a.Netmask != nil {
		body = appendTLV(body, tlvNetmask, a.Netmask.To4())
	}
	if len(body) > 0xffff || len(body)+4 > MaxDatagram {
		return nil, errors.New("discovery: announcement exceeds datagram limit")
	}
	out := make([]byte, 4, len(body)+4)
	out[0] = byte(a.Version)
	out[1] = a.Command
	binary.BigEndian.PutUint16(out[2:4], uint16(len(body)))
	return append(out, body...), nil
}

// ValidateIdentity enforces the core fields expected of a device response.
func (a Announcement) ValidateIdentity() error {
	if !supportedVersion(a.Version) {
		return errors.New("discovery: unsupported version")
	}
	if err := validateMAC(a.MAC); err != nil {
		return err
	}
	if len(a.Addresses) == 0 || len(a.Addresses) > 16 {
		return errors.New("discovery: announcement requires 1-16 addresses")
	}
	matchedPrimary := false
	for _, address := range a.Addresses {
		if err := validateMAC(address.MAC); err != nil || address.IP.To4() == nil {
			return errors.New("discovery: invalid MAC/IP address TLV")
		}
		if bytesEqual(address.MAC, a.MAC) && (a.IPv4 == nil || address.IP.To4().Equal(a.IPv4.To4())) {
			matchedPrimary = true
		}
	}
	if !matchedPrimary {
		return errors.New("discovery: no MAC/IP TLV matches the primary identity")
	}
	for _, field := range []string{a.Firmware, a.Hostname, a.Platform, a.Hardware, a.ESSID, a.Model, a.VersionText} {
		if !validOptionalASCII(field, 1024) {
			return errors.New("discovery: invalid text TLV")
		}
	}
	if a.Firmware == "" || a.Hostname == "" || a.Platform == "" {
		return errors.New("discovery: firmware, hostname, and platform are required")
	}
	if a.Netmask != nil && a.Netmask.To4() == nil {
		return errors.New("discovery: netmask is not IPv4")
	}
	if a.IPv4 != nil && a.IPv4.To4() == nil {
		return errors.New("discovery: primary IP is not IPv4")
	}
	if a.DeviceMAC != nil {
		if err := validateMAC(a.DeviceMAC); err != nil {
			return errors.New("discovery: invalid device-MAC TLV")
		}
		if !bytesEqual(a.DeviceMAC, a.MAC) {
			return errors.New("discovery: device-MAC TLV does not match primary identity")
		}
	}
	if a.Version == V2 {
		if a.Sequence == 0 || a.Model == "" {
			return errors.New("discovery: v2 requires sequence and model")
		}
		if err := validateMAC(a.SourceMAC); err != nil {
			return errors.New("discovery: v2 requires a valid source MAC")
		}
		if !bytesEqual(a.SourceMAC, a.MAC) {
			return errors.New("discovery: source MAC does not match primary identity")
		}
	}
	return nil
}

// Parse validates the exact datagram length and decodes known TLVs. Unknown
// TLVs are skipped by their declared length. Use ValidateIdentity on non-query
// packets before treating the result as a device identity.
func Parse(packet []byte) (Announcement, error) {
	if len(packet) < 4 {
		return Announcement{}, errors.New("discovery: truncated header")
	}
	if len(packet) > MaxDatagram {
		return Announcement{}, errors.New("discovery: datagram exceeds limit")
	}
	version := Version(packet[0])
	if !supportedVersion(version) {
		return Announcement{}, errors.New("discovery: unsupported version")
	}
	bodyLen := int(binary.BigEndian.Uint16(packet[2:4]))
	if bodyLen != len(packet)-4 {
		return Announcement{}, errors.New("discovery: declared body length does not match datagram")
	}
	a := Announcement{Version: version, Command: packet[1]}
	seen := make(map[byte]struct{})
	body := packet[4:]
	for len(body) > 0 {
		if len(body) < 3 {
			return Announcement{}, errors.New("discovery: truncated TLV header")
		}
		typeID := body[0]
		valueLen := int(binary.BigEndian.Uint16(body[1:3]))
		if valueLen > len(body)-3 {
			return Announcement{}, errors.New("discovery: TLV overruns datagram")
		}
		value := body[3 : 3+valueLen]
		body = body[3+valueLen:]
		if singletonTLV(typeID) {
			if _, duplicate := seen[typeID]; duplicate {
				return Announcement{}, errors.New("discovery: duplicate singleton TLV")
			}
			seen[typeID] = struct{}{}
		}
		switch typeID {
		case tlvMAC:
			if len(value) != 6 {
				return Announcement{}, errors.New("discovery: invalid MAC TLV length")
			}
			a.MAC = cloneMAC(value)
		case tlvMACIP:
			if len(value) != 10 || len(a.Addresses) >= 16 {
				return Announcement{}, errors.New("discovery: invalid MAC/IP TLV")
			}
			a.Addresses = append(a.Addresses, Address{MAC: cloneMAC(value[:6]), IP: cloneIP(value[6:])})
		case tlvFirmware:
			if !validOptionalASCIIBytes(value, 1024) {
				return Announcement{}, errors.New("discovery: invalid firmware TLV")
			}
			a.Firmware = string(value)
		case tlvIPv4:
			if len(value) != 4 {
				return Announcement{}, errors.New("discovery: invalid primary-IPv4 TLV length")
			}
			a.IPv4 = cloneIP(value)
		case tlvDeviceMAC:
			if len(value) != 6 {
				return Announcement{}, errors.New("discovery: invalid device-MAC TLV length")
			}
			a.DeviceMAC = cloneMAC(value)
		case tlvUptime:
			if len(value) != 4 {
				return Announcement{}, errors.New("discovery: invalid uptime TLV length")
			}
			a.Uptime = uint32Pointer(binary.BigEndian.Uint32(value))
		case tlvHostname:
			if !validOptionalASCIIBytes(value, 1024) {
				return Announcement{}, errors.New("discovery: invalid hostname TLV")
			}
			a.Hostname = string(value)
		case tlvPlatform:
			if !validOptionalASCIIBytes(value, 1024) {
				return Announcement{}, errors.New("discovery: invalid platform TLV")
			}
			a.Platform = string(value)
		case tlvESSID:
			if !validOptionalASCIIBytes(value, 1024) {
				return Announcement{}, errors.New("discovery: invalid ESSID TLV")
			}
			a.ESSID = string(value)
		case tlvWMode:
			if len(value) != 4 {
				return Announcement{}, errors.New("discovery: invalid wireless-mode TLV length")
			}
			a.WMode = binary.BigEndian.Uint32(value)
		case tlvBoardID:
			if len(value) != 2 {
				return Announcement{}, errors.New("discovery: invalid board-ID TLV length")
			}
			a.BoardID = uint16Pointer(binary.BigEndian.Uint16(value))
		case tlvSequence:
			if version != V2 || len(value) != 4 {
				return Announcement{}, errors.New("discovery: invalid sequence TLV")
			}
			a.Sequence = binary.BigEndian.Uint32(value)
		case tlvSourceMAC:
			if version != V2 || len(value) != 6 {
				return Announcement{}, errors.New("discovery: invalid source-MAC TLV")
			}
			a.SourceMAC = cloneMAC(value)
		case tlvHardware:
			if !validOptionalASCIIBytes(value, 1024) {
				return Announcement{}, errors.New("discovery: invalid hardware TLV")
			}
			a.Hardware = string(value)
		case tlvModel:
			if version != V2 || !validOptionalASCIIBytes(value, 1024) {
				return Announcement{}, errors.New("discovery: invalid model TLV")
			}
			a.Model = string(value)
		case tlvVersion:
			if version != V2 || !validOptionalASCIIBytes(value, 1024) {
				return Announcement{}, errors.New("discovery: invalid version TLV")
			}
			a.VersionText = string(value)
		case tlvIsDefault:
			if len(value) != 1 || value[0] > 1 {
				return Announcement{}, errors.New("discovery: invalid is-default TLV")
			}
			a.IsDefault = boolPointer(value[0] == 1)
		case tlvControllerUUID:
			if version != V2 || len(value) != 16 {
				return Announcement{}, errors.New("discovery: invalid controller-UUID TLV")
			}
			var controllerUUID [16]byte
			copy(controllerUUID[:], value)
			a.ControllerUUID = &controllerUUID
		case tlvHashID:
			if len(value) != 8 {
				return Announcement{}, errors.New("discovery: invalid hash-ID TLV")
			}
			var hashID [8]byte
			copy(hashID[:], value)
			a.HashID = &hashID
		case tlvAnonID:
			if len(value) != 16 {
				return Announcement{}, errors.New("discovery: invalid anonymous-ID TLV")
			}
			var anonID [16]byte
			copy(anonID[:], value)
			a.AnonID = &anonID
		case tlvProfileUUID:
			if version != V2 || len(value) != 16 {
				return Announcement{}, errors.New("discovery: invalid profile-UUID TLV")
			}
			var profileUUID [16]byte
			copy(profileUUID[:], value)
			a.ProfileUUID = &profileUUID
		case tlvField2C:
			if version != V2 || len(value) != 1 {
				return Announcement{}, errors.New("discovery: invalid 0x2c TLV")
			}
			a.Field2C = bytePointer(value[0])
		case tlvField2D:
			if version != V2 || len(value) != 4 {
				return Announcement{}, errors.New("discovery: invalid 0x2d TLV")
			}
			a.Field2D = uint32Pointer(binary.BigEndian.Uint32(value))
		case tlvNetmask:
			if len(value) != 4 {
				return Announcement{}, errors.New("discovery: invalid netmask TLV length")
			}
			a.Netmask = cloneIP(value)
		}
	}
	return a, nil
}

func appendTLV(dst []byte, typeID byte, value []byte) []byte {
	dst = append(dst, typeID, byte(len(value)>>8), byte(len(value)))
	return append(dst, value...)
}

func appendU32(dst []byte, typeID byte, value uint32) []byte {
	var encoded [4]byte
	binary.BigEndian.PutUint32(encoded[:], value)
	return appendTLV(dst, typeID, encoded[:])
}

func appendU16(dst []byte, typeID byte, value uint16) []byte {
	var encoded [2]byte
	binary.BigEndian.PutUint16(encoded[:], value)
	return appendTLV(dst, typeID, encoded[:])
}

func supportedVersion(version Version) bool {
	return version == V1 || version == V2
}

func singletonTLV(typeID byte) bool {
	switch typeID {
	case tlvMAC, tlvFirmware, tlvIPv4, tlvDeviceMAC, tlvUptime, tlvHostname,
		tlvPlatform, tlvESSID, tlvWMode, tlvBoardID, tlvSequence, tlvSourceMAC,
		tlvHardware, tlvModel, tlvVersion, tlvIsDefault, tlvControllerUUID,
		tlvHashID, tlvAnonID, tlvProfileUUID, tlvField2C, tlvField2D, tlvNetmask:
		return true
	default:
		return false
	}
}

func boolPointer(value bool) *bool       { return &value }
func bytePointer(value byte) *byte       { return &value }
func uint16Pointer(value uint16) *uint16 { return &value }
func uint32Pointer(value uint32) *uint32 { return &value }

func validateMAC(mac net.HardwareAddr) error {
	if len(mac) != 6 || mac[0]&1 != 0 {
		return errors.New("discovery: MAC must be a six-byte unicast address")
	}
	var nonzero byte
	for _, b := range mac {
		nonzero |= b
	}
	if nonzero == 0 {
		return errors.New("discovery: MAC must not be all zeroes")
	}
	return nil
}

func validOptionalASCII(value string, max int) bool {
	return validOptionalASCIIBytes([]byte(value), max)
}

func validOptionalASCIIBytes(value []byte, max int) bool {
	if len(value) > max {
		return false
	}
	for _, b := range value {
		if b < 0x20 || b > 0x7e {
			return false
		}
	}
	return true
}

func cloneMAC(value []byte) net.HardwareAddr {
	return net.HardwareAddr(append([]byte(nil), value...))
}

func cloneIP(value []byte) net.IP {
	return net.IP(append([]byte(nil), value...))
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var difference byte
	for i := range a {
		difference |= a[i] ^ b[i]
	}
	return difference == 0
}

// String deliberately exposes no identity fields. It makes accidental logging
// of a parsed announcement non-sensitive.
func (a Announcement) String() string {
	return fmt.Sprintf("discovery announcement v%d command=%d addresses=%d", a.Version, a.Command, len(a.Addresses))
}

func (a Announcement) GoString() string { return a.String() }
