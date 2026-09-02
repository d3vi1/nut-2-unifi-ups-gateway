package discovery

import (
	"errors"
	"net"
)

const (
	USWDA26Platform              = "UPS26"
	USWDA26Hardware              = "UPS 2U"
	USWDA26Model                 = "UPS26"
	USWDA26Firmware              = "UPS2U.esp32.v1.6.1.g5457.260723.0556"
	USWDA26NetworkVersion        = "1.6.1.413"
	USWDA26BoardID        uint16 = 0xda26
	USWDA26Field2C        byte   = 3
	USWDA26Field2D        uint32 = 2
)

var USWDA26ProfileUUID = [16]byte{
	0x31, 0x78, 0x75, 0xca, 0xad, 0x3e, 0x47, 0xe9,
	0x94, 0x30, 0x47, 0xe3, 0xe2, 0xe1, 0xab, 0x3d,
}

// USWDA26Identity contains the dynamic fields in the firmware-proven v2,
// command-6 broadcast. ControllerUUID is optional and must be populated only
// when observed from a trusted controller response after adoption.
type USWDA26Identity struct {
	MAC            net.HardwareAddr
	IP             net.IP
	Hostname       string
	Uptime         uint32
	Sequence       uint32
	IsDefault      bool
	HashID         [8]byte
	AnonID         [16]byte
	ControllerUUID *[16]byte
}

func (i USWDA26Identity) String() string   { return "USWDA26 discovery identity" }
func (i USWDA26Identity) GoString() string { return i.String() }

// NewUSWDA26Announcement creates the exact pending-device discovery
// fingerprint observed in UPS 2U EU firmware 1.6.1 build 413.
func NewUSWDA26Announcement(identity USWDA26Identity) (Announcement, error) {
	if err := validateMAC(identity.MAC); err != nil {
		return Announcement{}, err
	}
	ip := identity.IP.To4()
	if ip == nil {
		return Announcement{}, errors.New("discovery: USWDA26 requires IPv4")
	}
	if !validOptionalASCII(identity.Hostname, 63) || identity.Hostname == "" {
		return Announcement{}, errors.New("discovery: USWDA26 requires a valid hostname")
	}
	if identity.Sequence == 0 {
		return Announcement{}, errors.New("discovery: USWDA26 sequence must be nonzero")
	}
	if zeroBytes(identity.HashID[:]) || zeroBytes(identity.AnonID[:]) {
		return Announcement{}, errors.New("discovery: USWDA26 opaque identities must be nonzero")
	}
	mac := append(net.HardwareAddr(nil), identity.MAC...)
	ip = append(net.IP(nil), ip...)
	profileUUID := USWDA26ProfileUUID
	field2C := USWDA26Field2C
	announcement := Announcement{
		Version: V2, Command: CommandAnnouncement,
		MAC: mac, DeviceMAC: append(net.HardwareAddr(nil), mac...),
		Addresses: []Address{{MAC: append(net.HardwareAddr(nil), mac...), IP: append(net.IP(nil), ip...)}},
		IPv4:      ip, Firmware: USWDA26Firmware,
		Uptime: uint32Pointer(identity.Uptime), Hostname: identity.Hostname,
		Platform: USWDA26Platform, Hardware: USWDA26Hardware,
		BoardID: uint16Pointer(USWDA26BoardID), Sequence: identity.Sequence,
		SourceMAC: append(net.HardwareAddr(nil), mac...), Model: USWDA26Model,
		VersionText: USWDA26NetworkVersion, IsDefault: boolPointer(identity.IsDefault),
		HashID: &identity.HashID, AnonID: &identity.AnonID,
		ProfileUUID: &profileUUID, Field2C: &field2C,
		Field2D: uint32Pointer(USWDA26Field2D),
	}
	if identity.ControllerUUID != nil {
		copyValue := *identity.ControllerUUID
		announcement.ControllerUUID = &copyValue
		announcement.ControllerUUIDBeforeOpaqueIDs = true
	}
	if err := announcement.ValidateIdentity(); err != nil {
		return Announcement{}, err
	}
	return announcement, nil
}
