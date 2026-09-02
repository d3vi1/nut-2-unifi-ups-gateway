package discovery

import (
	"errors"
	"net"
)

const (
	USPDA2CPlatform              = "esp32s3"
	USPDA2CHardware              = "ESP32-S3"
	USPDA2CModel                 = "UPSPROEU"
	USPDA2CNetworkVersion        = "1.6.1.4933"
	USPDA2CBoardID        uint16 = 0xda2c
	USPDA2CField2D        uint32 = 2
)

// USPDA2CIdentity contains the dynamic fields in the firmware-proven v2,
// command-6 broadcast. HashID and AnonID are opaque fixed-width identities;
// callers must generate and persist them without logging them.
type USPDA2CIdentity struct {
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

func (i USPDA2CIdentity) String() string   { return "USPDA2C discovery identity" }
func (i USPDA2CIdentity) GoString() string { return i.String() }

// NewUSPDA2CAnnouncement creates the exact core discovery fingerprint observed
// in UPS 2U Pro EU firmware 1.6.1 build 4933. It emits v2 command 6 and is meant
// for IPv4 broadcast; no multicast destination is implied by this value.
func NewUSPDA2CAnnouncement(identity USPDA2CIdentity) (Announcement, error) {
	if err := validateMAC(identity.MAC); err != nil {
		return Announcement{}, err
	}
	ip := identity.IP.To4()
	if ip == nil {
		return Announcement{}, errors.New("discovery: USPDA2C requires IPv4")
	}
	if !validOptionalASCII(identity.Hostname, 63) || identity.Hostname == "" {
		return Announcement{}, errors.New("discovery: USPDA2C requires a valid hostname")
	}
	if identity.Sequence == 0 {
		return Announcement{}, errors.New("discovery: USPDA2C sequence must be nonzero")
	}
	if zeroBytes(identity.HashID[:]) || zeroBytes(identity.AnonID[:]) {
		return Announcement{}, errors.New("discovery: USPDA2C opaque identities must be nonzero")
	}
	mac := append(net.HardwareAddr(nil), identity.MAC...)
	ip = append(net.IP(nil), ip...)
	announcement := Announcement{
		Version: V2, Command: CommandAnnouncement,
		MAC: mac, DeviceMAC: append(net.HardwareAddr(nil), mac...),
		Addresses: []Address{{MAC: append(net.HardwareAddr(nil), mac...), IP: append(net.IP(nil), ip...)}},
		IPv4:      ip, Firmware: USPDA2CNetworkVersion,
		Uptime: uint32Pointer(identity.Uptime), Hostname: identity.Hostname,
		Platform: USPDA2CPlatform, Hardware: USPDA2CHardware,
		BoardID: uint16Pointer(USPDA2CBoardID), Sequence: identity.Sequence,
		SourceMAC: append(net.HardwareAddr(nil), mac...), Model: USPDA2CModel,
		VersionText: USPDA2CNetworkVersion, IsDefault: boolPointer(identity.IsDefault),
		HashID: &identity.HashID, AnonID: &identity.AnonID,
		Field2D: uint32Pointer(USPDA2CField2D),
	}
	if identity.ControllerUUID != nil {
		copyValue := *identity.ControllerUUID
		announcement.ControllerUUID = &copyValue
	}
	if err := announcement.ValidateIdentity(); err != nil {
		return Announcement{}, err
	}
	return announcement, nil
}

func zeroBytes(value []byte) bool {
	var accumulator byte
	for _, b := range value {
		accumulator |= b
	}
	return accumulator == 0
}
