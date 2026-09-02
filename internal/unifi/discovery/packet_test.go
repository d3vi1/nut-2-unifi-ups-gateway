package discovery

import (
	"bytes"
	"encoding/binary"
	"net"
	"strings"
	"testing"
)

func sampleAnnouncement() Announcement {
	mac, _ := net.ParseMAC("02:11:22:33:44:55")
	return Announcement{
		Version: V2, Command: CommandAnnouncement, MAC: mac,
		Addresses: []Address{{MAC: mac, IP: net.IPv4(192, 0, 2, 20)}},
		Firmware:  "USWDA26.v1.6.1", Uptime: uint32Pointer(900), Hostname: "n2u-test",
		Platform: ModelUPS2U, Sequence: 7, SourceMAC: mac, Model: ModelUPS2U,
		Netmask: net.IPv4(255, 255, 255, 0),
	}
}

const ModelUPS2U = "USWDA26"

func TestQueryWireBytes(t *testing.T) {
	for _, version := range []Version{V1, V2} {
		packet, err := Query(version)
		if err != nil {
			t.Fatal(err)
		}
		want := []byte{byte(version), 0, 0, 0}
		if !bytes.Equal(packet, want) {
			t.Fatalf("v%d query = %x, want %x", version, packet, want)
		}
	}
	if _, err := Query(3); err == nil {
		t.Fatal("unsupported query version accepted")
	}
}

func TestV2MarshalParseRoundTrip(t *testing.T) {
	in := sampleAnnouncement()
	packet, err := in.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if packet[0] != 2 || packet[1] != CommandAnnouncement || int(binary.BigEndian.Uint16(packet[2:4])) != len(packet)-4 {
		t.Fatalf("invalid discovery header: %x", packet[:4])
	}
	out, err := Parse(packet)
	if err != nil {
		t.Fatal(err)
	}
	if err := out.ValidateIdentity(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out.MAC, in.MAC) || !bytes.Equal(out.SourceMAC, in.SourceMAC) || out.Sequence != in.Sequence || out.Model != in.Model || out.Firmware != in.Firmware || out.Hostname != in.Hostname || out.Platform != in.Platform || out.Uptime == nil || *out.Uptime != *in.Uptime {
		t.Fatalf("round trip lost identity: in=%s out=%s", in.String(), out.String())
	}
	if len(out.Addresses) != 1 || !out.Addresses[0].IP.Equal(in.Addresses[0].IP) || !out.Netmask.Equal(in.Netmask) {
		t.Fatalf("round trip lost network fields: %s", out.String())
	}
}

func TestV1MarshalOmitsV2Fields(t *testing.T) {
	in := sampleAnnouncement()
	in.Version = V1
	in.Command = CommandDiscover
	packet, err := in.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	out, err := Parse(packet)
	if err != nil {
		t.Fatal(err)
	}
	if out.Version != V1 || out.Sequence != 0 || out.SourceMAC != nil || out.Model != "" {
		t.Fatalf("v2-only fields leaked into v1: %s", out.String())
	}
}

func TestUSPDA2CFirmwareDiscoveryShape(t *testing.T) {
	mac, _ := net.ParseMAC("02:11:22:33:44:55")
	hashID := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	anonID := [16]byte{1, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 1, 2, 3, 4, 5}
	controllerUUID := [16]byte{9, 8, 7, 6, 5, 4, 3, 2, 1, 9, 8, 7, 6, 5, 4, 3}
	announcement, err := NewUSPDA2CAnnouncement(USPDA2CIdentity{
		MAC: mac, IP: net.IPv4(192, 0, 2, 20), Hostname: "n2u-ups",
		Uptime: 0, Sequence: 1, IsDefault: true, HashID: hashID, AnonID: anonID,
		ControllerUUID: &controllerUUID,
	})
	if err != nil {
		t.Fatal(err)
	}
	packet, err := announcement.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if packet[0] != 2 || packet[1] != 6 {
		t.Fatalf("USPDA2C discovery header = %x, want v2 command6", packet[:4])
	}
	wantOrder := []byte{
		tlvModel, tlvPlatform, tlvHardware, tlvHostname, tlvUptime, tlvIPv4,
		tlvMACIP, tlvMAC, tlvDeviceMAC, tlvFirmware, tlvBoardID, tlvIsDefault,
		tlvHashID, tlvAnonID, tlvSequence, tlvSourceMAC, tlvVersion, tlvField2D, tlvControllerUUID,
	}
	if got := tlvOrder(t, packet); !bytes.Equal(got, wantOrder) {
		t.Fatalf("USPDA2C TLV order = %x, want %x", got, wantOrder)
	}
	parsed, err := Parse(packet)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Model != "UPSPROEU" || parsed.Platform != "esp32s3" || parsed.Hardware != "ESP32-S3" ||
		parsed.Firmware != "1.6.1.4933" || parsed.VersionText != "1.6.1.4933" {
		t.Fatalf("wrong USPDA2C text fingerprint: %s", parsed.String())
	}
	if parsed.Uptime == nil || *parsed.Uptime != 0 || parsed.BoardID == nil || *parsed.BoardID != 0xda2c ||
		parsed.IsDefault == nil || !*parsed.IsDefault || parsed.Field2D == nil || *parsed.Field2D != 2 {
		t.Fatalf("wrong USPDA2C numeric fingerprint: %s", parsed.String())
	}
	if parsed.HashID == nil || *parsed.HashID != hashID || parsed.AnonID == nil || *parsed.AnonID != anonID ||
		parsed.ControllerUUID == nil || *parsed.ControllerUUID != controllerUUID ||
		!parsed.IPv4.Equal(net.IPv4(192, 0, 2, 20)) || !bytes.Equal(parsed.DeviceMAC, mac) {
		t.Fatalf("wrong USPDA2C fixed identity fields: %s", parsed.String())
	}
}

func TestUSPDA2CRejectsMissingOpaqueIdentity(t *testing.T) {
	mac, _ := net.ParseMAC("02:11:22:33:44:55")
	_, err := NewUSPDA2CAnnouncement(USPDA2CIdentity{
		MAC: mac, IP: net.IPv4(192, 0, 2, 20), Hostname: "n2u-ups", Sequence: 1,
	})
	if err == nil {
		t.Fatal("all-zero hash/anonymous IDs accepted")
	}
}

func TestUSWDA26FirmwareDiscoveryShape(t *testing.T) {
	mac, _ := net.ParseMAC("02:11:22:33:44:55")
	hashID := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	anonID := [16]byte{1, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 1, 2, 3, 4, 5}
	controllerUUID := [16]byte{9, 8, 7, 6, 5, 4, 3, 2, 1, 9, 8, 7, 6, 5, 4, 3}
	announcement, err := NewUSWDA26Announcement(USWDA26Identity{
		MAC: mac, IP: net.IPv4(192, 0, 2, 20), Hostname: "n2u-ups",
		Uptime: 42, Sequence: 7, IsDefault: true, HashID: hashID, AnonID: anonID,
		ControllerUUID: &controllerUUID,
	})
	if err != nil {
		t.Fatal(err)
	}
	packet, err := announcement.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	wantOrder := []byte{
		tlvModel, tlvPlatform, tlvHardware, tlvHostname, tlvUptime, tlvIPv4,
		tlvMACIP, tlvMAC, tlvDeviceMAC, tlvFirmware, tlvBoardID, tlvIsDefault,
		tlvControllerUUID, tlvHashID, tlvAnonID, tlvSequence, tlvSourceMAC, tlvVersion, tlvField2D,
		tlvProfileUUID, tlvField2C,
	}
	if got := tlvOrder(t, packet); !bytes.Equal(got, wantOrder) {
		t.Fatalf("USWDA26 TLV order = %x, want %x", got, wantOrder)
	}
	parsed, err := Parse(packet)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Model != "UPS26" || parsed.Platform != "UPS26" || parsed.Hardware != "UPS 2U" ||
		parsed.Firmware != "UPS2U.esp32.v1.6.1.g5457.260723.0556" || parsed.VersionText != "1.6.1.413" {
		t.Fatalf("wrong USWDA26 text fingerprint: %s", parsed.String())
	}
	if parsed.BoardID == nil || *parsed.BoardID != 0xda26 || parsed.Field2D == nil || *parsed.Field2D != 2 ||
		parsed.Field2C == nil || *parsed.Field2C != 3 || parsed.ProfileUUID == nil || *parsed.ProfileUUID != USWDA26ProfileUUID ||
		parsed.ControllerUUID == nil || *parsed.ControllerUUID != controllerUUID {
		t.Fatalf("wrong USWDA26 numeric/profile fingerprint: %s", parsed.String())
	}
}

func TestParseSkipsRepeatedUnknownTLVs(t *testing.T) {
	body := []byte{0x7f, 0, 1, 0xaa, 0x7f, 0, 1, 0xbb}
	packet := append([]byte{1, 0, 0, byte(len(body))}, body...)
	parsed, err := Parse(packet)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Version != V1 || parsed.Command != 0 {
		t.Fatalf("query header lost: %s", parsed.String())
	}
}

func TestParseRejectsAmbiguousOrMalformedPackets(t *testing.T) {
	mac := []byte{2, 1, 2, 3, 4, 5}
	duplicateMACBody := appendTLV(nil, tlvMAC, mac)
	duplicateMACBody = appendTLV(duplicateMACBody, tlvMAC, mac)
	duplicateMAC := append([]byte{1, 0, 0, byte(len(duplicateMACBody))}, duplicateMACBody...)
	truncatedTLV := []byte{1, 0, 0, 4, tlvMAC, 0, 6, 2}
	v2FieldInV1Body := appendU32(nil, tlvSequence, 1)
	v2FieldInV1 := append([]byte{1, 0, 0, byte(len(v2FieldInV1Body))}, v2FieldInV1Body...)
	tests := [][]byte{
		{1, 0},
		{3, 0, 0, 0},
		{1, 0, 0, 1},
		truncatedTLV,
		duplicateMAC,
		v2FieldInV1,
	}
	for index, packet := range tests {
		if _, err := Parse(packet); err == nil {
			t.Fatalf("malformed packet %d accepted: %x", index, packet)
		}
	}
}

func TestV2RequiresSequenceSourceAndModel(t *testing.T) {
	for name, mutate := range map[string]func(*Announcement){
		"sequence": func(a *Announcement) { a.Sequence = 0 },
		"source":   func(a *Announcement) { a.SourceMAC = nil },
		"model":    func(a *Announcement) { a.Model = "" },
		"mismatched source": func(a *Announcement) {
			a.SourceMAC = net.HardwareAddr{2, 1, 2, 3, 4, 6}
		},
		"mismatched identity IP": func(a *Announcement) {
			a.IPv4 = net.IPv4(192, 0, 2, 21)
		},
	} {
		t.Run(name, func(t *testing.T) {
			a := sampleAnnouncement()
			mutate(&a)
			if _, err := a.Marshal(); err == nil {
				t.Fatal("incomplete v2 identity accepted")
			}
		})
	}
}

func TestStringRedactsIdentity(t *testing.T) {
	a := sampleAnnouncement()
	text := a.String()
	if strings.Contains(text, a.MAC.String()) || strings.Contains(text, a.Hostname) || strings.Contains(text, a.Model) {
		t.Fatalf("String leaked identity: %q", text)
	}
}

func FuzzParseDoesNotPanic(f *testing.F) {
	f.Add([]byte{1, 0, 0, 0})
	f.Add([]byte{2, 0, 0, 0})
	f.Add([]byte{1, 0, 0, 4, tlvMAC, 0, 6, 2})
	f.Fuzz(func(t *testing.T, packet []byte) {
		_, _ = Parse(packet)
	})
}

func tlvOrder(t *testing.T, packet []byte) []byte {
	t.Helper()
	body := packet[4:]
	var order []byte
	for len(body) > 0 {
		if len(body) < 3 {
			t.Fatal("truncated TLV while reading test packet")
		}
		length := int(binary.BigEndian.Uint16(body[1:3]))
		if length > len(body)-3 {
			t.Fatal("overrunning TLV while reading test packet")
		}
		order = append(order, body[0])
		body = body[3+length:]
	}
	return order
}
