package inform

import (
	"bytes"
	"crypto/aes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"testing"
)

var codecTestMAC = [6]byte{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}

func TestCBCHeaderOffsetsAndRoundTrip(t *testing.T) {
	randomBytes := make([]byte, 8+16)
	for i := range randomBytes {
		randomBytes[i] = byte(i + 1)
	}
	encoder, err := newEncoder(bytes.NewReader(randomBytes), DefaultCodecLimits(), PacketVersion)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := encoder.Encode(Packet{MAC: codecTestMAC, Payload: []byte(`{"_type":"inform"}`)}, DefaultKey, ModeCBC)
	if err != nil {
		t.Fatal(err)
	}
	if string(wire[0:4]) != "TNBU" {
		t.Fatalf("magic at 0..3 = %q", wire[0:4])
	}
	if got := binary.BigEndian.Uint32(wire[4:8]); got != 0 {
		t.Fatalf("packet_version at 4..7 = %d, want firmware-required 0", got)
	}
	if !bytes.Equal(wire[8:14], codecTestMAC[:]) {
		t.Fatal("MAC is not at 8..13")
	}
	if got := binary.BigEndian.Uint16(wire[14:16]); got != flagEncrypted {
		t.Fatalf("flags at 14..15 = %#x", got)
	}
	if !bytes.Equal(wire[16:32], randomBytes[8:24]) {
		t.Fatal("IV is not at 16..31")
	}
	if got := binary.BigEndian.Uint32(wire[32:36]); got != 1 {
		t.Fatalf("payload_version at 32..35 = %d, want 1", got)
	}
	if got := int(binary.BigEndian.Uint32(wire[36:40])); got != len(wire)-HeaderLength {
		t.Fatalf("body length at 36..39 = %d, actual %d", got, len(wire)-HeaderLength)
	}

	decoded, err := (Decoder{Limits: DefaultCodecLimits(), ExpectedMAC: &codecTestMAC}).Decode(wire, DefaultKey)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.PacketVersion != 0 || string(decoded.Payload) != `{"_type":"inform"}` {
		t.Fatalf("unexpected decoded packet: version=%d payload=%q", decoded.PacketVersion, decoded.Payload)
	}
}

func TestCBCMatchesIndependentOpenSSLVector(t *testing.T) {
	randomBytes := append(make([]byte, 8), []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	}...)
	encoder, err := newEncoder(bytes.NewReader(randomBytes), DefaultCodecLimits(), PacketVersion)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := encoder.Encode(Packet{MAC: codecTestMAC, Payload: []byte(`{"_type":"noop"}`)}, DefaultKey, ModeCBC)
	if err != nil {
		t.Fatal(err)
	}
	const fixture = "544e4255000000000211223344550001000102030405060708090a0b0c0d0e0f00000001000000201dceec939d8b40363e346590b0c94fa39086870ca8f2496b449b7740a54044c1"
	if got := hex.EncodeToString(wire); got != fixture {
		t.Fatalf("CBC wire vector = %s, want %s", got, fixture)
	}
}

func TestPacketVersionOneIsRejected(t *testing.T) {
	if _, err := newEncoder(bytes.NewReader(make([]byte, 8)), DefaultCodecLimits(), 1); err == nil {
		t.Fatal("firmware-incompatible packet version 1 encoder accepted")
	}
}

func TestGCMNonceMonotonicAndAuthenticated(t *testing.T) {
	encoder, err := newEncoder(bytes.NewReader(make([]byte, 8)), DefaultCodecLimits(), PacketVersion)
	if err != nil {
		t.Fatal(err)
	}
	a, err := encoder.Encode(Packet{MAC: codecTestMAC, Payload: []byte(`{"n":1}`)}, DefaultKey, ModeGCM)
	if err != nil {
		t.Fatal(err)
	}
	b, err := encoder.Encode(Packet{MAC: codecTestMAC, Payload: []byte(`{"n":2}`)}, DefaultKey, ModeGCM)
	if err != nil {
		t.Fatal(err)
	}
	if binary.BigEndian.Uint64(a[24:32]) != 1 || binary.BigEndian.Uint64(b[24:32]) != 2 {
		t.Fatalf("nonces are not monotonic: %x %x", a[16:32], b[16:32])
	}
	decoded, err := Decode(a, DefaultKey)
	if err != nil {
		t.Fatal(err)
	}
	nonce, ok := decoded.AuthenticatedGCMNonce()
	if !ok || !bytes.Equal(nonce[:], a[16:32]) {
		t.Fatalf("authenticated GCM nonce = %x, %t; want header nonce", nonce, ok)
	}
	if got := binary.BigEndian.Uint16(a[14:16]); got != flagEncrypted|flagGCM {
		t.Fatalf("GCM flags = %#x, want firmware-required %#x", got, flagEncrypted|flagGCM)
	}
	tampered := append([]byte(nil), a...)
	tampered[8] ^= 0x02 // keep it unicast but invalidate GCM header AAD.
	if _, err := Decode(tampered, DefaultKey); err == nil || !strings.Contains(err.Error(), "authentication failed") {
		t.Fatalf("tampered GCM header accepted: %v", err)
	}
}

func TestConcurrentGCMNoncesAreUnique(t *testing.T) {
	encoder, err := newEncoder(bytes.NewReader(make([]byte, 8)), DefaultCodecLimits(), PacketVersion)
	if err != nil {
		t.Fatal(err)
	}
	const count = 128
	nonces := make(chan string, count)
	errs := make(chan error, count)
	var group sync.WaitGroup
	for range count {
		group.Add(1)
		go func() {
			defer group.Done()
			wire, err := encoder.Encode(Packet{MAC: codecTestMAC, Payload: []byte(`{}`)}, DefaultKey, ModeGCM)
			if err != nil {
				errs <- err
				return
			}
			nonces <- string(wire[16:32])
		}()
	}
	group.Wait()
	close(errs)
	close(nonces)
	for err := range errs {
		t.Fatal(err)
	}
	seen := make(map[string]struct{}, count)
	for nonce := range nonces {
		if _, duplicate := seen[nonce]; duplicate {
			t.Fatal("GCM nonce was reused")
		}
		seen[nonce] = struct{}{}
	}
	if len(seen) != count {
		t.Fatalf("got %d unique nonces, want %d", len(seen), count)
	}
}

func TestGCMNonceSequenceFailsClosedAtWrap(t *testing.T) {
	encoder, err := newEncoder(bytes.NewReader(make([]byte, 8)), DefaultCodecLimits(), PacketVersion)
	if err != nil {
		t.Fatal(err)
	}
	encoder.gcmNext = ^uint64(0)
	if _, err := encoder.Encode(Packet{MAC: codecTestMAC, Payload: []byte(`{}`)}, DefaultKey, ModeGCM); err != nil {
		t.Fatalf("last unique nonce rejected: %v", err)
	}
	if _, err := encoder.Encode(Packet{MAC: codecTestMAC, Payload: []byte(`{}`)}, DefaultKey, ModeGCM); err == nil {
		t.Fatal("wrapped GCM nonce sequence was reused")
	}
}

func TestDecodeRejectsVersionsFlagsLengthsAndMAC(t *testing.T) {
	encoder, err := newEncoder(bytes.NewReader(make([]byte, 24)), DefaultCodecLimits(), PacketVersion)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := encoder.Encode(Packet{MAC: codecTestMAC, Payload: []byte(`{}`)}, DefaultKey, ModeCBC)
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]func([]byte){
		"packet version":    func(v []byte) { binary.BigEndian.PutUint32(v[4:8], 2) },
		"payload version":   func(v []byte) { binary.BigEndian.PutUint32(v[32:36], 0) },
		"unknown flag":      func(v []byte) { v[15] |= 0x80 },
		"missing encrypted": func(v []byte) { v[15] &^= byte(flagEncrypted) },
		"multicast MAC":     func(v []byte) { v[8] |= 1 },
		"wrong length":      func(v []byte) { binary.BigEndian.PutUint32(v[36:40], uint32(len(v))) },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			bad := append([]byte(nil), wire...)
			mutate(bad)
			if _, err := Decode(bad, DefaultKey); err == nil {
				t.Fatal("malformed packet accepted")
			}
		})
	}
	if _, err := Decode(append(wire, 0), DefaultKey); err == nil {
		t.Fatal("packet with trailing bytes accepted")
	}
	other := codecTestMAC
	other[5]++
	if _, err := (Decoder{Limits: DefaultCodecLimits(), ExpectedMAC: &other}).Decode(wire, DefaultKey); err == nil {
		t.Fatal("reply for another MAC accepted")
	}
}

func TestDecodeBoundsPlaintext(t *testing.T) {
	encoder, err := newEncoder(bytes.NewReader(make([]byte, 24)), DefaultCodecLimits(), PacketVersion)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := encoder.Encode(Packet{MAC: codecTestMAC, Payload: bytes.Repeat([]byte("A"), 4096)}, DefaultKey, ModeCBC)
	if err != nil {
		t.Fatal(err)
	}
	_, err = (Decoder{Limits: Limits{MaxWireBody: 1 << 20, MaxPlaintext: 64}}).Decode(wire, DefaultKey)
	if err == nil || !strings.Contains(err.Error(), "plaintext exceeds") {
		t.Fatalf("plaintext limit was not enforced: %v", err)
	}
}

func TestDecodeRequiresExpectedEncryptionMode(t *testing.T) {
	encoder, err := newEncoder(bytes.NewReader(make([]byte, 24)), DefaultCodecLimits(), PacketVersion)
	if err != nil {
		t.Fatal(err)
	}
	for _, encodedMode := range []Mode{ModeCBC, ModeGCM} {
		wire, err := encoder.Encode(Packet{MAC: codecTestMAC, Payload: []byte(`{}`)}, DefaultKey, encodedMode)
		if err != nil {
			t.Fatal(err)
		}
		expectedMode := ModeGCM
		if encodedMode == ModeGCM {
			expectedMode = ModeCBC
		}
		if _, err := (Decoder{ExpectedMode: &expectedMode}).Decode(wire, DefaultKey); err == nil {
			t.Fatalf("mode %d packet accepted as mode %d", encodedMode, expectedMode)
		}
	}
}

func TestPKCS7ChecksWholePadding(t *testing.T) {
	valid := append(bytes.Repeat([]byte{0x41}, 12), 4, 4, 4, 4)
	plain, err := stripPKCS7(valid)
	if err != nil || len(plain) != 12 {
		t.Fatalf("valid padding rejected: %v", err)
	}
	for _, bad := range [][]byte{
		append(bytes.Repeat([]byte{0x41}, 15), 0),
		append(bytes.Repeat([]byte{0x41}, 12), 4, 3, 4, 4),
		append(bytes.Repeat([]byte{0x41}, 15), 17),
	} {
		if _, err := stripPKCS7(bad); err == nil {
			t.Fatal("invalid padding accepted")
		}
	}
}

func TestKeyErrorsDoNotEchoInput(t *testing.T) {
	encoder, err := NewEncoder()
	if err != nil {
		t.Fatal(err)
	}
	wire, err := encoder.Encode(Packet{MAC: codecTestMAC, Payload: []byte(`{}`)}, DefaultKey, ModeCBC)
	if err != nil {
		t.Fatal(err)
	}
	secret := strings.Repeat("z", 32)
	if _, err := Decode(wire, secret); err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("error missing or leaked key: %v", err)
	}
}

func TestPacketFormattingRedactsMACAndPayload(t *testing.T) {
	p := Packet{
		MAC: codecTestMAC, PacketVersion: PacketVersion, Payload: []byte("do-not-log"),
		authenticatedGCMNonce: [aes.BlockSize]byte{0xde, 0xad, 0xbe, 0xef, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
		hasGCMNonce:           true,
	}
	for _, formatted := range []string{fmt.Sprintf("%v", p), fmt.Sprintf("%+v", p), fmt.Sprintf("%#v", p)} {
		if strings.Contains(formatted, "do-not-log") || strings.Contains(formatted, "17 34 51") || strings.Contains(formatted, "deadbeef") || strings.Contains(formatted, "222 173 190 239") {
			t.Fatalf("formatted packet leaked content: %q", formatted)
		}
	}
}

func TestCBCDecodeDoesNotExposeIVAsGCMNonce(t *testing.T) {
	encoder, err := newEncoder(bytes.NewReader(make([]byte, 24)), DefaultCodecLimits(), PacketVersion)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := encoder.Encode(Packet{MAC: codecTestMAC, Payload: []byte(`{}`)}, DefaultKey, ModeCBC)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(wire, DefaultKey)
	if err != nil {
		t.Fatal(err)
	}
	if nonce, ok := decoded.AuthenticatedGCMNonce(); ok || nonce != [aes.BlockSize]byte{} {
		t.Fatalf("CBC packet exposed a GCM nonce: %x, %t", nonce, ok)
	}
}

func FuzzDecodeDoesNotPanic(f *testing.F) {
	f.Add([]byte("TNBU"), DefaultKey)
	f.Add(make([]byte, HeaderLength), DefaultKey)
	f.Fuzz(func(t *testing.T, packet []byte, key string) {
		_, _ = Decode(packet, key)
	})
}
