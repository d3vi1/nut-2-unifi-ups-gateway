// Package inform implements the UniFi TNBU inform wire format and the small
// amount of controller-response state required by adoption.
package inform

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sync"
)

const (
	// DefaultKey is the protocol's public, pre-adoption AES-128 key. It is not
	// a deployment secret; a controller-issued replacement key is.
	DefaultKey = "ba86f2bbe107c7c57eb5f2690775c712"

	HeaderLength = 40
	// PacketVersion is the value required by the USPDA2C firmware parser.
	PacketVersion  = uint32(0)
	PayloadVersion = uint32(1)

	flagEncrypted = uint16(1 << 0)
	flagGCM       = uint16(1 << 3)
	knownFlags    = flagEncrypted | flagGCM
)

var magic = [4]byte{'T', 'N', 'B', 'U'}

// Mode selects the encryption mode for a packet. CBC is the pre-adoption
// mode. A controller may upgrade a session to GCM through mgmt_cfg.
type Mode uint8

const (
	ModeCBC Mode = iota
	ModeGCM
)

// Limits bound encrypted-body and plaintext allocation. A controller reply is
// untrusted even when its TNBU envelope authenticates successfully.
type Limits struct {
	MaxWireBody  int
	MaxPlaintext int
}

// DefaultCodecLimits returns a fresh conservative limit set.
func DefaultCodecLimits() Limits {
	return Limits{MaxWireBody: 1 << 20, MaxPlaintext: 4 << 20}
}

func (l Limits) validate() error {
	if l.MaxWireBody < aes.BlockSize || l.MaxPlaintext < 1 {
		return errors.New("inform: invalid codec limits")
	}
	return nil
}

// Packet is one decrypted inform request or response.
type Packet struct {
	MAC           [6]byte
	PacketVersion uint32
	Payload       []byte

	authenticatedGCMNonce [aes.BlockSize]byte
	hasGCMNonce           bool
}

func (p Packet) String() string {
	return fmt.Sprintf("inform packet version=%d payload_bytes=%d", p.PacketVersion, len(p.Payload))
}

func (p Packet) GoString() string { return p.String() }

// AuthenticatedGCMNonce returns the TNBU GCM nonce only after Decode has
// successfully authenticated the complete packet. CBC packets and packets
// constructed by callers do not carry an authenticated inbound nonce.
func (p Packet) AuthenticatedGCMNonce() ([aes.BlockSize]byte, bool) {
	return p.authenticatedGCMNonce, p.hasGCMNonce
}

// Encoder owns the nonce sequence used for outgoing packets. GCM nonces have
// a random per-process prefix and a monotonically increasing counter, so a
// concurrent caller cannot accidentally reuse a nonce under the same key.
// Encoder is safe for concurrent use.
type Encoder struct {
	random io.Reader
	limits Limits

	mu        sync.Mutex
	gcmPrefix [8]byte
	gcmNext   uint64
	version   uint32
}

// NewEncoder constructs an encoder backed by crypto/rand.Reader.
func NewEncoder() (*Encoder, error) {
	return newEncoder(rand.Reader, DefaultCodecLimits(), PacketVersion)
}

func newEncoder(random io.Reader, limits Limits, version uint32) (*Encoder, error) {
	if random == nil {
		return nil, errors.New("inform: random source is required")
	}
	if err := limits.validate(); err != nil {
		return nil, err
	}
	if version != PacketVersion {
		return nil, errors.New("inform: unsupported packet version")
	}
	e := &Encoder{random: random, limits: limits, gcmNext: 1, version: version}
	if _, err := io.ReadFull(random, e.gcmPrefix[:]); err != nil {
		return nil, fmt.Errorf("inform: initialize nonce sequence: %w", err)
	}
	return e, nil
}

// Encode encrypts p into a complete 40-byte-header TNBU packet. The UPS
// firmware encrypts the JSON directly; it does not zlib-compress inform
// payloads. Errors never include the key or payload.
func (e *Encoder) Encode(p Packet, keyHex string, mode Mode) ([]byte, error) {
	if e == nil {
		return nil, errors.New("inform: nil encoder")
	}
	if err := validateMAC(p.MAC); err != nil {
		return nil, err
	}
	if len(p.Payload) == 0 {
		return nil, errors.New("inform: empty payload")
	}
	if len(p.Payload) > e.limits.MaxPlaintext {
		return nil, fmt.Errorf("inform: plaintext exceeds %d-byte limit", e.limits.MaxPlaintext)
	}
	key, err := parseKey(keyHex)
	if err != nil {
		return nil, err
	}
	defer clear(key)

	var iv [aes.BlockSize]byte
	flags := flagEncrypted
	switch mode {
	case ModeCBC:
		if err := e.randomIV(iv[:]); err != nil {
			return nil, err
		}
	case ModeGCM:
		flags |= flagGCM
		if err := e.nextGCMNonce(iv[:]); err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("inform: unsupported encryption mode")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.New("inform: initialize AES")
	}

	var bodyLen int
	if mode == ModeCBC {
		bodyLen = paddedLength(len(p.Payload), aes.BlockSize)
	} else {
		bodyLen = len(p.Payload) + 16 // TNBU uses the standard 16-byte GCM tag.
	}
	if bodyLen > e.limits.MaxWireBody {
		return nil, fmt.Errorf("inform: encrypted body exceeds %d-byte limit", e.limits.MaxWireBody)
	}

	header := marshalHeader(p.MAC, e.version, flags, iv, bodyLen)
	var body []byte
	if mode == ModeCBC {
		body = encryptCBC(block, iv[:], p.Payload)
	} else {
		aead, err := cipher.NewGCMWithNonceSize(block, aes.BlockSize)
		if err != nil {
			return nil, errors.New("inform: initialize GCM")
		}
		body = aead.Seal(nil, iv[:], p.Payload, header)
	}
	return append(header, body...), nil
}

func (e *Encoder) randomIV(dst []byte) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, err := io.ReadFull(e.random, dst); err != nil {
		return fmt.Errorf("inform: generate CBC IV: %w", err)
	}
	return nil
}

func (e *Encoder) nextGCMNonce(dst []byte) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.gcmNext == 0 {
		return errors.New("inform: GCM nonce sequence exhausted")
	}
	copy(dst[:8], e.gcmPrefix[:])
	binary.BigEndian.PutUint64(dst[8:], e.gcmNext)
	e.gcmNext++
	return nil
}

func paddedLength(n, blockSize int) int {
	return n + blockSize - n%blockSize
}

func encryptCBC(block cipher.Block, iv, plain []byte) []byte {
	pad := aes.BlockSize - len(plain)%aes.BlockSize
	out := make([]byte, len(plain)+pad)
	copy(out, plain)
	for i := len(plain); i < len(out); i++ {
		out[i] = byte(pad)
	}
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, out)
	return out
}

// Decoder validates and decodes TNBU packets. ExpectedMAC, when non-nil,
// binds controller replies to the identity that sent the inform.
type Decoder struct {
	Limits       Limits
	ExpectedMAC  *[6]byte
	ExpectedMode *Mode
}

// Decode uses conservative default limits and accepts any valid unicast MAC.
// A runtime should normally use Decoder with ExpectedMAC set.
func Decode(data []byte, keyHex string) (Packet, error) {
	return (Decoder{Limits: DefaultCodecLimits()}).Decode(data, keyHex)
}

// Decode validates header versions, flags, MAC, exact length, cryptographic
// framing, padding, expected mode, and plaintext size before returning JSON.
func (d Decoder) Decode(data []byte, keyHex string) (Packet, error) {
	limits := d.Limits
	if limits == (Limits{}) {
		limits = DefaultCodecLimits()
	}
	if err := limits.validate(); err != nil {
		return Packet{}, err
	}
	if len(data) < HeaderLength {
		return Packet{}, errors.New("inform: truncated TNBU header")
	}
	if !bytes.Equal(data[:4], magic[:]) {
		return Packet{}, errors.New("inform: invalid TNBU magic")
	}
	packetVersion := binary.BigEndian.Uint32(data[4:8])
	if packetVersion != PacketVersion {
		return Packet{}, errors.New("inform: unsupported packet version")
	}
	if binary.BigEndian.Uint32(data[32:36]) != PayloadVersion {
		return Packet{}, errors.New("inform: unsupported payload version")
	}

	var mac [6]byte
	copy(mac[:], data[8:14])
	if err := validateMAC(mac); err != nil {
		return Packet{}, err
	}
	if d.ExpectedMAC != nil && subtle.ConstantTimeCompare(mac[:], d.ExpectedMAC[:]) != 1 {
		return Packet{}, errors.New("inform: reply MAC does not match device identity")
	}

	flags := binary.BigEndian.Uint16(data[14:16])
	if flags&^knownFlags != 0 || flags&flagEncrypted == 0 {
		return Packet{}, errors.New("inform: unsupported TNBU flags")
	}
	mode := ModeCBC
	if flags&flagGCM != 0 {
		mode = ModeGCM
	}
	if d.ExpectedMode != nil && mode != *d.ExpectedMode {
		return Packet{}, errors.New("inform: reply encryption mode does not match adoption state")
	}
	bodyLen := uint64(binary.BigEndian.Uint32(data[36:40]))
	if bodyLen > uint64(limits.MaxWireBody) {
		return Packet{}, fmt.Errorf("inform: body exceeds %d-byte limit", limits.MaxWireBody)
	}
	if bodyLen != uint64(len(data)-HeaderLength) {
		return Packet{}, errors.New("inform: declared body length does not match packet")
	}
	if bodyLen == 0 {
		return Packet{}, errors.New("inform: empty encrypted body")
	}

	key, err := parseKey(keyHex)
	if err != nil {
		return Packet{}, err
	}
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return Packet{}, errors.New("inform: initialize AES")
	}

	iv := data[16:32]
	body := data[HeaderLength:]
	var plain []byte
	if flags&flagGCM != 0 {
		aead, err := cipher.NewGCMWithNonceSize(block, aes.BlockSize)
		if err != nil {
			return Packet{}, errors.New("inform: initialize GCM")
		}
		if len(body) < aead.Overhead() {
			return Packet{}, errors.New("inform: truncated GCM body")
		}
		plain, err = aead.Open(nil, iv, body, data[:HeaderLength])
		if err != nil {
			return Packet{}, errors.New("inform: GCM authentication failed")
		}
	} else {
		if len(body)%aes.BlockSize != 0 {
			return Packet{}, errors.New("inform: CBC body is not block aligned")
		}
		plain = make([]byte, len(body))
		cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, body)
		plain, err = stripPKCS7(plain)
		if err != nil {
			return Packet{}, err
		}
	}
	if len(plain) == 0 || len(plain) > limits.MaxPlaintext {
		return Packet{}, fmt.Errorf("inform: plaintext exceeds %d-byte limit", limits.MaxPlaintext)
	}
	packet := Packet{MAC: mac, PacketVersion: packetVersion, Payload: plain}
	if mode == ModeGCM {
		copy(packet.authenticatedGCMNonce[:], iv)
		packet.hasGCMNonce = true
	}
	return packet, nil
}

func marshalHeader(mac [6]byte, packetVersion uint32, flags uint16, iv [aes.BlockSize]byte, bodyLen int) []byte {
	header := make([]byte, HeaderLength)
	copy(header[:4], magic[:])
	binary.BigEndian.PutUint32(header[4:8], packetVersion)
	copy(header[8:14], mac[:])
	binary.BigEndian.PutUint16(header[14:16], flags)
	copy(header[16:32], iv[:])
	binary.BigEndian.PutUint32(header[32:36], PayloadVersion)
	binary.BigEndian.PutUint32(header[36:40], uint32(bodyLen))
	return header
}

func parseKey(keyHex string) ([]byte, error) {
	if len(keyHex) != 32 {
		return nil, errors.New("inform: auth key must be exactly 32 hexadecimal characters")
	}
	key, err := hex.DecodeString(keyHex)
	if err != nil || len(key) != aes.BlockSize {
		return nil, errors.New("inform: auth key must be exactly 32 hexadecimal characters")
	}
	return key, nil
}

func validateMAC(mac [6]byte) error {
	var nonzero byte
	for _, b := range mac {
		nonzero |= b
	}
	if nonzero == 0 || mac[0]&1 != 0 {
		return errors.New("inform: MAC must be a nonzero unicast address")
	}
	return nil
}

// stripPKCS7 checks every byte of the final block before branching on the
// result. This avoids a byte-by-byte early-exit padding oracle in callers that
// surface distinguishable errors or timing.
func stripPKCS7(in []byte) ([]byte, error) {
	if len(in) == 0 || len(in)%aes.BlockSize != 0 {
		return nil, errors.New("inform: invalid CBC padding")
	}
	pad := int(in[len(in)-1])
	valid := subtle.ConstantTimeLessOrEq(1, pad) & subtle.ConstantTimeLessOrEq(pad, aes.BlockSize)
	mismatch := 0
	for i := 0; i < aes.BlockSize; i++ {
		insidePad := subtle.ConstantTimeLessOrEq(i+1, pad)
		equal := subtle.ConstantTimeByteEq(in[len(in)-1-i], byte(pad))
		mismatch |= insidePad & (1 - equal)
	}
	valid &= subtle.ConstantTimeEq(int32(mismatch), 0)
	if valid != 1 {
		return nil, errors.New("inform: invalid CBC padding")
	}
	return in[:len(in)-pad], nil
}
