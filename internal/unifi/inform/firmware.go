package inform

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"unicode/utf8"

	"github.com/d3vi1/nut-2-unifi-ups-gateway/internal/unifi/firmware"
)

// FirmwareTarget carries only controller-visible version text, not an executable
// upgrade, URL, artifact checksum, or timestamp.
type FirmwareTarget struct{ Version string }

func ClassifyFirmwareTarget(body []byte) (FirmwareTarget, error) {
	bad := errors.New("inform: ineligible reported firmware target")
	if len(body) == 0 || len(body) > 16<<10 || !utf8.Valid(body) {
		return FirmwareTarget{}, bad
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	opening, err := dec.Token()
	if err != nil || opening != json.Delim('{') {
		return FirmwareTarget{}, bad
	}
	fields := make(map[string]string, 6)
	for dec.More() {
		tok, err := dec.Token()
		name, ok := tok.(string)
		if err != nil || !ok {
			return FirmwareTarget{}, bad
		}
		switch name {
		case "_type", "version", "url", "server_time_in_utc", "md5sum", "sha256sum":
		default:
			return FirmwareTarget{}, bad
		}
		if _, exists := fields[name]; exists {
			return FirmwareTarget{}, bad
		}
		tok, err = dec.Token()
		value, ok := tok.(string)
		if err != nil || !ok {
			return FirmwareTarget{}, bad
		}
		fields[name] = value
	}
	closing, err := dec.Token()
	if err != nil || closing != json.Delim('}') {
		return FirmwareTarget{}, bad
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return FirmwareTarget{}, bad
	}
	if fields["_type"] != "upgrade" || !firmware.ValidVersion(fields["version"]) {
		return FirmwareTarget{}, bad
	}
	if value, present := fields["url"]; present {
		if len(value) == 0 || len(value) > 2048 {
			return FirmwareTarget{}, bad
		}
		for _, ch := range []byte(value) {
			if ch < 0x20 || ch > 0x7e {
				return FirmwareTarget{}, bad
			}
		}
	}
	for name, size := range map[string]int{"md5sum": 32, "sha256sum": 64} {
		if value, present := fields[name]; present {
			if len(value) != size {
				return FirmwareTarget{}, bad
			}
			if _, err := hex.DecodeString(value); err != nil {
				return FirmwareTarget{}, bad
			}
		}
	}
	if value, present := fields["server_time_in_utc"]; present {
		if len(value) != 13 {
			return FirmwareTarget{}, bad
		}
		for _, ch := range []byte(value) {
			if ch < '0' || ch > '9' {
				return FirmwareTarget{}, bad
			}
		}
	}
	return FirmwareTarget{Version: fields["version"]}, nil
}
