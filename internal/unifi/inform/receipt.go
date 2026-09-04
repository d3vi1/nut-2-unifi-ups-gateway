package inform

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"unicode/utf8"
)

// ConfigReceipt retains only a report marker and fixed diagnostic categories.
// It cannot convey adoption changes, destinations, credentials, or commands.
type ConfigReceipt struct {
	CfgVersion          string
	UnsupportedSettings []string
}

var errConfigReceipt = errors.New("inform: ineligible configuration receipt")

// ClassifyConfigReceipt is a pure, strict parser for the observed UPS setparam
// shape. Call it only after authenticating the envelope and checking its epoch
// and nonce. Unlike ApplyControllerResponse, it has no adoption-state effects.
func ClassifyConfigReceipt(body []byte) (ConfigReceipt, error) {
	if len(body) == 0 || len(body) > maxControllerResponse || !utf8.Valid(body) {
		return ConfigReceipt{}, errConfigReceipt
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	opening, err := dec.Token()
	if err != nil || opening != json.Delim('{') {
		return ConfigReceipt{}, errConfigReceipt
	}
	fields := make(map[string]string, 6)
	for dec.More() {
		token, err := dec.Token()
		name, ok := token.(string)
		if err != nil || !ok {
			return ConfigReceipt{}, errConfigReceipt
		}
		switch name {
		case "_type", "mgmt_cfg", "system_cfg", "cfgversion", "server_time_in_utc", "blocked_sta":
		default:
			return ConfigReceipt{}, errConfigReceipt
		}
		if _, exists := fields[name]; exists {
			return ConfigReceipt{}, errConfigReceipt
		}
		token, err = dec.Token()
		value, ok := token.(string)
		if err != nil || !ok {
			return ConfigReceipt{}, errConfigReceipt
		}
		fields[name] = value
	}
	closing, err := dec.Token()
	if err != nil || closing != json.Delim('}') {
		return ConfigReceipt{}, errConfigReceipt
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return ConfigReceipt{}, errConfigReceipt
	}
	if fields["_type"] != "setparam" || len(fields["system_cfg"]) > 64<<10 {
		return ConfigReceipt{}, errConfigReceipt
	}
	management := fields["mgmt_cfg"]
	if len(management) == 0 || len(management) > 64<<10 {
		return ConfigReceipt{}, errConfigReceipt
	}
	for _, ch := range []byte(management) {
		if (ch < 0x20 && ch != '\n' && ch != '\r' && ch != '\t') || ch > 0x7e {
			return ConfigReceipt{}, errConfigReceipt
		}
	}
	lines := strings.Split(strings.ReplaceAll(management, "\r\n", "\n"), "\n")
	if len(lines) > 256 {
		return ConfigReceipt{}, errConfigReceipt
	}
	seen := make(map[string]bool, 8)
	var version string
	for _, raw := range lines {
		if len(raw) > 255 {
			return ConfigReceipt{}, errConfigReceipt
		}
		line := strings.Trim(raw, " \t")
		if line == "" {
			continue
		}
		name, value, ok := strings.Cut(line, "=")
		name, value = strings.Trim(name, " \t"), strings.Trim(value, " \t")
		if !ok || !validToken(name, 64) || seen[name] || strings.ContainsAny(value, "\r\t") {
			return ConfigReceipt{}, errConfigReceipt
		}
		seen[name] = true
		switch name {
		case "cfgversion":
			if !validConfigValue(value, 128) {
				return ConfigReceipt{}, errConfigReceipt
			}
			version = value
		case "use_aes_gcm":
			if value != "true" {
				return ConfigReceipt{}, errConfigReceipt
			}
		case "capability", "led_enabled", "mgmt_url", "report_crash", "selfrun_guest_mode", "stun_url":
			// Intentionally inert. In particular these URLs are never followed.
		default:
			return ConfigReceipt{}, errConfigReceipt
		}
	}
	if version == "" {
		return ConfigReceipt{}, errConfigReceipt
	}
	if outer, present := fields["cfgversion"]; present && outer != version {
		return ConfigReceipt{}, errConfigReceipt
	}
	if fields["blocked_sta"] != "" {
		return ConfigReceipt{}, errConfigReceipt
	}
	if stamp, present := fields["server_time_in_utc"]; present {
		if len(stamp) != 13 {
			return ConfigReceipt{}, errConfigReceipt
		}
		for _, ch := range []byte(stamp) {
			if ch < '0' || ch > '9' {
				return ConfigReceipt{}, errConfigReceipt
			}
		}
	}
	// Outer metadata is only syntax-checked. The management marker is the sole
	// retained value; server time supplies neither ordering nor freshness.
	return ConfigReceipt{CfgVersion: version, UnsupportedSettings: unsupportedControllerSettings(fields["system_cfg"])}, nil
}
