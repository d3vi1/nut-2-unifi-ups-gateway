package inform

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const maxControllerResponse = 256 << 10

// AdoptionState is the persistent subset of the device-side adoption state.
// AuthKey is secret after adoption and must never be formatted into logs.
type AdoptionState struct {
	AuthKey    string
	InformURL  string
	CfgVersion string
	Adopted    bool
	UseAESGCM  bool
}

func (s AdoptionState) String() string {
	return fmt.Sprintf("inform adoption state adopted=%t gcm=%t", s.Adopted, s.UseAESGCM)
}

func (s AdoptionState) GoString() string { return s.String() }

// NewAdoptionState creates a pending, CBC-mode state.
func NewAdoptionState(informURL string) (AdoptionState, error) {
	s := AdoptionState{
		AuthKey:    DefaultKey,
		InformURL:  informURL,
		CfgVersion: "0",
	}
	if err := s.Validate(); err != nil {
		return AdoptionState{}, err
	}
	return s, nil
}

// Validate checks state without echoing key or URL contents in errors.
func (s AdoptionState) Validate() error {
	if !validKey(s.AuthKey) {
		return errors.New("inform: invalid adoption auth key")
	}
	if err := validateInformURL(s.InformURL); err != nil {
		return err
	}
	if !validConfigValue(s.CfgVersion, 128) {
		return errors.New("inform: invalid cfgversion")
	}
	if !s.Adopted && !strings.EqualFold(s.AuthKey, DefaultKey) {
		return errors.New("inform: pending state cannot use a controller key")
	}
	if !s.Adopted && s.UseAESGCM {
		return errors.New("inform: pending state cannot use AES-GCM")
	}
	return nil
}

// ResponseKind classifies a controller response without retaining its raw JSON.
type ResponseKind uint8

const (
	ResponseNoop ResponseKind = iota
	ResponseSetParam
	ResponseFactoryReset
	ResponseReboot
	ResponseUpgrade
	ResponseRelayControl
	ResponseIgnoredCommand
)

// Outcome reports non-secret effects that the gateway may act on. It never
// contains a controller auth key or a raw controller response.
type Outcome struct {
	Kind             ResponseKind
	Interval         time.Duration
	StateChanged     bool
	InformURLChanged bool
	RestartRequested bool
	UpgradeVersion   string
	CycleIntents     []OutletCycleIntent
}

// OutletCycleIntent is non-executable protocol evidence. Gateway v1 records
// only the count of parsed intents and has no NUT write-command API.
type OutletCycleIntent struct {
	OutletIndex int
	DelayOff    time.Duration
	DelayOn     time.Duration
}

type controllerResponse struct {
	Type        string          `json:"_type"`
	Cmd         string          `json:"cmd"`
	Interval    int64           `json:"interval"`
	MgmtCfg     string          `json:"mgmt_cfg"`
	Version     string          `json:"version"`
	OutletTable json.RawMessage `json:"outlet_table"`
}

// ApplyControllerResponse transactionally applies adoption-related fields.
// Firmware marks a default device managed after any supported normal response,
// even a noop which leaves the public default key in place. setparam may rotate
// the envelope key at any time. GCM is a one-way transition until setdefault.
func (s *AdoptionState) ApplyControllerResponse(body []byte) (Outcome, error) {
	if s == nil {
		return Outcome{}, errors.New("inform: nil adoption state")
	}
	if err := s.Validate(); err != nil {
		return Outcome{}, err
	}
	if len(body) == 0 || len(body) > maxControllerResponse {
		return Outcome{}, errors.New("inform: controller response has invalid size")
	}
	if err := validateUniqueJSON(body); err != nil {
		return Outcome{}, err
	}

	var response controllerResponse
	dec := json.NewDecoder(bytes.NewReader(body))
	if err := dec.Decode(&response); err != nil {
		return Outcome{}, errors.New("inform: invalid controller response JSON")
	}
	if !validToken(response.Type, 32) {
		return Outcome{}, errors.New("inform: invalid controller response type")
	}

	next := *s
	out := Outcome{}
	markManaged := true
	switch response.Type {
	case "noop":
		out.Kind = ResponseNoop
		if response.Interval < 0 || response.Interval > 24*60*60 {
			return Outcome{}, errors.New("inform: controller interval is out of range")
		}
		out.Interval = time.Duration(response.Interval) * time.Second
	case "setparam":
		out.Kind = ResponseSetParam
		changed, urlChanged, err := next.applyMgmtCfg(response.MgmtCfg)
		if err != nil {
			return Outcome{}, err
		}
		out.StateChanged = changed
		out.InformURLChanged = urlChanged
	case "setdefault":
		out = next.factoryReset()
		markManaged = false
	case "reboot":
		out = Outcome{Kind: ResponseReboot, RestartRequested: true}
	case "upgrade":
		out.Kind = ResponseUpgrade
		out.RestartRequested = true
		if response.Version != "" {
			if !validConfigValue(response.Version, 128) {
				return Outcome{}, errors.New("inform: invalid upgrade version")
			}
			out.UpgradeVersion = response.Version
		}
	case "cmd":
		var err error
		out, err = next.applyCommand(response)
		if err != nil {
			return Outcome{}, err
		}
	default:
		return Outcome{}, errors.New("inform: unsupported controller response type")
	}
	if markManaged && !next.Adopted {
		next.Adopted = true
		out.StateChanged = true
	}

	if err := next.Validate(); err != nil {
		return Outcome{}, err
	}
	*s = next
	return out, nil
}

func (s *AdoptionState) applyMgmtCfg(raw string) (bool, bool, error) {
	if len(raw) > 64<<10 {
		return false, false, errors.New("inform: mgmt_cfg is too large")
	}
	before := *s
	seen := make(map[string]struct{})
	lines := strings.Split(strings.ReplaceAll(raw, "\r", "\n"), "\n")
	if len(lines) > 256 {
		return false, false, errors.New("inform: mgmt_cfg has too many entries")
	}
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if len(line) > 255 {
			return false, false, errors.New("inform: mgmt_cfg line is too long")
		}
		name, value, ok := strings.Cut(line, "=")
		name = strings.TrimSpace(name)
		value = strings.TrimSpace(value)
		if !ok || !validToken(name, 64) || len(value) > 255 {
			return false, false, errors.New("inform: malformed mgmt_cfg entry")
		}
		if _, duplicate := seen[name]; duplicate {
			return false, false, errors.New("inform: duplicate mgmt_cfg entry")
		}
		seen[name] = struct{}{}
		switch name {
		case "cfgversion":
			if !validConfigValue(value, 128) {
				return false, false, errors.New("inform: invalid cfgversion")
			}
			s.CfgVersion = value
		case "inform_url":
			if err := validateInformURL(value); err != nil {
				return false, false, err
			}
			s.InformURL = value
		case "authkey":
			if !validKey(value) {
				return false, false, errors.New("inform: invalid controller auth key")
			}
			s.AuthKey = strings.ToLower(value)
		case "use_aes_gcm":
			enabled, recognized := parseConfigBoolean(value)
			if !recognized {
				return false, false, errors.New("inform: invalid use_aes_gcm value")
			}
			// Sticky by firmware design: only setdefault returns a session to CBC.
			if enabled {
				s.UseAESGCM = true
			}
		}
	}
	return *s != before, s.InformURL != before.InformURL, nil
}

func parseConfigBoolean(value string) (bool, bool) {
	switch strings.ToLower(value) {
	case "on", "enabled", "1", "enable", "active", "true":
		return true, true
	case "off", "disabled", "0", "disable", "inactive", "false":
		return false, true
	default:
		return false, false
	}
}

func (s *AdoptionState) applyCommand(response controllerResponse) (Outcome, error) {
	if !validToken(response.Cmd, 64) {
		return Outcome{}, errors.New("inform: invalid controller command")
	}
	switch response.Cmd {
	case "relayctl":
		intents, err := parseRelayControl(response.OutletTable)
		if err != nil {
			return Outcome{}, err
		}
		return Outcome{Kind: ResponseRelayControl, CycleIntents: intents}, nil
	default:
		return Outcome{Kind: ResponseIgnoredCommand}, nil
	}
}

func (s *AdoptionState) factoryReset() Outcome {
	changed := s.Adopted || !strings.EqualFold(s.AuthKey, DefaultKey) || s.CfgVersion != "0" || s.UseAESGCM
	s.AuthKey = DefaultKey
	s.CfgVersion = "0"
	s.Adopted = false
	s.UseAESGCM = false
	return Outcome{Kind: ResponseFactoryReset, StateChanged: changed}
}

const maxRelayDelayMinutes = 10

type controllerRelayEntry struct {
	Index    strictJSONNumber `json:"index"`
	DelayOff strictJSONNumber `json:"delay_time_to_off"`
	DelayOn  strictJSONNumber `json:"delay_time_to_on"`
}

type strictJSONNumber struct {
	present bool
	raw     string
}

func (n *strictJSONNumber) UnmarshalJSON(data []byte) error {
	n.present = true
	if len(data) == 0 || data[0] == '"' || bytes.Equal(data, []byte("null")) {
		return errors.New("expected JSON number")
	}
	if _, err := strconv.ParseFloat(string(data), 64); err != nil {
		return errors.New("expected JSON number")
	}
	n.raw = string(data)
	return nil
}

// parseRelayControl implements the firmware-proven relayctl shape. The real
// firmware defaults malformed delays; this gateway is deliberately stricter:
// supplied delays must be finite and within a ten-minute safety bound.
func parseRelayControl(raw json.RawMessage) ([]OutletCycleIntent, error) {
	if len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil, errors.New("inform: relayctl requires outlet_table array")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	dec.DisallowUnknownFields()
	var entries []controllerRelayEntry
	if err := dec.Decode(&entries); err != nil {
		return nil, errors.New("inform: invalid relayctl outlet_table")
	}
	if len(entries) > 9 {
		return nil, errors.New("inform: relayctl has too many outlets")
	}
	seen := make(map[int]struct{}, len(entries))
	intents := make([]OutletCycleIntent, 0, len(entries))
	for _, entry := range entries {
		index, err := parseRelayIndex(entry.Index)
		if err != nil {
			return nil, err
		}
		if _, duplicate := seen[index]; duplicate {
			return nil, errors.New("inform: relayctl has duplicate outlet index")
		}
		seen[index] = struct{}{}
		delayOff, err := parseRelayDelay(entry.DelayOff, 0, true)
		if err != nil {
			return nil, err
		}
		delayOn, err := parseRelayDelay(entry.DelayOn, 0.1, false)
		if err != nil {
			return nil, err
		}
		intents = append(intents, OutletCycleIntent{OutletIndex: index, DelayOff: delayOff, DelayOn: delayOn})
	}
	return intents, nil
}

func parseRelayIndex(value strictJSONNumber) (int, error) {
	if !value.present {
		return 0, errors.New("inform: relayctl outlet index is required")
	}
	numeric, err := strconv.ParseFloat(value.raw, 64)
	if err != nil || math.IsNaN(numeric) || math.IsInf(numeric, 0) || numeric < 1 || numeric >= 10 {
		return 0, errors.New("inform: relayctl outlet index is out of range")
	}
	// ESP-IDF's cJSON valueint conversion truncates a real-valued index.
	index := int(numeric)
	if index < 1 || index > 9 {
		return 0, errors.New("inform: relayctl outlet index is out of range")
	}
	return index, nil
}

func parseRelayDelay(value strictJSONNumber, defaultMinutes float64, zeroAllowed bool) (time.Duration, error) {
	minutes := defaultMinutes
	if value.present {
		parsed, err := strconv.ParseFloat(value.raw, 64)
		if err != nil || math.IsNaN(parsed) || math.IsInf(parsed, 0) {
			return 0, errors.New("inform: relayctl delay must be finite")
		}
		minutes = parsed
	}
	if minutes > maxRelayDelayMinutes || (zeroAllowed && minutes < 0) || (!zeroAllowed && minutes <= 0) {
		return 0, errors.New("inform: relayctl delay is out of range")
	}
	milliseconds := int64(minutes * 60 * 1000)
	return time.Duration(milliseconds) * time.Millisecond, nil
}

func validKey(value string) bool {
	if len(value) != 32 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 16
}

func validateInformURL(value string) error {
	if len(value) == 0 || len(value) > 2048 {
		return errors.New("inform: invalid inform URL")
	}
	u, err := url.Parse(value)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("inform: invalid inform URL")
	}
	if u.Path != "/inform" {
		return errors.New("inform: invalid inform URL path")
	}
	return nil
}

func validToken(value string, max int) bool {
	if len(value) == 0 || len(value) > max {
		return false
	}
	for i := range len(value) {
		c := value[i]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}

func validConfigValue(value string, max int) bool {
	if len(value) == 0 || len(value) > max {
		return false
	}
	for i := range len(value) {
		if value[i] < 0x20 || value[i] == 0x7f {
			return false
		}
	}
	return true
}

// validateUniqueJSON rejects ambiguous duplicate object keys at any depth.
func validateUniqueJSON(body []byte) error {
	dec := json.NewDecoder(bytes.NewReader(body))
	if err := walkJSON(dec, 0); err != nil {
		return errors.New("inform: invalid or ambiguous controller response JSON")
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("inform: controller response has trailing JSON")
	}
	return nil
}

func walkJSON(dec *json.Decoder, depth int) error {
	if depth > 32 {
		return errors.New("JSON nesting limit")
	}
	token, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := make(map[string]struct{})
		for dec.More() {
			nameToken, err := dec.Token()
			if err != nil {
				return err
			}
			name, ok := nameToken.(string)
			if !ok {
				return errors.New("non-string object key")
			}
			if _, duplicate := seen[name]; duplicate {
				return fmt.Errorf("duplicate object key")
			}
			seen[name] = struct{}{}
			if err := walkJSON(dec, depth+1); err != nil {
				return err
			}
		}
		end, err := dec.Token()
		if err != nil || end != json.Delim('}') {
			return errors.New("unterminated object")
		}
	case '[':
		for dec.More() {
			if err := walkJSON(dec, depth+1); err != nil {
				return err
			}
		}
		end, err := dec.Token()
		if err != nil || end != json.Delim(']') {
			return errors.New("unterminated array")
		}
	default:
		return errors.New("unexpected delimiter")
	}
	return nil
}
