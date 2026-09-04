// Package model maps a raw NUT observation to the conservative UPS model sent
// to UniFi. Native outlet topology is retained when NUT publishes it; telemetry
// is only marked known when the upstream observation proves it.
package model

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/d3vi1/nut-2-unifi-ups-gateway/internal/nut"
)

const defaultStaleAfter = 20 * time.Second

const (
	maxBatteryRuntimeSeconds = 31 * 24 * 60 * 60
	maxObservedPower         = 1_000_000_000
	// MaxOutletCount bounds topology controlled by an untrusted NUT server.
	MaxOutletCount = 64
)

// Availability is the freshness of the complete upstream observation.
type Availability string

const (
	AvailabilityAvailable   Availability = "available"
	AvailabilityStale       Availability = "stale"
	AvailabilityUnavailable Availability = "unavailable"
)

// PowerSource is derived only from the complete ups.status token set.
type PowerSource string

const (
	PowerSourceUnknown PowerSource = "unknown"
	PowerSourceMains   PowerSource = "mains"
	PowerSourceBattery PowerSource = "battery"
	PowerSourceOff     PowerSource = "off"
)

// BeeperStatus is the observed standard NUT ups.beeper.status value. Unknown
// covers both absent and malformed upstream evidence; only malformed values
// add an issue.
type BeeperStatus string

const (
	BeeperStatusUnknown  BeeperStatus = "unknown"
	BeeperStatusEnabled  BeeperStatus = "enabled"
	BeeperStatusDisabled BeeperStatus = "disabled"
	BeeperStatusMuted    BeeperStatus = "muted"
)

// RelayState represents an observed outlet/group state. Unknown is distinct
// from off; Mixed is a derived state based on observed outlet states.
type RelayState string

const (
	RelayUnknown RelayState = "unknown"
	RelayOn      RelayState = "on"
	RelayOff     RelayState = "off"
	RelayMixed   RelayState = "mixed"
)

// Measurement is an observed numeric value. Known=false means Value must not be
// serialized as real telemetry.
type Measurement struct {
	Value float64
	Known bool
}

// Truth is an observed or safely derived boolean value.
type Truth struct {
	Value bool
	Known bool
}

// Status is the interpreted NUT ups.status field.
type Status struct {
	Raw            []string
	PowerSource    PowerSource
	OnBattery      Truth
	LowBattery     Truth
	Charging       Truth
	Discharging    Truth
	Bypass         Truth
	Overloaded     Truth
	ReplaceBattery Truth
}

// Battery contains only standard NUT battery measurements.
type Battery struct {
	ChargePercent  Measurement
	RuntimeSeconds Measurement
	Voltage        Measurement
	TemperatureC   Measurement
}

// Electrical contains UPS-wide input and output measurements.
type Electrical struct {
	InputVoltage                 Measurement
	OutputVoltage                Measurement
	OutputCurrent                Measurement
	OutputPowerW                 Measurement
	OutputPowerNominalW          Measurement
	OutputApparentPowerVA        Measurement
	OutputApparentPowerNominalVA Measurement
	OutputPowerFactor            Measurement
	LoadPercent                  Measurement
}

// OutletType retains the NUT-side physical type classification. NUT defines
// outlet.N.type as opaque text rather than a closed enum, so only explicit AC
// and USB tokens are classified.
type OutletType string

const (
	OutletTypeUnknown OutletType = "unknown"
	OutletTypeAC      OutletType = "ac"
	OutletTypeUSB     OutletType = "usb"
)

// Outlet is one NUT outlet. RelayGroup is the deterministic, dense UniFi group
// number derived from NativeGroupID; electrical fields and RelayState are
// observations. PowerMeter means a per-outlet current or power variable was
// present, even if its current sample was malformed and therefore omitted.
type Outlet struct {
	Index         int
	NativeID      string
	NativeGroupID string
	RelayGroup    int
	Name          string
	NameObserved  bool
	Type          OutletType
	Switchable    Truth
	PowerMeter    bool
	RelayState    RelayState
	Voltage       Measurement
	Current       Measurement
	PowerW        Measurement
	PowerFactor   Measurement
}

// OutletGroup is a relay grouping derived from equal, opaque NUT groupid
// values. SourceIndex is populated only when outlet.group.N.id exactly matches
// NativeID and its optional count agrees; numeric group IDs are never assumed
// to be group-table indices.
type OutletGroup struct {
	Index         int
	NativeID      string
	SourceIndex   int
	Name          string
	OutletIndices []int
	Switchable    Truth
	// SwitchablePresent distinguishes absent group evidence from malformed
	// group evidence, which must not fall through to a broader global value.
	SwitchablePresent bool
	RelayState        RelayState
}

// NativeOutletGroup retains a source-ordered NUT outlet.group.N row even when
// NUT supplies no physical outlet inventory. It never implies outlet membership.
// Present flags distinguish absent optional evidence from malformed evidence.
type NativeOutletGroup struct {
	SourceIndex        int
	NativeID           string
	Name               string
	Type               string
	TypeObserved       bool
	OutletCount        int
	OutletCountPresent bool
	OutletCountKnown   bool
	Switchable         Truth
	SwitchablePresent  bool
	RelayState         RelayState
	RelayStatePresent  bool
}

// State is the conservative canonical view consumed by protocol projections.
// Issues contains bounded machine-readable codes, never raw upstream values.
type State struct {
	Availability         Availability
	AvailabilityReason   string
	ObservedAt           time.Time
	Age                  time.Duration
	Status               Status
	BeeperStatus         BeeperStatus
	Battery              Battery
	Electrical           Electrical
	TopologyObserved     bool
	NativeGroupsObserved bool
	NativeGroups         []NativeOutletGroup
	Groups               []OutletGroup
	Outlets              []Outlet
	Issues               []string
}

// Options controls observation freshness.
type Options struct {
	Now        time.Time
	StaleAfter time.Duration
}

// FromSnapshot maps one NUT snapshot. It never substitutes defaults for absent,
// stale, malformed, or out-of-range telemetry.
func FromSnapshot(snapshot nut.Snapshot, options Options) State {
	now := options.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	staleAfter := options.StaleAfter
	if staleAfter <= 0 {
		staleAfter = defaultStaleAfter
	}

	state := State{
		Availability: AvailabilityAvailable,
		ObservedAt:   snapshot.CollectedAt,
		Status:       Status{PowerSource: PowerSourceUnknown},
		BeeperStatus: BeeperStatusUnknown,
	}
	initializeFallbackTopology(&state)

	if snapshot.CollectedAt.IsZero() || snapshot.Variables == nil {
		state.Availability = AvailabilityUnavailable
		state.AvailabilityReason = "no-observation"
		state.Issues = append(state.Issues, "no-observation")
		return state
	}
	state.Age = now.Sub(snapshot.CollectedAt)
	if state.Age < 0 {
		state.Availability = AvailabilityUnavailable
		state.AvailabilityReason = "observation-in-future"
		state.Issues = append(state.Issues, "observation-in-future")
		return state
	}
	if state.Age > staleAfter {
		state.Availability = AvailabilityStale
		state.AvailabilityReason = "observation-too-old"
	}

	initializeObservedTopology(&state, snapshot.Variables)
	mapStatus(&state, snapshot.Variables["ups.status"])
	mapChargerStatus(&state, snapshot.Variables)
	mapBeeperStatus(&state, snapshot.Variables)
	mapMeasurements(&state, snapshot.Variables)
	mapOutletTelemetry(&state, snapshot.Variables)
	mapGroupRelayStates(&state)
	return state
}

func initializeFallbackTopology(state *State) {
	state.TopologyObserved = false
	state.Groups = []OutletGroup{
		{Index: 1, Name: "Zone 1", OutletIndices: []int{1, 2, 3, 4}, RelayState: RelayUnknown},
		{Index: 2, Name: "Zone 2", OutletIndices: []int{5, 6, 7, 8}, RelayState: RelayUnknown},
	}
	state.Outlets = make([]Outlet, 8)
	for outletIndex := range state.Outlets {
		index := outletIndex + 1
		state.Outlets[outletIndex] = Outlet{
			Index:      index,
			RelayGroup: outletIndex/4 + 1,
			Name:       fmt.Sprintf("Outlet %d", index),
			Type:       OutletTypeUnknown,
			RelayState: RelayUnknown,
		}
	}
}

type nativeGroupMetadata struct {
	SourceIndex       int
	Name              string
	ExpectedSize      int
	HasSize           bool
	InvalidSize       bool
	Switchable        Truth
	SwitchablePresent bool
}

type nativeGroupTable struct {
	Observed bool
	Rows     []NativeOutletGroup
	ByID     map[string]nativeGroupMetadata
}

type outletGroupKey struct {
	NativeID       string
	SingletonIndex int
}

// initializeObservedTopology replaces the compatibility fallback only when
// NUT supplies a valid outlet.count. NUT group IDs are opaque identifiers:
// equal IDs mean equal groups, but their spelling and numeric appearance have
// no relationship to the dense relay_group integers required by UniFi.
func initializeObservedTopology(state *State, variables map[string]string) {
	nativeGroups := readNativeGroupMetadata(variables, &state.Issues)
	state.NativeGroupsObserved = nativeGroups.Observed
	state.NativeGroups = nativeGroups.Rows

	rawCount, exists := variables["outlet.count"]
	if !exists {
		return
	}
	count, valid := boundedIntegral(rawCount, 1, MaxOutletCount)
	if !valid {
		state.Issues = append(state.Issues, "invalid-outlet-count")
		return
	}

	state.TopologyObserved = true
	state.Groups = nil
	state.Outlets = make([]Outlet, count)
	groupByKey := make(map[outletGroupKey]int, count)

	for offset := range state.Outlets {
		index := offset + 1
		prefix := fmt.Sprintf("outlet.%d.", index)
		nativeID := ""
		if raw, ok := variables[prefix+"id"]; ok {
			var validID bool
			nativeID, validID = opaqueNativeID(raw, 128)
			if !validID {
				state.Issues = append(state.Issues, fmt.Sprintf("invalid-outlet-%d-id", index))
			}
		}
		nativeGroupID := ""
		if raw, ok := variables[prefix+"groupid"]; ok {
			var validGroupID bool
			nativeGroupID, validGroupID = opaqueNativeID(raw, 128)
			if !validGroupID {
				state.Issues = append(state.Issues, fmt.Sprintf("invalid-outlet-%d-groupid", index))
			}
		}
		groupKey := outletGroupKey{NativeID: nativeGroupID}
		if nativeGroupID == "" {
			// Absence of groupid is evidence for no grouping, not permission to
			// infer that adjacent outlets share a relay.
			groupKey.SingletonIndex = index
		}
		groupOffset, found := groupByKey[groupKey]
		if !found {
			groupOffset = len(state.Groups)
			groupByKey[groupKey] = groupOffset
			state.Groups = append(state.Groups, OutletGroup{
				Index:      groupOffset + 1,
				NativeID:   nativeGroupID,
				Name:       fmt.Sprintf("Relay Group %d", groupOffset+1),
				RelayState: RelayUnknown,
			})
		}
		group := &state.Groups[groupOffset]
		group.OutletIndices = append(group.OutletIndices, index)
		state.Outlets[offset] = Outlet{
			Index:         index,
			NativeID:      nativeID,
			NativeGroupID: nativeGroupID,
			RelayGroup:    group.Index,
			Name:          fmt.Sprintf("Outlet %d", index),
			Type:          OutletTypeUnknown,
			RelayState:    RelayUnknown,
		}
	}

	for groupOffset := range state.Groups {
		group := &state.Groups[groupOffset]
		metadata, ok := nativeGroups.ByID[group.NativeID]
		if group.NativeID == "" || !ok {
			continue
		}
		if metadata.InvalidSize || (metadata.HasSize && metadata.ExpectedSize != len(group.OutletIndices)) {
			if !metadata.InvalidSize {
				state.Issues = append(state.Issues, fmt.Sprintf("conflicting-relay-group-%d-count", group.Index))
			}
			continue
		}
		if metadata.Name != "" {
			group.Name = metadata.Name
		}
		group.SourceIndex = metadata.SourceIndex
		group.Switchable = metadata.Switchable
		group.SwitchablePresent = metadata.SwitchablePresent
	}
}

func readNativeGroupMetadata(variables map[string]string, issues *[]string) nativeGroupTable {
	result := nativeGroupTable{ByID: make(map[string]nativeGroupMetadata)}
	rawCount, exists := variables["outlet.group.count"]
	if !exists {
		return result
	}
	count, valid := boundedIntegral(rawCount, 0, MaxOutletCount)
	if !valid {
		*issues = append(*issues, "invalid-outlet-group-count")
		return result
	}
	result.Observed = true
	result.Rows = make([]NativeOutletGroup, 0, count)
	ambiguous := make(map[string]bool)
	for index := 1; index <= count; index++ {
		prefix := fmt.Sprintf("outlet.group.%d.", index)
		row := NativeOutletGroup{
			SourceIndex: index,
			RelayState:  RelayUnknown,
		}
		rawID, idPresent := variables[prefix+"id"]
		if !idPresent {
			*issues = append(*issues, fmt.Sprintf("missing-outlet-group-%d-id", index))
		} else if id, validID := opaqueNativeID(rawID, 128); validID {
			row.NativeID = id
		} else {
			*issues = append(*issues, fmt.Sprintf("invalid-outlet-group-%d-id", index))
		}
		if rawName, ok := variables[prefix+"name"]; ok {
			row.Name = optionalNativeText(rawName, 128)
			if row.Name == "" {
				*issues = append(*issues, fmt.Sprintf("invalid-outlet-group-%d-name", index))
			}
		}
		if rawType, ok := variables[prefix+"type"]; ok {
			row.Type = optionalNativeText(rawType, 128)
			row.TypeObserved = row.Type != ""
			if !row.TypeObserved {
				*issues = append(*issues, fmt.Sprintf("invalid-outlet-group-%d-type", index))
			}
		}
		if rawSize, ok := variables[prefix+"count"]; ok {
			row.OutletCountPresent = true
			if size, validSize := boundedIntegral(rawSize, 0, MaxOutletCount); validSize {
				row.OutletCount = size
				row.OutletCountKnown = true
			} else {
				*issues = append(*issues, fmt.Sprintf("invalid-outlet-group-%d-count", index))
			}
		}
		if rawSwitchable, ok := variables[prefix+"switchable"]; ok {
			row.SwitchablePresent = true
			row.Switchable = parseTruth(rawSwitchable)
			if !row.Switchable.Known {
				*issues = append(*issues, fmt.Sprintf("invalid-outlet-group-%d-switchable", index))
			}
		}
		if rawStatus, ok := variables[prefix+"status"]; ok {
			row.RelayStatePresent = true
			row.RelayState = parseRelay(rawStatus)
			if row.RelayState == RelayUnknown {
				*issues = append(*issues, fmt.Sprintf("invalid-outlet-group-%d-status", index))
			}
		}
		result.Rows = append(result.Rows, row)

		if row.NativeID == "" || ambiguous[row.NativeID] {
			continue
		}
		if _, duplicate := result.ByID[row.NativeID]; duplicate {
			delete(result.ByID, row.NativeID)
			ambiguous[row.NativeID] = true
			*issues = append(*issues, "duplicate-outlet-group-id")
			continue
		}
		result.ByID[row.NativeID] = nativeGroupMetadata{
			SourceIndex:       row.SourceIndex,
			Name:              row.Name,
			ExpectedSize:      row.OutletCount,
			HasSize:           row.OutletCountPresent && row.OutletCountKnown,
			InvalidSize:       row.OutletCountPresent && !row.OutletCountKnown,
			Switchable:        row.Switchable,
			SwitchablePresent: row.SwitchablePresent,
		}
	}
	return result
}

func boundedIntegral(raw string, minimum, maximum int) (int, bool) {
	value, err := strconv.ParseFloat(strings.TrimSpace(raw), 64)
	if err != nil || math.IsNaN(value) || math.IsInf(value, 0) || math.Trunc(value) != value ||
		value < float64(minimum) || value > float64(maximum) {
		return 0, false
	}
	return int(value), true
}

func optionalNativeText(raw string, maximum int) string {
	value := strings.TrimSpace(raw)
	if value == "" || len(value) > maximum {
		return ""
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return ""
		}
	}
	return value
}

func opaqueNativeID(raw string, maximum int) (string, bool) {
	if raw == "" || len(raw) > maximum {
		return "", false
	}
	for _, r := range raw {
		if r < 0x20 || r == 0x7f {
			return "", false
		}
	}
	return raw, true
}

func mapStatus(state *State, raw string) {
	tokens := strings.Fields(raw)
	if len(tokens) == 0 {
		state.Availability = AvailabilityUnavailable
		state.AvailabilityReason = "missing-ups-status"
		state.Issues = append(state.Issues, "missing-ups-status")
		return
	}
	seen := make(map[string]struct{}, len(tokens))
	duplicateReported := false
	for _, token := range tokens {
		if _, duplicate := seen[token]; duplicate {
			if !duplicateReported {
				state.Issues = append(state.Issues, "duplicate-status-token")
				duplicateReported = true
			}
			continue
		}
		seen[token] = struct{}{}
		state.Status.Raw = append(state.Status.Raw, token)
	}

	_, online := seen["OL"]
	_, onBattery := seen["OB"]
	_, off := seen["OFF"]
	if boolCount(online, onBattery, off) > 1 {
		state.Availability = AvailabilityUnavailable
		state.AvailabilityReason = "conflicting-power-status"
		state.Issues = append(state.Issues, "conflicting-power-status")
	} else {
		switch {
		case online:
			state.Status.PowerSource = PowerSourceMains
		case onBattery:
			state.Status.PowerSource = PowerSourceBattery
		case off:
			state.Status.PowerSource = PowerSourceOff
		default:
			state.Availability = AvailabilityUnavailable
			state.AvailabilityReason = "unknown-power-status"
			state.Issues = append(state.Issues, "unknown-power-status")
		}
	}
	state.Status.OnBattery = Truth{Value: onBattery, Known: online || onBattery || off}
	state.Status.LowBattery = knownStatusFlag(seen, "LB")
	state.Status.Bypass = knownStatusFlag(seen, "BYPASS")
	state.Status.Overloaded = knownStatusFlag(seen, "OVER")
	state.Status.ReplaceBattery = knownStatusFlag(seen, "RB")
}

func mapChargerStatus(state *State, variables map[string]string) {
	legacyCharging := statusHasToken(state.Status.Raw, "CHRG")
	legacyDischarging := statusHasToken(state.Status.Raw, "DISCHRG")
	raw, modernPresent := variables["battery.charger.status"]
	var charging, discharging Truth
	if modernPresent {
		switch strings.ToLower(strings.TrimSpace(raw)) {
		case "charging":
			charging = Truth{Value: true, Known: true}
			discharging = Truth{Value: false, Known: true}
		case "discharging":
			charging = Truth{Value: false, Known: true}
			discharging = Truth{Value: true, Known: true}
		case "floating", "resting":
			charging = Truth{Value: false, Known: true}
			discharging = Truth{Value: false, Known: true}
		default:
			state.Issues = append(state.Issues, "invalid-battery-charger-status")
			return
		}
	}

	if legacyCharging && legacyDischarging {
		state.Issues = append(state.Issues, "conflicting-charge-status")
		return
	}
	if !modernPresent {
		switch {
		case legacyCharging:
			state.Status.Charging = Truth{Value: true, Known: true}
			state.Status.Discharging = Truth{Value: false, Known: true}
		case legacyDischarging:
			state.Status.Charging = Truth{Value: false, Known: true}
			state.Status.Discharging = Truth{Value: true, Known: true}
		}
		return
	}

	if (legacyCharging && !charging.Value) || (legacyDischarging && !discharging.Value) {
		state.Issues = append(state.Issues, "conflicting-charge-status")
		return
	}
	state.Status.Charging = charging
	state.Status.Discharging = discharging
}

func statusHasToken(tokens []string, want string) bool {
	for _, token := range tokens {
		if token == want {
			return true
		}
	}
	return false
}

func knownStatusFlag(tokens map[string]struct{}, name string) Truth {
	_, value := tokens[name]
	return Truth{Value: value, Known: true}
}

func boolCount(values ...bool) int {
	count := 0
	for _, value := range values {
		if value {
			count++
		}
	}
	return count
}

func mapBeeperStatus(state *State, variables map[string]string) {
	raw, exists := variables["ups.beeper.status"]
	if !exists {
		return
	}
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "enabled":
		state.BeeperStatus = BeeperStatusEnabled
	case "disabled":
		state.BeeperStatus = BeeperStatusDisabled
	case "muted":
		state.BeeperStatus = BeeperStatusMuted
	default:
		state.Issues = append(state.Issues, "invalid-ups-beeper-status")
	}
}

func mapMeasurements(state *State, variables map[string]string) {
	state.Battery.ChargePercent = measurement(variables, "battery.charge", 0, 100, &state.Issues)
	state.Battery.RuntimeSeconds = measurement(variables, "battery.runtime", 0, maxBatteryRuntimeSeconds, &state.Issues)
	state.Battery.Voltage = measurement(variables, "battery.voltage", 0, 1000, &state.Issues)
	state.Battery.TemperatureC = measurement(variables, "ups.temperature", -100, 300, &state.Issues)
	state.Electrical.InputVoltage = measurement(variables, "input.voltage", 0, 1000, &state.Issues)
	state.Electrical.OutputVoltage = measurement(variables, "output.voltage", 0, 1000, &state.Issues)
	state.Electrical.OutputCurrent = measurement(variables, "output.current", 0, 10000, &state.Issues)
	state.Electrical.OutputPowerW = aliasedPowerMeasurement(variables, "ups.realpower", "output.realpower", true, &state.Issues)
	state.Electrical.OutputPowerNominalW = aliasedPowerMeasurement(variables, "ups.realpower.nominal", "output.realpower.nominal", false, &state.Issues)
	state.Electrical.OutputApparentPowerVA = aliasedPowerMeasurement(variables, "ups.power", "output.power", true, &state.Issues)
	state.Electrical.OutputApparentPowerNominalVA = aliasedPowerMeasurement(variables, "ups.power.nominal", "output.power.nominal", false, &state.Issues)
	state.Electrical.OutputPowerFactor = outputPowerFactor(variables, state.Electrical, &state.Issues)
	state.Electrical.LoadPercent = measurement(variables, "ups.load", 0, 100, &state.Issues)
}

func aliasedPowerMeasurement(variables map[string]string, primary, alternate string, allowZero bool, issues *[]string) Measurement {
	primaryRaw, primaryPresent := variables[primary]
	alternateRaw, alternatePresent := variables[alternate]
	if !primaryPresent && !alternatePresent {
		return Measurement{}
	}

	primaryValue, primaryValid := Measurement{}, true
	if primaryPresent {
		primaryValue, primaryValid = parseMeasurementValue(primaryRaw, 0, maxObservedPower)
		if primaryValid && !allowZero && primaryValue.Value == 0 {
			primaryValid = false
		}
		if !primaryValid {
			*issues = append(*issues, "invalid-"+strings.ReplaceAll(primary, ".", "-"))
		}
	}
	alternateValue, alternateValid := Measurement{}, true
	if alternatePresent {
		alternateValue, alternateValid = parseMeasurementValue(alternateRaw, 0, maxObservedPower)
		if alternateValid && !allowZero && alternateValue.Value == 0 {
			alternateValid = false
		}
		if !alternateValid {
			*issues = append(*issues, "invalid-"+strings.ReplaceAll(alternate, ".", "-"))
		}
	}
	if !primaryValid || !alternateValid {
		return Measurement{}
	}
	if primaryPresent && alternatePresent {
		if primaryValue.Value != alternateValue.Value {
			*issues = append(*issues, "conflicting-"+strings.ReplaceAll(primary, ".", "-"))
			return Measurement{}
		}
		return primaryValue
	}
	if primaryPresent {
		return primaryValue
	}
	return alternateValue
}

func outputPowerFactor(variables map[string]string, electrical Electrical, issues *[]string) Measurement {
	if raw, present := variables["output.powerfactor"]; present {
		value, valid := parseMeasurementValue(raw, 0, 1)
		if !valid {
			*issues = append(*issues, "invalid-output-powerfactor")
			return Measurement{}
		}
		return value
	}
	if !electrical.OutputPowerW.Known || !electrical.OutputApparentPowerVA.Known || electrical.OutputApparentPowerVA.Value == 0 {
		return Measurement{}
	}
	if electrical.OutputPowerW.Value > electrical.OutputApparentPowerVA.Value {
		*issues = append(*issues, "invalid-derived-output-powerfactor")
		return Measurement{}
	}
	value := electrical.OutputPowerW.Value / electrical.OutputApparentPowerVA.Value
	if math.IsNaN(value) || math.IsInf(value, 0) || value < 0 || value > 1 {
		*issues = append(*issues, "invalid-derived-output-powerfactor")
		return Measurement{}
	}
	return Measurement{Value: value, Known: true}
}

func mapOutletTelemetry(state *State, variables map[string]string) {
	globalSwitchable := Truth{}
	if raw, ok := variables["outlet.switchable"]; ok {
		globalSwitchable = parseTruth(raw)
		if !globalSwitchable.Known {
			state.Issues = append(state.Issues, "invalid-outlet-switchable")
		}
	}
	for outletIndex := range state.Outlets {
		outlet := &state.Outlets[outletIndex]
		prefix := fmt.Sprintf("outlet.%d.", outlet.Index)
		if description, ok := variables[prefix+"desc"]; ok && strings.TrimSpace(description) != "" {
			if value := optionalNativeText(description, 128); value != "" {
				outlet.Name = value
				outlet.NameObserved = true
			} else {
				state.Issues = append(state.Issues, fmt.Sprintf("invalid-outlet-%d-description", outlet.Index))
			}
		} else if name, ok := variables[prefix+"name"]; ok && strings.TrimSpace(name) != "" {
			if value := optionalNativeText(name, 128); value != "" {
				outlet.Name = value
				outlet.NameObserved = true
			} else {
				state.Issues = append(state.Issues, fmt.Sprintf("invalid-outlet-%d-name", outlet.Index))
			}
		}
		outlet.Type = classifyOutletType(variables[prefix+"type"], variables[prefix+"designator"])
		outlet.Switchable = globalSwitchable
		if outlet.RelayGroup >= 1 && outlet.RelayGroup <= len(state.Groups) {
			group := state.Groups[outlet.RelayGroup-1]
			if group.SwitchablePresent {
				outlet.Switchable = group.Switchable
			}
		}
		if raw, ok := variables[prefix+"switchable"]; ok {
			outlet.Switchable = parseTruth(raw)
			if !outlet.Switchable.Known {
				state.Issues = append(state.Issues, fmt.Sprintf("invalid-outlet-%d-switchable", outlet.Index))
			}
		}
		if raw, ok := variables[prefix+"status"]; ok {
			outlet.RelayState = parseRelay(raw)
			if outlet.RelayState == RelayUnknown {
				state.Issues = append(state.Issues, fmt.Sprintf("invalid-outlet-%d-status", outlet.Index))
			}
		}
		outlet.Voltage = measurement(variables, prefix+"voltage", 0, 1000, &state.Issues)
		outlet.Current = measurement(variables, prefix+"current", 0, 10000, &state.Issues)
		outlet.PowerW = measurement(variables, prefix+"realpower", 0, maxObservedPower, &state.Issues)
		outlet.PowerFactor = measurement(variables, prefix+"powerfactor", 0, 1, &state.Issues)
		// Voltage alone does not prove a load/power meter. Apparent power is
		// enough to advertise metering, but is not mislabeled as real watts.
		_, hasCurrent := variables[prefix+"current"]
		_, hasRealPower := variables[prefix+"realpower"]
		_, hasApparentPower := variables[prefix+"power"]
		outlet.PowerMeter = hasCurrent || hasRealPower || hasApparentPower
	}
}

func mapGroupRelayStates(state *State) {
	for groupIndex := range state.Groups {
		group := &state.Groups[groupIndex]
		members := make([]Outlet, 0, len(group.OutletIndices))
		for _, outletIndex := range group.OutletIndices {
			if outletIndex >= 1 && outletIndex <= len(state.Outlets) {
				members = append(members, state.Outlets[outletIndex-1])
			}
		}
		derivedState := deriveGroupRelay(members)
		if group.SourceIndex == 0 {
			group.RelayState = derivedState
			continue
		}
		if group.SourceIndex > len(state.NativeGroups) {
			group.RelayState = RelayUnknown
			state.Issues = append(state.Issues, fmt.Sprintf("invalid-relay-group-%d-source", group.Index))
			continue
		}
		nativeGroup := state.NativeGroups[group.SourceIndex-1]
		if nativeGroup.RelayStatePresent {
			if nativeGroup.RelayState == RelayUnknown {
				group.RelayState = RelayUnknown
				continue
			}
			if relayEvidenceConflicts(members, nativeGroup.RelayState) {
				group.RelayState = RelayUnknown
				state.Issues = append(state.Issues, fmt.Sprintf("conflicting-relay-group-%d-status", group.Index))
				continue
			}
			group.RelayState = nativeGroup.RelayState
			continue
		}
		group.RelayState = derivedState
	}
}

func relayEvidenceConflicts(outlets []Outlet, groupState RelayState) bool {
	for _, outlet := range outlets {
		if (outlet.RelayState == RelayOn || outlet.RelayState == RelayOff) && outlet.RelayState != groupState {
			return true
		}
	}
	return false
}

func deriveGroupRelay(outlets []Outlet) RelayState {
	if len(outlets) == 0 {
		return RelayUnknown
	}
	first := outlets[0].RelayState
	if first != RelayOn && first != RelayOff {
		return RelayUnknown
	}
	for _, outlet := range outlets[1:] {
		if outlet.RelayState == RelayUnknown {
			return RelayUnknown
		}
		if outlet.RelayState != first {
			return RelayMixed
		}
	}
	return first
}

func parseRelay(raw string) RelayState {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "on":
		return RelayOn
	case "off":
		return RelayOff
	default:
		return RelayUnknown
	}
}

func parseTruth(raw string) Truth {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "yes", "true", "on", "1":
		return Truth{Value: true, Known: true}
	case "no", "false", "off", "0":
		return Truth{Value: false, Known: true}
	default:
		return Truth{}
	}
}

func classifyOutletType(rawType, rawDesignator string) OutletType {
	for _, raw := range []string{rawType, rawDesignator} {
		value := strings.ToLower(strings.TrimSpace(raw))
		if value == "" || value == "unknown" {
			continue
		}
		tokens := strings.FieldsFunc(value, func(r rune) bool {
			return (r < 'a' || r > 'z') && (r < '0' || r > '9')
		})
		if len(tokens) != 0 && (tokens[0] == "usb" || tokens[0] == "usba" || tokens[0] == "usbc") {
			return OutletTypeUSB
		}
		compact := strings.NewReplacer("-", "", "_", "", " ", "").Replace(value)
		switch compact {
		case "ac", "schuko", "french", "uk", "i520r", "iecc13", "iecc19",
			"nema515", "nema51520", "nema520", "nemal520", "nemal530",
			"nema615", "nema620", "nemal620", "nemal630", "nemal715", "rf203p277":
			return OutletTypeAC
		}
	}
	return OutletTypeUnknown
}

func measurement(variables map[string]string, name string, minimum, maximum float64, issues *[]string) Measurement {
	raw, exists := variables[name]
	if !exists || strings.TrimSpace(raw) == "" {
		return Measurement{}
	}
	value, valid := parseMeasurementValue(raw, minimum, maximum)
	if !valid {
		*issues = append(*issues, "invalid-"+strings.ReplaceAll(name, ".", "-"))
		return Measurement{}
	}
	return value
}

func parseMeasurementValue(raw string, minimum, maximum float64) (Measurement, bool) {
	value, err := strconv.ParseFloat(strings.TrimSpace(raw), 64)
	if err != nil || math.IsNaN(value) || math.IsInf(value, 0) || value < minimum || value > maximum {
		return Measurement{}, false
	}
	return Measurement{Value: value, Known: true}, true
}
