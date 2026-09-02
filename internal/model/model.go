// Package model maps a raw NUT observation to the conservative UPS model sent
// to UniFi. Fixed outlet topology is emulation metadata; telemetry is only
// marked known when the upstream observation proves it.
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
	maxObservedPowerW        = 1_000_000_000
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

// RelayState represents an observed outlet/group state. Unknown is distinct
// from off; Mixed is a derived state based on four observed outlet states.
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
	InputVoltage      Measurement
	OutputVoltage     Measurement
	OutputCurrent     Measurement
	OutputPowerW      Measurement
	OutputPowerFactor Measurement
	LoadPercent       Measurement
}

// Outlet is one of the eight configured emulated outlets. RelayGroup and index
// are topology, while all electrical fields and RelayState are observations.
type Outlet struct {
	Index        int
	RelayGroup   int
	Name         string
	NameObserved bool
	RelayState   RelayState
	Voltage      Measurement
	Current      Measurement
	PowerW       Measurement
	PowerFactor  Measurement
}

// Zone is one four-outlet relay group.
type Zone struct {
	Index         int
	Name          string
	OutletIndices [4]int
	RelayState    RelayState
}

// State is the conservative canonical view consumed by protocol projections.
// Issues contains bounded machine-readable codes, never raw upstream values.
type State struct {
	Availability       Availability
	AvailabilityReason string
	ObservedAt         time.Time
	Age                time.Duration
	Status             Status
	Battery            Battery
	Electrical         Electrical
	Zones              [2]Zone
	Outlets            [8]Outlet
	Issues             []string
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
	}
	initializeTopology(&state)

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

	mapStatus(&state, snapshot.Variables["ups.status"])
	mapMeasurements(&state, snapshot.Variables)
	mapOutletTelemetry(&state, snapshot.Variables)
	mapZoneRelayStates(&state, snapshot.Variables)
	return state
}

func initializeTopology(state *State) {
	for zoneIndex := range state.Zones {
		firstOutlet := zoneIndex*4 + 1
		zone := Zone{
			Index:         zoneIndex + 1,
			Name:          fmt.Sprintf("Zone %d", zoneIndex+1),
			OutletIndices: [4]int{firstOutlet, firstOutlet + 1, firstOutlet + 2, firstOutlet + 3},
			RelayState:    RelayUnknown,
		}
		state.Zones[zoneIndex] = zone
	}
	for outletIndex := range state.Outlets {
		index := outletIndex + 1
		state.Outlets[outletIndex] = Outlet{
			Index:      index,
			RelayGroup: (outletIndex / 4) + 1,
			Name:       fmt.Sprintf("Outlet %d", index),
			RelayState: RelayUnknown,
		}
	}
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
	for _, token := range tokens {
		if _, duplicate := seen[token]; duplicate {
			state.Issues = append(state.Issues, "duplicate-status-token")
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
	_, charging := seen["CHRG"]
	_, discharging := seen["DISCHRG"]
	if charging && discharging {
		state.Availability = AvailabilityUnavailable
		state.AvailabilityReason = "conflicting-charge-status"
		state.Issues = append(state.Issues, "conflicting-charge-status")
	}
	state.Status.OnBattery = Truth{Value: onBattery, Known: online || onBattery || off}
	state.Status.LowBattery = knownStatusFlag(seen, "LB")
	state.Status.Charging = knownStatusFlag(seen, "CHRG")
	state.Status.Discharging = knownStatusFlag(seen, "DISCHRG")
	state.Status.Bypass = knownStatusFlag(seen, "BYPASS")
	state.Status.Overloaded = knownStatusFlag(seen, "OVER")
	state.Status.ReplaceBattery = knownStatusFlag(seen, "RB")
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

func mapMeasurements(state *State, variables map[string]string) {
	state.Battery.ChargePercent = measurement(variables, "battery.charge", 0, 100, &state.Issues)
	state.Battery.RuntimeSeconds = measurement(variables, "battery.runtime", 0, maxBatteryRuntimeSeconds, &state.Issues)
	state.Battery.Voltage = measurement(variables, "battery.voltage", 0, 1000, &state.Issues)
	state.Battery.TemperatureC = measurement(variables, "ups.temperature", -100, 300, &state.Issues)
	state.Electrical.InputVoltage = measurement(variables, "input.voltage", 0, 1000, &state.Issues)
	state.Electrical.OutputVoltage = measurement(variables, "output.voltage", 0, 1000, &state.Issues)
	state.Electrical.OutputCurrent = measurement(variables, "output.current", 0, 10000, &state.Issues)
	state.Electrical.OutputPowerW = measurement(variables, "ups.realpower", 0, maxObservedPowerW, &state.Issues)
	state.Electrical.OutputPowerFactor = measurement(variables, "output.powerfactor", 0, 1.5, &state.Issues)
	state.Electrical.LoadPercent = measurement(variables, "ups.load", 0, 100, &state.Issues)
}

func mapOutletTelemetry(state *State, variables map[string]string) {
	for outletIndex := range state.Outlets {
		outlet := &state.Outlets[outletIndex]
		prefix := fmt.Sprintf("outlet.%d.", outlet.Index)
		if description, ok := variables[prefix+"desc"]; ok && strings.TrimSpace(description) != "" {
			if len(description) <= 128 {
				outlet.Name = description
				outlet.NameObserved = true
			} else {
				state.Issues = append(state.Issues, fmt.Sprintf("invalid-outlet-%d-description", outlet.Index))
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
		outlet.PowerW = measurement(variables, prefix+"realpower", 0, maxObservedPowerW, &state.Issues)
		outlet.PowerFactor = measurement(variables, prefix+"powerfactor", 0, 1.5, &state.Issues)
	}
}

func mapZoneRelayStates(state *State, variables map[string]string) {
	for zoneIndex := range state.Zones {
		zone := &state.Zones[zoneIndex]
		groupVariable := fmt.Sprintf("outlet.group.%d.status", zone.Index)
		if raw, ok := variables[groupVariable]; ok {
			groupState := parseRelay(raw)
			if groupState == RelayUnknown {
				state.Issues = append(state.Issues, fmt.Sprintf("invalid-zone-%d-status", zone.Index))
				continue
			}
			derivedState := deriveGroupRelay(state.Outlets[(zone.Index-1)*4 : zone.Index*4])
			if derivedState != RelayUnknown && derivedState != groupState {
				zone.RelayState = RelayUnknown
				state.Issues = append(state.Issues, fmt.Sprintf("conflicting-zone-%d-status", zone.Index))
				continue
			}
			zone.RelayState = groupState
			continue
		}
		zone.RelayState = deriveGroupRelay(state.Outlets[(zone.Index-1)*4 : zone.Index*4])
	}
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

func measurement(variables map[string]string, name string, minimum, maximum float64, issues *[]string) Measurement {
	raw, exists := variables[name]
	if !exists || strings.TrimSpace(raw) == "" {
		return Measurement{}
	}
	value, err := strconv.ParseFloat(strings.TrimSpace(raw), 64)
	if err != nil || math.IsNaN(value) || math.IsInf(value, 0) || value < minimum || value > maximum {
		*issues = append(*issues, "invalid-"+strings.ReplaceAll(name, ".", "-"))
		return Measurement{}
	}
	return Measurement{Value: value, Known: true}
}
