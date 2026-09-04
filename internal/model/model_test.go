package model

import (
	"fmt"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/d3vi1/nut-2-unifi-ups-gateway/internal/nut"
)

func TestFromSnapshotMapsFreshTelemetryAndFallbackTopology(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	variables := map[string]string{
		"ups.status":            "OL CHRG",
		"battery.charge":        "100",
		"battery.runtime":       "2040",
		"battery.voltage":       "27.10",
		"ups.temperature":       "24.5",
		"input.voltage":         "231.2",
		"output.voltage":        "230.8",
		"output.current":        "1.25",
		"ups.realpower":         "225",
		"output.powerfactor":    "0.91",
		"ups.load":              "15",
		"outlet.1.desc":         "NVR",
		"outlet.1.status":       "on",
		"outlet.1.voltage":      "230.7",
		"outlet.group.2.status": "off",
	}
	for index := 2; index <= 4; index++ {
		variables[fmt.Sprintf("outlet.%d.status", index)] = "on"
	}
	state := FromSnapshot(nut.Snapshot{
		UPSName:     "ups",
		Variables:   variables,
		CollectedAt: now.Add(-5 * time.Second),
	}, Options{
		Now:        now,
		StaleAfter: 20 * time.Second,
	})

	if state.Availability != AvailabilityAvailable || state.Age != 5*time.Second {
		t.Fatalf("unexpected availability: %+v", state)
	}
	if state.Status.PowerSource != PowerSourceMains || !state.Status.Charging.Known || !state.Status.Charging.Value {
		t.Fatalf("unexpected status: %+v", state.Status)
	}
	if !state.Battery.ChargePercent.Known || state.Battery.ChargePercent.Value != 100 ||
		!state.Battery.RuntimeSeconds.Known || state.Battery.RuntimeSeconds.Value != 2040 {
		t.Fatalf("unexpected battery telemetry: %+v", state.Battery)
	}
	if len(state.Outlets) != 8 || state.Outlets[0].RelayGroup != 1 || state.Outlets[4].RelayGroup != 2 {
		t.Fatalf("unexpected outlet topology: %+v", state.Outlets)
	}
	if got := state.Groups[0].OutletIndices; !equalInts(got, []int{1, 2, 3, 4}) {
		t.Fatalf("group 1 outlet indices = %v", got)
	}
	if got := state.Groups[1].OutletIndices; !equalInts(got, []int{5, 6, 7, 8}) {
		t.Fatalf("group 2 outlet indices = %v", got)
	}
	if state.Groups[0].RelayState != RelayOn || state.Groups[1].RelayState != RelayUnknown {
		t.Fatalf("unexpected group relay states: %+v", state.Groups)
	}
	if state.Outlets[0].Name != "NVR" || !state.Outlets[0].NameObserved {
		t.Fatalf("observed outlet description was not preserved: %+v", state.Outlets[0])
	}
}

func TestFromSnapshotDoesNotInventTelemetry(t *testing.T) {
	now := time.Now().UTC()
	state := FromSnapshot(nut.Snapshot{
		UPSName:     "ups",
		Variables:   map[string]string{"ups.status": "OL"},
		CollectedAt: now,
	}, Options{Now: now})

	if state.Availability != AvailabilityAvailable {
		t.Fatalf("unexpected availability %q", state.Availability)
	}
	if state.Battery.ChargePercent.Known || state.Battery.RuntimeSeconds.Known || state.Electrical.LoadPercent.Known {
		t.Fatalf("absent measurements were invented: %+v %+v", state.Battery, state.Electrical)
	}
	for _, outlet := range state.Outlets {
		if outlet.RelayState != RelayUnknown || outlet.Voltage.Known || outlet.Current.Known || outlet.PowerW.Known {
			t.Fatalf("absent outlet telemetry was invented: %+v", outlet)
		}
	}
}

func TestStaleUnavailableAndConflictingStateAreExplicit(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name         string
		snapshot     nut.Snapshot
		availability Availability
		reason       string
	}{
		{
			name:         "no observation",
			snapshot:     nut.Snapshot{},
			availability: AvailabilityUnavailable,
			reason:       "no-observation",
		},
		{
			name: "stale",
			snapshot: nut.Snapshot{
				Variables:   map[string]string{"ups.status": "OL"},
				CollectedAt: now.Add(-21 * time.Second),
			},
			availability: AvailabilityStale,
			reason:       "observation-too-old",
		},
		{
			name: "missing status",
			snapshot: nut.Snapshot{
				Variables:   map[string]string{"battery.charge": "100"},
				CollectedAt: now,
			},
			availability: AvailabilityUnavailable,
			reason:       "missing-ups-status",
		},
		{
			name: "conflicting status",
			snapshot: nut.Snapshot{
				Variables:   map[string]string{"ups.status": "OL OB"},
				CollectedAt: now,
			},
			availability: AvailabilityUnavailable,
			reason:       "conflicting-power-status",
		},
		{
			name: "future observation",
			snapshot: nut.Snapshot{
				Variables:   map[string]string{"ups.status": "OL"},
				CollectedAt: now.Add(time.Second),
			},
			availability: AvailabilityUnavailable,
			reason:       "observation-in-future",
		},
		{
			name: "unknown power source",
			snapshot: nut.Snapshot{
				Variables:   map[string]string{"ups.status": "CAL"},
				CollectedAt: now,
			},
			availability: AvailabilityUnavailable,
			reason:       "unknown-power-status",
		},
		{
			name: "conflicting charge state",
			snapshot: nut.Snapshot{
				Variables:   map[string]string{"ups.status": "OL CHRG DISCHRG"},
				CollectedAt: now,
			},
			availability: AvailabilityAvailable,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			state := FromSnapshot(test.snapshot, Options{Now: now, StaleAfter: 20 * time.Second})
			if state.Availability != test.availability || state.AvailabilityReason != test.reason {
				t.Fatalf("availability = %q (%q), want %q (%q)", state.Availability, state.AvailabilityReason, test.availability, test.reason)
			}
		})
	}
}

func TestMalformedMeasurementsRemainUnknown(t *testing.T) {
	now := time.Now().UTC()
	state := FromSnapshot(nut.Snapshot{
		Variables: map[string]string{
			"ups.status":       "OB LB DISCHRG",
			"battery.charge":   "101",
			"battery.runtime":  "NaN",
			"input.voltage":    "not-a-number",
			"outlet.1.status":  "maybe",
			"outlet.1.voltage": "-1",
		},
		CollectedAt: now,
	}, Options{Now: now})
	if state.Battery.ChargePercent.Known || state.Battery.RuntimeSeconds.Known || state.Electrical.InputVoltage.Known {
		t.Fatalf("malformed measurements were promoted: %+v %+v", state.Battery, state.Electrical)
	}
	if state.Outlets[0].RelayState != RelayUnknown || state.Outlets[0].Voltage.Known {
		t.Fatalf("malformed outlet values were promoted: %+v", state.Outlets[0])
	}
	if state.Status.PowerSource != PowerSourceBattery || !state.Status.LowBattery.Value || !state.Status.Discharging.Value {
		t.Fatalf("valid status tokens were lost: %+v", state.Status)
	}
	if len(state.Issues) < 5 {
		t.Fatalf("expected bounded issue codes, got %v", state.Issues)
	}
}

func TestOverflowingRuntimeAndPowerRemainUnknown(t *testing.T) {
	now := time.Now().UTC()
	state := FromSnapshot(nut.Snapshot{
		Variables: map[string]string{
			"ups.status":         "OL",
			"battery.runtime":    "1e100",
			"ups.realpower":      "1e100",
			"outlet.1.realpower": "1e100",
		},
		CollectedAt: now,
	}, Options{Now: now})
	if state.Battery.RuntimeSeconds.Known || state.Electrical.OutputPowerW.Known || state.Outlets[0].PowerW.Known {
		t.Fatalf("overflowing values were promoted: battery=%+v electrical=%+v outlet=%+v", state.Battery, state.Electrical, state.Outlets[0])
	}
}

func TestNominalRealPowerMapsOnlyFromDirectWattMeasurement(t *testing.T) {
	now := time.Now().UTC()
	state := FromSnapshot(nut.Snapshot{
		Variables: map[string]string{
			"ups.status":            "OL",
			"ups.realpower.nominal": "865.5",
			"ups.power.nominal":     "1500",
			"ups.load":              "15",
			"output.voltage":        "230",
			"output.current":        "1",
		},
		CollectedAt: now,
	}, Options{Now: now})

	if !state.Electrical.OutputPowerNominalW.Known || state.Electrical.OutputPowerNominalW.Value != 865.5 {
		t.Fatalf("direct nominal real power was not retained: %+v", state.Electrical)
	}

	withoutRealPower := FromSnapshot(nut.Snapshot{
		Variables: map[string]string{
			"ups.status":        "OL",
			"ups.power.nominal": "1500",
			"ups.load":          "15",
			"output.voltage":    "230",
			"output.current":    "1",
		},
		CollectedAt: now,
	}, Options{Now: now})
	if withoutRealPower.Electrical.OutputPowerNominalW.Known {
		t.Fatalf("VA, load, or V*A was mislabeled as nominal watts: %+v", withoutRealPower.Electrical)
	}
}

func TestMalformedNominalRealPowerRemainsUnknown(t *testing.T) {
	now := time.Now().UTC()
	state := FromSnapshot(nut.Snapshot{
		Variables: map[string]string{
			"ups.status":            "OL",
			"ups.realpower.nominal": "not-watts",
		},
		CollectedAt: now,
	}, Options{Now: now})

	if state.Electrical.OutputPowerNominalW.Known {
		t.Fatalf("malformed nominal real power was promoted: %+v", state.Electrical.OutputPowerNominalW)
	}
	if !containsIssue(state.Issues, "invalid-ups-realpower-nominal") {
		t.Fatalf("malformed nominal real power was not reported with a bounded issue: %v", state.Issues)
	}
}

func TestApparentPowerVoltageCurrentAndLoadDoNotInventWatts(t *testing.T) {
	now := time.Now().UTC()
	state := FromSnapshot(nut.Snapshot{
		Variables: map[string]string{
			"ups.status":        "OL",
			"output.voltage":    "233.1",
			"output.current":    "1",
			"ups.load":          "44",
			"ups.power":         "234",
			"ups.power.nominal": "1500",
		},
		CollectedAt: now,
	}, Options{Now: now})

	if state.Electrical.OutputPowerW.Known || state.Electrical.OutputPowerNominalW.Known {
		t.Fatalf("VA, voltage, current, or load invented watts: %+v", state.Electrical)
	}
	if !state.Electrical.OutputApparentPowerVA.Known || state.Electrical.OutputApparentPowerVA.Value != 234 ||
		!state.Electrical.OutputApparentPowerNominalVA.Known || state.Electrical.OutputApparentPowerNominalVA.Value != 1500 {
		t.Fatalf("canonical VA evidence was not retained: %+v", state.Electrical)
	}
}

func TestElectricalPowerAliasesResolveFailClosed(t *testing.T) {
	now := time.Now().UTC()
	type aliasField struct {
		name        string
		primary     string
		alternate   string
		allowZero   bool
		measurement func(State) Measurement
	}
	fields := []aliasField{
		{name: "actual watts", primary: "ups.realpower", alternate: "output.realpower", allowZero: true, measurement: func(state State) Measurement { return state.Electrical.OutputPowerW }},
		{name: "nominal watts", primary: "ups.realpower.nominal", alternate: "output.realpower.nominal", measurement: func(state State) Measurement { return state.Electrical.OutputPowerNominalW }},
		{name: "actual volt-amperes", primary: "ups.power", alternate: "output.power", allowZero: true, measurement: func(state State) Measurement { return state.Electrical.OutputApparentPowerVA }},
		{name: "nominal volt-amperes", primary: "ups.power.nominal", alternate: "output.power.nominal", measurement: func(state State) Measurement { return state.Electrical.OutputApparentPowerNominalVA }},
	}
	tests := []struct {
		name              string
		primary           string
		alternate         string
		wantKnown         bool
		wantValue         float64
		wantIssueFor      string
		wantConflictIssue bool
	}{
		{name: "primary only", primary: "104", wantKnown: true, wantValue: 104},
		{name: "alternate only", alternate: "104", wantKnown: true, wantValue: 104},
		{name: "equal numeric aliases", primary: "104", alternate: "104.0", wantKnown: true, wantValue: 104},
		{name: "conflicting aliases", primary: "104", alternate: "234", wantConflictIssue: true},
		{name: "malformed primary blocks alternate", primary: "invalid", alternate: "104", wantIssueFor: "primary"},
		{name: "malformed alternate blocks primary", primary: "104", alternate: "invalid", wantIssueFor: "alternate"},
		{name: "blank primary blocks alternate", primary: " ", alternate: "104", wantIssueFor: "primary"},
		{name: "negative", primary: "-1", wantIssueFor: "primary"},
		{name: "zero", primary: "0"},
	}

	for _, field := range fields {
		field := field
		for _, test := range tests {
			test := test
			t.Run(field.name+"/"+test.name, func(t *testing.T) {
				variables := map[string]string{"ups.status": "OL"}
				if test.primary != "" {
					variables[field.primary] = test.primary
				}
				if test.alternate != "" {
					variables[field.alternate] = test.alternate
				}
				state := FromSnapshot(nut.Snapshot{Variables: variables, CollectedAt: now}, Options{Now: now})
				got := field.measurement(state)
				wantKnown := test.wantKnown
				if test.name == "zero" {
					wantKnown = field.allowZero
				}
				if got.Known != wantKnown || (wantKnown && got.Value != test.wantValue) {
					t.Fatalf("measurement = %+v, want known=%t value=%v; issues=%v", got, wantKnown, test.wantValue, state.Issues)
				}
				if test.wantConflictIssue {
					want := "conflicting-" + strings.ReplaceAll(field.primary, ".", "-")
					if !containsIssue(state.Issues, want) {
						t.Fatalf("conflicting aliases lacked %q: %v", want, state.Issues)
					}
				}
				if test.wantIssueFor != "" || (test.name == "zero" && !field.allowZero) {
					key := field.primary
					if test.wantIssueFor == "alternate" {
						key = field.alternate
					}
					want := "invalid-" + strings.ReplaceAll(key, ".", "-")
					if !containsIssue(state.Issues, want) {
						t.Fatalf("invalid alias lacked %q: %v", want, state.Issues)
					}
				}
			})
		}
	}
}

func TestOutputPowerFactorUsesDirectOrSameSnapshotPower(t *testing.T) {
	now := time.Now().UTC()
	tests := []struct {
		name      string
		variables map[string]string
		wantKnown bool
		wantValue float64
		wantIssue string
	}{
		{
			name: "direct has priority",
			variables: map[string]string{
				"output.powerfactor": "0.8",
				"ups.realpower":      "104",
				"ups.power":          "234",
			},
			wantKnown: true,
			wantValue: 0.8,
		},
		{
			name:      "direct zero boundary",
			variables: map[string]string{"output.powerfactor": "0"},
			wantKnown: true,
			wantValue: 0,
		},
		{
			name:      "direct one boundary",
			variables: map[string]string{"output.powerfactor": "1"},
			wantKnown: true,
			wantValue: 1,
		},
		{
			name: "derive from canonical 104 W and 234 VA",
			variables: map[string]string{
				"ups.realpower": "104",
				"ups.power":     "234",
			},
			wantKnown: true,
			wantValue: 104.0 / 234.0,
		},
		{
			name: "equal watts and volt-amperes derive one",
			variables: map[string]string{
				"ups.realpower": "234",
				"ups.power":     "234",
			},
			wantKnown: true,
			wantValue: 1,
		},
		{
			name: "derive from alternate aliases",
			variables: map[string]string{
				"output.realpower": "104",
				"output.power":     "234",
			},
			wantKnown: true,
			wantValue: 104.0 / 234.0,
		},
		{
			name: "zero watts is a valid ratio",
			variables: map[string]string{
				"ups.realpower": "0",
				"ups.power":     "234",
			},
			wantKnown: true,
			wantValue: 0,
		},
		{
			name: "zero apparent power leaves ratio unknown",
			variables: map[string]string{
				"ups.realpower": "0",
				"ups.power":     "0",
			},
		},
		{
			name: "watts above volt-amperes fail closed",
			variables: map[string]string{
				"ups.realpower": "235",
				"ups.power":     "234",
			},
			wantIssue: "invalid-derived-output-powerfactor",
		},
		{
			name: "malformed direct value blocks derivation",
			variables: map[string]string{
				"output.powerfactor": "malformed",
				"ups.realpower":      "104",
				"ups.power":          "234",
			},
			wantIssue: "invalid-output-powerfactor",
		},
		{
			name: "direct value above one is invalid",
			variables: map[string]string{
				"output.powerfactor": "1.01",
			},
			wantIssue: "invalid-output-powerfactor",
		},
		{
			name: "negative direct value is invalid",
			variables: map[string]string{
				"output.powerfactor": "-0.01",
			},
			wantIssue: "invalid-output-powerfactor",
		},
		{
			name: "nominal power does not derive actual factor",
			variables: map[string]string{
				"ups.realpower.nominal": "1000",
				"ups.power.nominal":     "1500",
			},
		},
		{
			name: "voltage current and load do not derive factor",
			variables: map[string]string{
				"output.voltage": "234",
				"output.current": "1",
				"ups.load":       "44",
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			test.variables["ups.status"] = "OL"
			state := FromSnapshot(nut.Snapshot{Variables: test.variables, CollectedAt: now}, Options{Now: now})
			got := state.Electrical.OutputPowerFactor
			if got.Known != test.wantKnown || (test.wantKnown && math.Abs(got.Value-test.wantValue) > 1e-12) {
				t.Fatalf("power factor = %+v, want known=%t value=%v; issues=%v", got, test.wantKnown, test.wantValue, state.Issues)
			}
			if test.wantIssue != "" && !containsIssue(state.Issues, test.wantIssue) {
				t.Fatalf("missing issue %q: %v", test.wantIssue, state.Issues)
			}
		})
	}
}

func TestBeeperStatusPreservesOnlyStandardTokens(t *testing.T) {
	now := time.Now().UTC()
	tests := []struct {
		name string
		raw  string
		want BeeperStatus
	}{
		{name: "enabled", raw: "enabled", want: BeeperStatusEnabled},
		{name: "disabled case insensitive", raw: " DISABLED ", want: BeeperStatusDisabled},
		{name: "muted case insensitive", raw: "MuTeD", want: BeeperStatusMuted},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			state := FromSnapshot(nut.Snapshot{
				Variables: map[string]string{
					"ups.status":        "OL",
					"ups.beeper.status": test.raw,
				},
				CollectedAt: now,
			}, Options{Now: now})
			if state.BeeperStatus != test.want {
				t.Fatalf("beeper status = %q, want %q", state.BeeperStatus, test.want)
			}
			if containsIssue(state.Issues, "invalid-ups-beeper-status") {
				t.Fatalf("valid beeper status produced an issue: %v", state.Issues)
			}
		})
	}
}

func TestAbsentAndMalformedBeeperStatusRemainUnknown(t *testing.T) {
	now := time.Now().UTC()

	absent := FromSnapshot(nut.Snapshot{
		Variables:   map[string]string{"ups.status": "OL"},
		CollectedAt: now,
	}, Options{Now: now})
	if absent.BeeperStatus != BeeperStatusUnknown {
		t.Fatalf("absent beeper status = %q, want unknown", absent.BeeperStatus)
	}
	if containsIssue(absent.Issues, "invalid-ups-beeper-status") {
		t.Fatalf("absent optional beeper status produced an issue: %v", absent.Issues)
	}

	for _, raw := range []string{"", "unknown", "enabled extra", "1"} {
		t.Run(fmt.Sprintf("raw_%q", raw), func(t *testing.T) {
			state := FromSnapshot(nut.Snapshot{
				Variables: map[string]string{
					"ups.status":        "OL",
					"ups.beeper.status": raw,
				},
				CollectedAt: now,
			}, Options{Now: now})
			if state.BeeperStatus != BeeperStatusUnknown {
				t.Fatalf("malformed beeper status %q became %q", raw, state.BeeperStatus)
			}
			if !containsIssue(state.Issues, "invalid-ups-beeper-status") {
				t.Fatalf("malformed beeper status %q lacked bounded issue: %v", raw, state.Issues)
			}
		})
	}
}

func TestBatteryChargerStatusPrecedenceAndContradictions(t *testing.T) {
	now := time.Now().UTC()
	unknown := Truth{}
	knownTrue := Truth{Value: true, Known: true}
	knownFalse := Truth{Value: false, Known: true}
	tests := []struct {
		name            string
		upsStatus       string
		modern          *string
		wantCharging    Truth
		wantDischarging Truth
		wantIssue       string
	}{
		{name: "no charger evidence", upsStatus: "OL", wantCharging: unknown, wantDischarging: unknown},
		{name: "legacy charging", upsStatus: "OL CHRG", wantCharging: knownTrue, wantDischarging: knownFalse},
		{name: "legacy discharging", upsStatus: "OB DISCHRG", wantCharging: knownFalse, wantDischarging: knownTrue},
		{name: "modern charging", upsStatus: "OL", modern: stringPointer("charging"), wantCharging: knownTrue, wantDischarging: knownFalse},
		{name: "modern discharging", upsStatus: "OB", modern: stringPointer("discharging"), wantCharging: knownFalse, wantDischarging: knownTrue},
		{name: "modern floating", upsStatus: "OL", modern: stringPointer("floating"), wantCharging: knownFalse, wantDischarging: knownFalse},
		{name: "modern resting case insensitive", upsStatus: "OL", modern: stringPointer(" ReStInG "), wantCharging: knownFalse, wantDischarging: knownFalse},
		{name: "matching modern charging", upsStatus: "OL CHRG", modern: stringPointer("charging"), wantCharging: knownTrue, wantDischarging: knownFalse},
		{name: "matching modern discharging", upsStatus: "OB DISCHRG", modern: stringPointer("discharging"), wantCharging: knownFalse, wantDischarging: knownTrue},
		{name: "malformed modern blocks legacy fallback", upsStatus: "OL CHRG", modern: stringPointer("unknown"), wantCharging: unknown, wantDischarging: unknown, wantIssue: "invalid-battery-charger-status"},
		{name: "blank modern blocks legacy fallback", upsStatus: "OL CHRG", modern: stringPointer(" "), wantCharging: unknown, wantDischarging: unknown, wantIssue: "invalid-battery-charger-status"},
		{name: "malformed modern remains primary over contradictory legacy", upsStatus: "OL CHRG DISCHRG", modern: stringPointer("unknown"), wantCharging: unknown, wantDischarging: unknown, wantIssue: "invalid-battery-charger-status"},
		{name: "modern charging contradicts legacy discharging", upsStatus: "OB DISCHRG", modern: stringPointer("charging"), wantCharging: unknown, wantDischarging: unknown, wantIssue: "conflicting-charge-status"},
		{name: "modern discharging contradicts legacy charging", upsStatus: "OL CHRG", modern: stringPointer("discharging"), wantCharging: unknown, wantDischarging: unknown, wantIssue: "conflicting-charge-status"},
		{name: "modern floating contradicts legacy charging", upsStatus: "OL CHRG", modern: stringPointer("floating"), wantCharging: unknown, wantDischarging: unknown, wantIssue: "conflicting-charge-status"},
		{name: "modern resting contradicts legacy discharging", upsStatus: "OB DISCHRG", modern: stringPointer("resting"), wantCharging: unknown, wantDischarging: unknown, wantIssue: "conflicting-charge-status"},
		{name: "legacy contradiction stays local", upsStatus: "OL CHRG DISCHRG", wantCharging: unknown, wantDischarging: unknown, wantIssue: "conflicting-charge-status"},
		{name: "legacy contradiction defeats valid modern state", upsStatus: "OL CHRG DISCHRG", modern: stringPointer("charging"), wantCharging: unknown, wantDischarging: unknown, wantIssue: "conflicting-charge-status"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			variables := map[string]string{"ups.status": test.upsStatus}
			if test.modern != nil {
				variables["battery.charger.status"] = *test.modern
			}
			state := FromSnapshot(nut.Snapshot{Variables: variables, CollectedAt: now}, Options{Now: now})
			if state.Status.Charging != test.wantCharging || state.Status.Discharging != test.wantDischarging {
				t.Fatalf("charger state = charging %+v, discharging %+v; want %+v/%+v", state.Status.Charging, state.Status.Discharging, test.wantCharging, test.wantDischarging)
			}
			if state.Availability != AvailabilityAvailable || state.AvailabilityReason != "" {
				t.Fatalf("charger evidence changed UPS availability: %q (%q)", state.Availability, state.AvailabilityReason)
			}
			if test.wantIssue != "" && !containsIssue(state.Issues, test.wantIssue) {
				t.Fatalf("missing issue %q: %v", test.wantIssue, state.Issues)
			}
		})
	}
}

func TestDuplicateStatusIssueIsEmittedOncePerSnapshot(t *testing.T) {
	now := time.Now().UTC()
	state := FromSnapshot(nut.Snapshot{
		Variables:   map[string]string{"ups.status": "OL CHRG CHRG CHRG OL"},
		CollectedAt: now,
	}, Options{Now: now})

	count := 0
	for _, issue := range state.Issues {
		if issue == "duplicate-status-token" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("duplicate-status-token issue count = %d, want 1: %v", count, state.Issues)
	}
}

func stringPointer(value string) *string {
	return &value
}

func TestFallbackGroupStateIsMixedOnlyFromFourKnownOutlets(t *testing.T) {
	now := time.Now().UTC()
	variables := map[string]string{"ups.status": "OL"}
	for index := 1; index <= 4; index++ {
		variables[fmt.Sprintf("outlet.%d.status", index)] = "on"
	}
	variables["outlet.4.status"] = "off"
	state := FromSnapshot(nut.Snapshot{Variables: variables, CollectedAt: now}, Options{Now: now})
	if state.Groups[0].RelayState != RelayMixed {
		t.Fatalf("group state = %q, want mixed", state.Groups[0].RelayState)
	}
	if state.Groups[1].RelayState != RelayUnknown {
		t.Fatalf("unobserved group state = %q, want unknown", state.Groups[1].RelayState)
	}
}

func TestStrayGroupStatusDoesNotBindSyntheticFallbackTopology(t *testing.T) {
	now := time.Now().UTC()
	variables := map[string]string{
		"ups.status":            "OL",
		"outlet.group.1.status": "off",
	}
	for index := 1; index <= 4; index++ {
		variables[fmt.Sprintf("outlet.%d.status", index)] = "on"
	}
	state := FromSnapshot(nut.Snapshot{Variables: variables, CollectedAt: now}, Options{Now: now})
	if state.Groups[0].RelayState != RelayOn {
		t.Fatalf("fallback member evidence was lost: %+v", state.Groups[0])
	}
	if state.NativeGroupsObserved {
		t.Fatal("stray group row without outlet.group.count became an observed table")
	}
	if containsIssue(state.Issues, "conflicting-relay-group-1-status") {
		t.Fatalf("unbound group row conflicted with synthetic fallback: %v", state.Issues)
	}
}

func TestGroupOnlyNativeTableRetainsPartialEvidenceWithoutInventingOutlets(t *testing.T) {
	now := time.Now().UTC()
	state := FromSnapshot(nut.Snapshot{
		Variables: map[string]string{
			"ups.status":                "OL",
			"outlet.group.count":        "2",
			"outlet.group.1.id":         "bank-a",
			"outlet.group.1.name":       " Critical loads ",
			"outlet.group.1.type":       "vendor-bank",
			"outlet.group.1.count":      "4",
			"outlet.group.1.switchable": "yes",
			"outlet.group.1.status":     "on",
			"outlet.group.2.id":         " bank-b ",
			"outlet.group.2.type":       "opaque group type",
			"outlet.group.2.switchable": "no",
		},
		CollectedAt: now,
	}, Options{Now: now})

	assertFallbackTopology(t, state)
	if !state.NativeGroupsObserved || len(state.NativeGroups) != 2 {
		t.Fatalf("group-only table was not retained: observed=%t rows=%+v", state.NativeGroupsObserved, state.NativeGroups)
	}
	first := state.NativeGroups[0]
	if first.SourceIndex != 1 || first.NativeID != "bank-a" || first.Name != "Critical loads" ||
		first.Type != "vendor-bank" || !first.TypeObserved || first.OutletCount != 4 ||
		!first.OutletCountPresent || !first.OutletCountKnown || !first.SwitchablePresent ||
		first.Switchable != (Truth{Value: true, Known: true}) || !first.RelayStatePresent || first.RelayState != RelayOn {
		t.Fatalf("first native group row lost evidence: %+v", first)
	}
	second := state.NativeGroups[1]
	if second.SourceIndex != 2 || second.NativeID != " bank-b " || second.Type != "opaque group type" ||
		!second.TypeObserved || second.OutletCountPresent || second.OutletCountKnown || !second.SwitchablePresent ||
		second.Switchable != (Truth{Value: false, Known: true}) || second.RelayStatePresent || second.RelayState != RelayUnknown {
		t.Fatalf("second native group row lost optional-field provenance: %+v", second)
	}
	if len(state.Issues) != 0 {
		t.Fatalf("valid group-only table produced issues: %v", state.Issues)
	}
}

func TestGroupOnlyElectricalFieldsDoNotLeakIntoUPSOrSyntheticOutlets(t *testing.T) {
	now := time.Now().UTC()
	state := FromSnapshot(nut.Snapshot{
		Variables: map[string]string{
			"ups.status":                 "OL",
			"outlet.group.count":         "1",
			"outlet.group.1.id":          "bank-a",
			"outlet.group.1.voltage":     "234",
			"outlet.group.1.current":     "1",
			"outlet.group.1.realpower":   "104",
			"outlet.group.1.power":       "234",
			"outlet.group.1.powerfactor": "0.44",
		},
		CollectedAt: now,
	}, Options{Now: now})

	assertFallbackTopology(t, state)
	if !state.NativeGroupsObserved || len(state.NativeGroups) != 1 {
		t.Fatalf("native group table was not retained: %+v", state.NativeGroups)
	}
	if state.Electrical.OutputVoltage.Known || state.Electrical.OutputCurrent.Known ||
		state.Electrical.OutputPowerW.Known || state.Electrical.OutputApparentPowerVA.Known || state.Electrical.OutputPowerFactor.Known {
		t.Fatalf("group electrical evidence leaked into UPS-wide telemetry: %+v", state.Electrical)
	}
	for _, outlet := range state.Outlets {
		if outlet.PowerMeter || outlet.Voltage.Known || outlet.Current.Known || outlet.PowerW.Known || outlet.PowerFactor.Known {
			t.Fatalf("group electrical evidence leaked into synthetic outlet: %+v", outlet)
		}
	}
}

func TestNativeGroupTableSurvivesMalformedOutletCount(t *testing.T) {
	now := time.Now().UTC()
	state := FromSnapshot(nut.Snapshot{
		Variables: map[string]string{
			"ups.status":            "OL",
			"outlet.count":          "not-an-integer",
			"outlet.group.count":    "1",
			"outlet.group.1.id":     "bank-a",
			"outlet.group.1.count":  "3",
			"outlet.group.1.type":   "native-only",
			"outlet.group.1.status": "off",
		},
		CollectedAt: now,
	}, Options{Now: now})

	assertFallbackTopology(t, state)
	if !state.NativeGroupsObserved || len(state.NativeGroups) != 1 || state.NativeGroups[0].OutletCount != 3 {
		t.Fatalf("valid group table was discarded with malformed outlet.count: %+v", state.NativeGroups)
	}
	if !containsIssue(state.Issues, "invalid-outlet-count") {
		t.Fatalf("malformed outlet count was not reported: %v", state.Issues)
	}
}

func TestNativeGroupTableCountIsBoundedAndZeroIsObserved(t *testing.T) {
	now := time.Now().UTC()
	tests := []struct {
		name         string
		raw          string
		wantObserved bool
		wantIssue    bool
	}{
		{name: "zero", raw: "0", wantObserved: true},
		{name: "negative", raw: "-1", wantIssue: true},
		{name: "fractional", raw: "1.5", wantIssue: true},
		{name: "over limit", raw: fmt.Sprint(MaxOutletCount + 1), wantIssue: true},
		{name: "not numeric", raw: "NaN", wantIssue: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			state := FromSnapshot(nut.Snapshot{
				Variables: map[string]string{
					"ups.status":            "OL",
					"outlet.group.count":    test.raw,
					"outlet.group.1.id":     "stray-row",
					"outlet.group.1.status": "on",
				},
				CollectedAt: now,
			}, Options{Now: now})
			assertFallbackTopology(t, state)
			if state.NativeGroupsObserved != test.wantObserved || len(state.NativeGroups) != 0 {
				t.Fatalf("native group table = observed %t rows %+v, want observed %t and no rows", state.NativeGroupsObserved, state.NativeGroups, test.wantObserved)
			}
			if got := containsIssue(state.Issues, "invalid-outlet-group-count"); got != test.wantIssue {
				t.Fatalf("invalid count issue = %t, want %t: %v", got, test.wantIssue, state.Issues)
			}
		})
	}
}

func TestNativeGroupRowsRetainOnlySafeMalformedEvidence(t *testing.T) {
	now := time.Now().UTC()
	state := FromSnapshot(nut.Snapshot{
		Variables: map[string]string{
			"ups.status":                "OL",
			"outlet.group.count":        "2",
			"outlet.group.1.name":       "Unidentified row",
			"outlet.group.1.count":      "garbage",
			"outlet.group.1.switchable": "sometimes",
			"outlet.group.1.status":     "maybe",
			"outlet.group.2.id":         "bad\x00id",
			"outlet.group.2.type":       "bad\nkind",
			"outlet.group.2.count":      "0",
		},
		CollectedAt: now,
	}, Options{Now: now})

	if !state.NativeGroupsObserved || len(state.NativeGroups) != 2 {
		t.Fatalf("malformed rows were discarded instead of retained inertly: %+v", state.NativeGroups)
	}
	first := state.NativeGroups[0]
	if first.NativeID != "" || first.Name != "Unidentified row" || !first.OutletCountPresent || first.OutletCountKnown ||
		!first.SwitchablePresent || first.Switchable.Known || !first.RelayStatePresent || first.RelayState != RelayUnknown {
		t.Fatalf("malformed optional evidence was promoted or lost: %+v", first)
	}
	second := state.NativeGroups[1]
	if second.NativeID != "" || second.Type != "" || second.TypeObserved || !second.OutletCountPresent ||
		!second.OutletCountKnown || second.OutletCount != 0 {
		t.Fatalf("invalid identity/type was retained or valid zero count lost: %+v", second)
	}
	for _, want := range []string{
		"missing-outlet-group-1-id",
		"invalid-outlet-group-1-count",
		"invalid-outlet-group-1-switchable",
		"invalid-outlet-group-1-status",
		"invalid-outlet-group-2-id",
		"invalid-outlet-group-2-type",
	} {
		if !containsIssue(state.Issues, want) {
			t.Fatalf("malformed native row lacked %q: %v", want, state.Issues)
		}
	}
}

func TestDuplicateNativeGroupIDsRemainObservableButCannotBindOutlets(t *testing.T) {
	now := time.Now().UTC()
	state := FromSnapshot(nut.Snapshot{
		Variables: map[string]string{
			"ups.status":                "OL",
			"outlet.count":              "2",
			"outlet.1.groupid":          "bank-a",
			"outlet.1.status":           "on",
			"outlet.2.groupid":          "bank-a",
			"outlet.2.status":           "on",
			"outlet.group.count":        "2",
			"outlet.group.1.id":         "bank-a",
			"outlet.group.1.name":       "First row",
			"outlet.group.1.count":      "2",
			"outlet.group.1.switchable": "yes",
			"outlet.group.1.status":     "off",
			"outlet.group.2.id":         "bank-a",
			"outlet.group.2.name":       "Second row",
			"outlet.group.2.count":      "2",
			"outlet.group.2.switchable": "no",
			"outlet.group.2.status":     "off",
		},
		CollectedAt: now,
	}, Options{Now: now})

	if len(state.NativeGroups) != 2 || state.NativeGroups[0].NativeID != "bank-a" || state.NativeGroups[1].NativeID != "bank-a" {
		t.Fatalf("duplicate native rows were not retained in source order: %+v", state.NativeGroups)
	}
	if len(state.Groups) != 1 || state.Groups[0].SourceIndex != 0 || state.Groups[0].Name != "Relay Group 1" ||
		state.Groups[0].SwitchablePresent || state.Groups[0].RelayState != RelayOn {
		t.Fatalf("ambiguous native rows enriched physical topology: %+v", state.Groups)
	}
	if !containsIssue(state.Issues, "duplicate-outlet-group-id") {
		t.Fatalf("duplicate native ID was not reported: %v", state.Issues)
	}
}

func TestObservedOutletCountBuildsDenseOpaqueRelayGroups(t *testing.T) {
	now := time.Now().UTC()
	state := FromSnapshot(nut.Snapshot{
		Variables: map[string]string{
			"ups.status":            "OL",
			"outlet.count":          "5.0",
			"outlet.1.id":           "socket-a",
			"outlet.1.groupid":      "42",
			"outlet.1.status":       "on",
			"outlet.2.id":           "socket-b",
			"outlet.2.groupid":      "42",
			"outlet.2.status":       "on",
			"outlet.3.id":           "socket-c",
			"outlet.3.groupid":      "17",
			"outlet.3.status":       "off",
			"outlet.4.status":       "on",
			"outlet.5.status":       "off",
			"outlet.group.count":    "2",
			"outlet.group.1.id":     "17",
			"outlet.group.1.name":   "Second native table row",
			"outlet.group.1.count":  "1",
			"outlet.group.1.status": "off",
			"outlet.group.2.id":     "42",
			"outlet.group.2.name":   "First dense relay group",
			"outlet.group.2.count":  "2",
			"outlet.group.2.status": "on",
		},
		CollectedAt: now,
	}, Options{Now: now})

	if !state.TopologyObserved {
		t.Fatal("valid outlet.count did not replace the fallback topology")
	}
	if len(state.Outlets) != 5 {
		t.Fatalf("outlet count = %d, want 5", len(state.Outlets))
	}
	if len(state.Groups) != 4 {
		t.Fatalf("group count = %d, want two native groups and two singletons: %+v", len(state.Groups), state.Groups)
	}
	wantRelayGroups := []int{1, 1, 2, 3, 4}
	for offset, want := range wantRelayGroups {
		if got := state.Outlets[offset].RelayGroup; got != want {
			t.Fatalf("outlet %d relay group = %d, want %d", offset+1, got, want)
		}
	}
	if state.Outlets[0].NativeID != "socket-a" || state.Outlets[0].NativeGroupID != "42" {
		t.Fatalf("native outlet identity was not retained: %+v", state.Outlets[0])
	}

	// Dense group 1 comes from the second group-table row. A numeric groupid is
	// an opaque ID, not an implicit outlet.group.N array index.
	first := state.Groups[0]
	if first.NativeID != "42" || first.SourceIndex != 2 || first.Name != "First dense relay group" ||
		!equalInts(first.OutletIndices, []int{1, 2}) || first.RelayState != RelayOn {
		t.Fatalf("opaque group 42 mapped incorrectly: %+v", first)
	}
	second := state.Groups[1]
	if second.NativeID != "17" || second.SourceIndex != 1 || second.Name != "Second native table row" ||
		!equalInts(second.OutletIndices, []int{3}) || second.RelayState != RelayOff {
		t.Fatalf("opaque group 17 mapped incorrectly: %+v", second)
	}
	for offset, wantState := range []RelayState{RelayOn, RelayOff} {
		group := state.Groups[offset+2]
		if group.NativeID != "" || group.SourceIndex != 0 || len(group.OutletIndices) != 1 || group.RelayState != wantState {
			t.Fatalf("missing groupid did not create singleton group %d: %+v", offset+3, group)
		}
	}
	if len(state.Issues) != 0 {
		t.Fatalf("valid topology produced issues: %v", state.Issues)
	}
}

func TestOutletTypeClassificationUsesOnlyExplicitTypeOrDesignator(t *testing.T) {
	now := time.Now().UTC()
	state := FromSnapshot(nut.Snapshot{
		Variables: map[string]string{
			"ups.status":          "OL",
			"outlet.count":        "7",
			"outlet.1.type":       "USB-C",
			"outlet.2.designator": "usb_a",
			"outlet.3.type":       "Schuko",
			"outlet.4.designator": "IEC C13",
			"outlet.5.type":       "DC barrel",
			"outlet.6.type":       "not-usb-accessory",
			"outlet.7.desc":       "USB charger",
		},
		CollectedAt: now,
	}, Options{Now: now})

	want := []OutletType{
		OutletTypeUSB,
		OutletTypeUSB,
		OutletTypeAC,
		OutletTypeAC,
		OutletTypeUnknown,
		OutletTypeUnknown,
		OutletTypeUnknown,
	}
	for offset, wantType := range want {
		if got := state.Outlets[offset].Type; got != wantType {
			t.Fatalf("outlet %d type = %q, want %q", offset+1, got, wantType)
		}
	}
}

func TestOutletSwitchabilityUsesPerOutletValueBeforeGlobalValue(t *testing.T) {
	now := time.Now().UTC()
	state := FromSnapshot(nut.Snapshot{
		Variables: map[string]string{
			"ups.status":          "OL",
			"outlet.count":        "5",
			"outlet.switchable":   "yes",
			"outlet.2.switchable": "no",
			"outlet.3.switchable": "sometimes",
			"outlet.4.switchable": "0",
			"outlet.5.switchable": "true",
		},
		CollectedAt: now,
	}, Options{Now: now})

	want := []Truth{
		{Value: true, Known: true},  // inherited global value
		{Value: false, Known: true}, // per-outlet override
		{},                          // malformed local evidence must not inherit
		{Value: false, Known: true},
		{Value: true, Known: true},
	}
	for offset, wantTruth := range want {
		if got := state.Outlets[offset].Switchable; got != wantTruth {
			t.Fatalf("outlet %d switchability = %+v, want %+v", offset+1, got, wantTruth)
		}
	}
	if !containsIssue(state.Issues, "invalid-outlet-3-switchable") {
		t.Fatalf("malformed local switchability was not reported: %v", state.Issues)
	}
}

func TestPowerMeterRequiresDirectPerOutletCurrentOrPowerKey(t *testing.T) {
	now := time.Now().UTC()
	state := FromSnapshot(nut.Snapshot{
		Variables: map[string]string{
			"ups.status":                 "OL",
			"outlet.count":               "8",
			"outlet.1.current":           "1.25",
			"outlet.2.realpower":         "malformed",
			"outlet.3.power":             "300",
			"outlet.4.voltage":           "230",
			"outlet.5.powerfactor":       "0.9",
			"outlet.6.current.maximum":   "16",
			"outlet.7.realpower.nominal": "500",
			"outlet.8.power.maximum":     "750",
			"outlet.group.1.current":     "4",
			"outlet.group.1.realpower":   "800",
			"outlet.group.1.power":       "900",
			"ups.realpower":              "850",
		},
		CollectedAt: now,
	}, Options{Now: now})

	want := []bool{true, true, true, false, false, false, false, false}
	for offset, wantPowerMeter := range want {
		if got := state.Outlets[offset].PowerMeter; got != wantPowerMeter {
			t.Fatalf("outlet %d PowerMeter = %t, want %t", offset+1, got, wantPowerMeter)
		}
	}
	if !state.Outlets[0].Current.Known {
		t.Fatal("valid direct outlet current was not retained")
	}
	if state.Outlets[1].PowerW.Known {
		t.Fatal("malformed real power became a known measurement")
	}
	if state.Outlets[2].PowerW.Known {
		t.Fatal("apparent power was mislabeled as real watts")
	}
}

func TestOutletPowerFactorUsesClosedUnitInterval(t *testing.T) {
	now := time.Now().UTC()
	state := FromSnapshot(nut.Snapshot{
		Variables: map[string]string{
			"ups.status":           "OL",
			"outlet.count":         "3",
			"outlet.1.powerfactor": "1",
			"outlet.2.powerfactor": "1.01",
			"outlet.3.powerfactor": "-0.01",
		},
		CollectedAt: now,
	}, Options{Now: now})

	if !state.Outlets[0].PowerFactor.Known || state.Outlets[0].PowerFactor.Value != 1 {
		t.Fatalf("unit power factor was rejected: %+v", state.Outlets[0].PowerFactor)
	}
	for _, index := range []int{2, 3} {
		if state.Outlets[index-1].PowerFactor.Known {
			t.Fatalf("outlet %d out-of-range power factor was promoted: %+v", index, state.Outlets[index-1].PowerFactor)
		}
		if !containsIssue(state.Issues, fmt.Sprintf("invalid-outlet-%d-powerfactor", index)) {
			t.Fatalf("outlet %d invalid factor lacked bounded issue: %v", index, state.Issues)
		}
	}
}

func TestInvalidOutletCountsRetainBoundedFallback(t *testing.T) {
	now := time.Now().UTC()
	for _, raw := range []string{"", "0", "65", "1.5", "NaN", "+Inf", "not-a-number"} {
		t.Run(fmt.Sprintf("count_%q", raw), func(t *testing.T) {
			state := FromSnapshot(nut.Snapshot{
				Variables:   map[string]string{"ups.status": "OL", "outlet.count": raw},
				CollectedAt: now,
			}, Options{Now: now})
			assertFallbackTopology(t, state)
			if !containsIssue(state.Issues, "invalid-outlet-count") {
				t.Fatalf("invalid count %q was not reported: %v", raw, state.Issues)
			}
		})
	}

	t.Run("maximum accepted", func(t *testing.T) {
		state := FromSnapshot(nut.Snapshot{
			Variables: map[string]string{
				"ups.status":   "OL",
				"outlet.count": fmt.Sprint(MaxOutletCount),
			},
			CollectedAt: now,
		}, Options{Now: now})
		if !state.TopologyObserved || len(state.Outlets) != MaxOutletCount || len(state.Groups) != MaxOutletCount {
			t.Fatalf("maximum valid topology was not retained: observed=%t outlets=%d groups=%d", state.TopologyObserved, len(state.Outlets), len(state.Groups))
		}
	})

	t.Run("missing count is compatibility fallback without invalid issue", func(t *testing.T) {
		state := FromSnapshot(nut.Snapshot{
			Variables:   map[string]string{"ups.status": "OL"},
			CollectedAt: now,
		}, Options{Now: now})
		assertFallbackTopology(t, state)
		if containsIssue(state.Issues, "invalid-outlet-count") {
			t.Fatalf("missing optional outlet.count was called invalid: %v", state.Issues)
		}
	})
}

func TestObservedGroupStateConflictRemainsUnknown(t *testing.T) {
	now := time.Now().UTC()
	state := FromSnapshot(nut.Snapshot{
		Variables: map[string]string{
			"ups.status":            "OL",
			"outlet.count":          "2",
			"outlet.1.groupid":      "bank-a",
			"outlet.1.status":       "on",
			"outlet.2.groupid":      "bank-a",
			"outlet.2.status":       "on",
			"outlet.group.count":    "1",
			"outlet.group.1.id":     "bank-a",
			"outlet.group.1.status": "off",
		},
		CollectedAt: now,
	}, Options{Now: now})

	if len(state.Groups) != 1 || state.Groups[0].RelayState != RelayUnknown {
		t.Fatalf("conflicting group state was promoted: %+v", state.Groups)
	}
	if !containsIssue(state.Issues, "conflicting-relay-group-1-status") {
		t.Fatalf("group conflict was not reported: %v", state.Issues)
	}
}

func TestMatchedGroupSwitchabilityPrecedence(t *testing.T) {
	now := time.Now().UTC()
	state := FromSnapshot(nut.Snapshot{
		Variables: map[string]string{
			"ups.status":                "OL",
			"outlet.count":              "3",
			"outlet.switchable":         "no",
			"outlet.1.groupid":          "bank-a",
			"outlet.2.groupid":          "bank-a",
			"outlet.2.switchable":       "no",
			"outlet.group.count":        "1",
			"outlet.group.1.id":         "bank-a",
			"outlet.group.1.count":      "2",
			"outlet.group.1.switchable": "yes",
		},
		CollectedAt: now,
	}, Options{Now: now})

	want := []Truth{
		{Value: true, Known: true},  // matched group overrides the global value
		{Value: false, Known: true}, // per-outlet evidence overrides its group
		{Value: false, Known: true}, // singleton falls back to the global value
	}
	for offset, wantTruth := range want {
		if got := state.Outlets[offset].Switchable; got != wantTruth {
			t.Fatalf("outlet %d switchability = %+v, want %+v", offset+1, got, wantTruth)
		}
	}
}

func TestMalformedGroupSwitchabilityDoesNotFallThroughToGlobal(t *testing.T) {
	now := time.Now().UTC()
	state := FromSnapshot(nut.Snapshot{
		Variables: map[string]string{
			"ups.status":                "OL",
			"outlet.count":              "1",
			"outlet.switchable":         "yes",
			"outlet.1.groupid":          "bank-a",
			"outlet.group.count":        "1",
			"outlet.group.1.id":         "bank-a",
			"outlet.group.1.count":      "1",
			"outlet.group.1.switchable": "sometimes",
		},
		CollectedAt: now,
	}, Options{Now: now})

	if state.Outlets[0].Switchable.Known {
		t.Fatalf("malformed group switchability fell through to global value: %+v", state.Outlets[0])
	}
	if !containsIssue(state.Issues, "invalid-outlet-group-1-switchable") {
		t.Fatalf("malformed group switchability was not reported: %v", state.Issues)
	}
}

func TestKnownMemberConflictCannotBeHiddenByUnknownSibling(t *testing.T) {
	now := time.Now().UTC()
	state := FromSnapshot(nut.Snapshot{
		Variables: map[string]string{
			"ups.status":            "OL",
			"outlet.count":          "2",
			"outlet.1.groupid":      "bank-a",
			"outlet.1.status":       "on",
			"outlet.2.groupid":      "bank-a",
			"outlet.group.count":    "1",
			"outlet.group.1.id":     "bank-a",
			"outlet.group.1.count":  "2",
			"outlet.group.1.status": "off",
		},
		CollectedAt: now,
	}, Options{Now: now})

	if len(state.Groups) != 1 || state.Groups[0].RelayState != RelayUnknown {
		t.Fatalf("contradictory group status survived partial member evidence: %+v", state.Groups)
	}
	if !containsIssue(state.Issues, "conflicting-relay-group-1-status") {
		t.Fatalf("partial known-member conflict was not reported: %v", state.Issues)
	}
}

func TestNativeGroupIDCannotCollideWithMissingGroupSentinel(t *testing.T) {
	now := time.Now().UTC()
	state := FromSnapshot(nut.Snapshot{
		Variables: map[string]string{
			"ups.status":       "OL",
			"outlet.count":     "2",
			"outlet.1.status":  "on",
			"outlet.2.groupid": "@outlet:1",
			"outlet.2.status":  "off",
		},
		CollectedAt: now,
	}, Options{Now: now})

	if len(state.Groups) != 2 {
		t.Fatalf("native group ID collided with internal singleton identity: %+v", state.Groups)
	}
	if state.Outlets[0].NativeGroupID != "" || state.Outlets[1].NativeGroupID != "@outlet:1" {
		t.Fatalf("native group identity was not retained exactly: %+v", state.Outlets)
	}
	if state.Outlets[0].RelayGroup == state.Outlets[1].RelayGroup {
		t.Fatalf("missing groupid and explicit @outlet:1 shared relay group %d", state.Outlets[0].RelayGroup)
	}
	if !equalInts(state.Groups[0].OutletIndices, []int{1}) || !equalInts(state.Groups[1].OutletIndices, []int{2}) {
		t.Fatalf("colliding identities did not remain singleton groups: %+v", state.Groups)
	}
}

func TestOpaqueGroupIDsPreserveEdgeWhitespace(t *testing.T) {
	now := time.Now().UTC()
	state := FromSnapshot(nut.Snapshot{
		Variables: map[string]string{
			"ups.status":            "OL",
			"outlet.count":          "2",
			"outlet.1.groupid":      "rack",
			"outlet.1.status":       "on",
			"outlet.2.groupid":      " rack ",
			"outlet.2.status":       "off",
			"outlet.group.count":    "2",
			"outlet.group.1.id":     " rack ",
			"outlet.group.1.count":  "1",
			"outlet.group.1.status": "off",
			"outlet.group.2.id":     "rack",
			"outlet.group.2.count":  "1",
			"outlet.group.2.status": "on",
		},
		CollectedAt: now,
	}, Options{Now: now})

	if len(state.Groups) != 2 || state.Groups[0].NativeID != "rack" || state.Groups[1].NativeID != " rack " {
		t.Fatalf("opaque group IDs were normalized or merged: %+v", state.Groups)
	}
	if state.Groups[0].SourceIndex != 2 || state.Groups[1].SourceIndex != 1 ||
		state.Groups[0].RelayState != RelayOn || state.Groups[1].RelayState != RelayOff {
		t.Fatalf("group metadata did not match exact opaque IDs: %+v", state.Groups)
	}
}

func TestMismatchedGroupCountDisablesGroupStatusAndSwitchability(t *testing.T) {
	now := time.Now().UTC()
	state := FromSnapshot(nut.Snapshot{
		Variables: map[string]string{
			"ups.status":                "OL",
			"outlet.count":              "2",
			"outlet.switchable":         "no",
			"outlet.1.groupid":          "bank-a",
			"outlet.2.groupid":          "bank-a",
			"outlet.group.count":        "1",
			"outlet.group.1.id":         "bank-a",
			"outlet.group.1.count":      "3",
			"outlet.group.1.status":     "on",
			"outlet.group.1.switchable": "yes",
		},
		CollectedAt: now,
	}, Options{Now: now})

	if len(state.Groups) != 1 || state.Groups[0].RelayState != RelayUnknown {
		t.Fatalf("status from size-mismatched group metadata was trusted: %+v", state.Groups)
	}
	for _, outlet := range state.Outlets {
		if outlet.Switchable != (Truth{Value: false, Known: true}) {
			t.Fatalf("switchability from size-mismatched group metadata was trusted: %+v", outlet)
		}
	}
	if !containsIssue(state.Issues, "conflicting-relay-group-1-count") {
		t.Fatalf("group size mismatch was not reported: %v", state.Issues)
	}
}

func TestMalformedGroupCountDisablesGroupStatusAndSwitchability(t *testing.T) {
	now := time.Now().UTC()
	state := FromSnapshot(nut.Snapshot{
		Variables: map[string]string{
			"ups.status":                "OL",
			"outlet.count":              "1",
			"outlet.switchable":         "no",
			"outlet.1.groupid":          "bank-a",
			"outlet.group.count":        "1",
			"outlet.group.1.id":         "bank-a",
			"outlet.group.1.count":      "garbage",
			"outlet.group.1.status":     "on",
			"outlet.group.1.switchable": "yes",
		},
		CollectedAt: now,
	}, Options{Now: now})

	if len(state.Groups) != 1 || state.Groups[0].SourceIndex != 0 || state.Groups[0].RelayState != RelayUnknown {
		t.Fatalf("malformed-size group metadata was trusted: %+v", state.Groups)
	}
	if state.Outlets[0].Switchable != (Truth{Value: false, Known: true}) {
		t.Fatalf("malformed-size group switchability was trusted: %+v", state.Outlets[0])
	}
	if !containsIssue(state.Issues, "invalid-outlet-group-1-count") {
		t.Fatalf("malformed group count was not reported: %v", state.Issues)
	}
}

func TestUSBTypeClassificationRequiresExplicitToken(t *testing.T) {
	now := time.Now().UTC()
	state := FromSnapshot(nut.Snapshot{
		Variables: map[string]string{
			"ups.status":    "OL",
			"outlet.count":  "4",
			"outlet.1.type": "usbattery",
			"outlet.2.type": "USB",
			"outlet.3.type": "USB-A",
			"outlet.4.type": "USB-C",
		},
		CollectedAt: now,
	}, Options{Now: now})

	want := []OutletType{OutletTypeUnknown, OutletTypeUSB, OutletTypeUSB, OutletTypeUSB}
	for offset, wantType := range want {
		if got := state.Outlets[offset].Type; got != wantType {
			t.Fatalf("outlet %d type = %q, want %q", offset+1, got, wantType)
		}
	}
}

func assertFallbackTopology(t *testing.T, state State) {
	t.Helper()
	if state.TopologyObserved {
		t.Fatal("fallback topology was marked observed")
	}
	if len(state.Outlets) != 8 || len(state.Groups) != 2 {
		t.Fatalf("fallback shape = %d outlets/%d groups, want 8/2", len(state.Outlets), len(state.Groups))
	}
	if !equalInts(state.Groups[0].OutletIndices, []int{1, 2, 3, 4}) ||
		!equalInts(state.Groups[1].OutletIndices, []int{5, 6, 7, 8}) {
		t.Fatalf("fallback grouping is not 4+4: %+v", state.Groups)
	}
	for _, group := range state.Groups {
		if group.SourceIndex != 0 || group.NativeID != "" {
			t.Fatalf("synthetic fallback group retained a native source binding: %+v", group)
		}
	}
	for offset, outlet := range state.Outlets {
		wantGroup := offset/4 + 1
		if outlet.RelayGroup != wantGroup {
			t.Fatalf("fallback outlet %d relay group = %d, want %d", offset+1, outlet.RelayGroup, wantGroup)
		}
	}
}

func containsIssue(issues []string, want string) bool {
	for _, issue := range issues {
		if issue == want {
			return true
		}
	}
	return false
}

func equalInts(left, right []int) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
