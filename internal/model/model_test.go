package model

import (
	"fmt"
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
	if state.Groups[0].RelayState != RelayOn || state.Groups[1].RelayState != RelayOff {
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
			availability: AvailabilityUnavailable,
			reason:       "conflicting-charge-status",
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

func TestConflictingGroupAndOutletEvidenceRemainsUnknown(t *testing.T) {
	now := time.Now().UTC()
	variables := map[string]string{
		"ups.status":            "OL",
		"outlet.group.1.status": "off",
	}
	for index := 1; index <= 4; index++ {
		variables[fmt.Sprintf("outlet.%d.status", index)] = "on"
	}
	state := FromSnapshot(nut.Snapshot{Variables: variables, CollectedAt: now}, Options{Now: now})
	if state.Groups[0].RelayState != RelayUnknown {
		t.Fatalf("conflicting relay evidence was promoted: %+v", state.Groups[0])
	}
	found := false
	for _, issue := range state.Issues {
		if issue == "conflicting-relay-group-1-status" {
			found = true
		}
	}
	if !found {
		t.Fatalf("conflict was not made explicit: %v", state.Issues)
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
