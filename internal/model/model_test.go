package model

import (
	"fmt"
	"testing"
	"time"

	"github.com/d3vi1/nut-2-unifi-ups-gateway/internal/nut"
)

func TestFromSnapshotMapsFreshTelemetryAndFixedTopology(t *testing.T) {
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
	if got := state.Zones[0].OutletIndices; got != [4]int{1, 2, 3, 4} {
		t.Fatalf("zone 1 outlet indices = %v", got)
	}
	if got := state.Zones[1].OutletIndices; got != [4]int{5, 6, 7, 8} {
		t.Fatalf("zone 2 outlet indices = %v", got)
	}
	if state.Zones[0].RelayState != RelayOn || state.Zones[1].RelayState != RelayOff {
		t.Fatalf("unexpected zone relay states: %+v", state.Zones)
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

func TestZoneStateIsMixedOnlyFromFourKnownOutlets(t *testing.T) {
	now := time.Now().UTC()
	variables := map[string]string{"ups.status": "OL"}
	for index := 1; index <= 4; index++ {
		variables[fmt.Sprintf("outlet.%d.status", index)] = "on"
	}
	variables["outlet.4.status"] = "off"
	state := FromSnapshot(nut.Snapshot{Variables: variables, CollectedAt: now}, Options{Now: now})
	if state.Zones[0].RelayState != RelayMixed {
		t.Fatalf("zone state = %q, want mixed", state.Zones[0].RelayState)
	}
	if state.Zones[1].RelayState != RelayUnknown {
		t.Fatalf("unobserved zone state = %q, want unknown", state.Zones[1].RelayState)
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
	if state.Zones[0].RelayState != RelayUnknown {
		t.Fatalf("conflicting relay evidence was promoted: %+v", state.Zones[0])
	}
	found := false
	for _, issue := range state.Issues {
		if issue == "conflicting-zone-1-status" {
			found = true
		}
	}
	if !found {
		t.Fatalf("conflict was not made explicit: %v", state.Issues)
	}
}
