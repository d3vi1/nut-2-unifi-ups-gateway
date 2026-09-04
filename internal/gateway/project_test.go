package gateway

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/d3vi1/nut-2-unifi-ups-gateway/internal/config"
	"github.com/d3vi1/nut-2-unifi-ups-gateway/internal/model"
	"github.com/d3vi1/nut-2-unifi-ups-gateway/internal/state"
	"github.com/d3vi1/nut-2-unifi-ups-gateway/internal/unifi/inform"
)

func TestObservedNUTTopologyProjectsCapabilitiesGroupsAndMeasurements(t *testing.T) {
	observation := model.State{
		Availability:     model.AvailabilityAvailable,
		TopologyObserved: true,
		Groups: []model.OutletGroup{
			{Index: 1, NativeID: "rack-bank", OutletIndices: []int{1, 2}, RelayState: model.RelayOn},
			{Index: 2, NativeID: "aux-bank", OutletIndices: []int{3}, RelayState: model.RelayOff},
		},
		Outlets: []model.Outlet{
			{
				Index:         1,
				NativeID:      "usb-service",
				NativeGroupID: "rack-bank",
				RelayGroup:    1,
				Name:          "USB-C service",
				Type:          model.OutletTypeUSB,
				Switchable:    model.Truth{Value: true, Known: true},
				RelayState:    model.RelayOff,
			},
			{
				Index:         2,
				NativeID:      "rack-feed",
				NativeGroupID: "rack-bank",
				RelayGroup:    1,
				Name:          "Metered rack feed",
				Type:          model.OutletTypeAC,
				Switchable:    model.Truth{Value: false, Known: true},
				PowerMeter:    true,
				RelayState:    model.RelayUnknown,
				Voltage:       model.Measurement{Value: 230.4, Known: true},
				Current:       model.Measurement{Value: 1.37, Known: true},
				PowerW:        model.Measurement{Value: 242.4, Known: true},
				PowerFactor:   model.Measurement{Value: 0.77, Known: true},
			},
			{
				Index:         3,
				NativeID:      "aux-feed",
				NativeGroupID: "aux-bank",
				RelayGroup:    2,
				Name:          "Auxiliary AC",
				Type:          model.OutletTypeAC,
				Switchable:    model.Truth{Value: true, Known: true},
				RelayState:    model.RelayOn,
			},
		},
	}

	document := projectedPayloadDocument(t, observation)
	if document["model"] != "UPS26" {
		t.Fatalf("dynamic topology escaped the UPS carrier flow: model=%v", document["model"])
	}
	outlets := document["outlet_table"].([]any)
	if len(outlets) != 3 {
		t.Fatalf("outlet_table length = %d, want observed count 3", len(outlets))
	}
	first := outlets[0].(map[string]any)
	second := outlets[1].(map[string]any)
	third := outlets[2].(map[string]any)

	if first["index"] != float64(1) || first["relay_group"] != float64(1) || first["outlet_caps"] != float64(0x20000) {
		t.Fatalf("switchable USB projection = %+v, want index=1 group=1 caps=0x20000", first)
	}
	if second["index"] != float64(2) || second["relay_group"] != float64(1) || second["outlet_caps"] != float64(0x10002) {
		t.Fatalf("metered AC projection = %+v, want index=2 group=1 caps=0x10002", second)
	}
	if third["index"] != float64(3) || third["relay_group"] != float64(2) || third["outlet_caps"] != float64(0x10000) {
		t.Fatalf("switchable AC projection = %+v, want index=3 group=2 caps=0x10000", third)
	}
	if first["relay_state"] != true || second["relay_state"] != true || third["relay_state"] != false {
		t.Fatalf("group relay states were not projected consistently: first=%v second=%v third=%v", first["relay_state"], second["relay_state"], third["relay_state"])
	}
	if second["outlet_voltage"] != 230.4 || second["outlet_current"] != 1.37 || second["outlet_power"] != float64(242) || second["outlet_power_factor"] != 0.77 {
		t.Fatalf("real outlet-scoped measurements were lost: %+v", second)
	}
	for index, outlet := range []map[string]any{first, second, third} {
		if _, exists := outlet["button_group"]; exists {
			t.Fatalf("dynamic outlet %d invented a physical button: %+v", index+1, outlet)
		}
	}
}

func TestReadOnlyProjectionUsesDirectNominalWattsAndHidesUnsupportedControls(t *testing.T) {
	observation := model.State{
		Availability: model.AvailabilityAvailable,
		Electrical: model.Electrical{
			OutputCurrent:       model.Measurement{Value: 1, Known: true},
			OutputPowerW:        model.Measurement{Value: 225, Known: true},
			OutputPowerNominalW: model.Measurement{Value: 865.5, Known: true},
		},
		BeeperStatus: model.BeeperStatusDisabled,
		Outlets:      make([]model.Outlet, 8),
		Groups: []model.OutletGroup{
			{Index: 1, OutletIndices: []int{1, 2, 3, 4}},
			{Index: 2, OutletIndices: []int{5, 6, 7, 8}},
		},
	}
	for offset := range observation.Outlets {
		observation.Outlets[offset] = model.Outlet{
			Index: offset + 1, RelayGroup: offset/4 + 1, Name: "Outlet " + integerString(offset+1),
		}
	}

	document := projectedPayloadDocument(t, observation)
	battery := document["vbms_table"].(map[string]any)["battpool"].(map[string]any)
	if battery["device_total_power_output"] != float64(225) || battery["device_total_power_budget"] != float64(866) || battery["device_output_current"] != float64(1) {
		t.Fatalf("direct UPS-wide electrical values were not projected exactly: %+v", battery)
	}
	if document["beep_enabled"] != false {
		t.Fatalf("known disabled beeper state was not preserved: %v", document["beep_enabled"])
	}
	smartPower := int64(document["smart_power_caps"].(float64))
	if smartPower&inform.SmartPowerCapabilityCycleOnACRecovery != 0 || smartPower&inform.SmartPowerCapabilityBuzzerControl != 0 || smartPower&inform.SmartPowerCapabilityEmergencyPowerOff != 0 {
		t.Fatalf("read-only projection advertised unsupported controls: %#x", smartPower)
	}
	if smartPower&inform.SmartPowerCapabilityNUTInformationAccess != 0 {
		t.Fatalf("default projection advertised a downstream NUT server: %#x", smartPower)
	}
	if smartPower&inform.SmartPowerCapabilitySafeShutdownAndCycleTime == 0 {
		t.Fatalf("read-only projection lost safe-shutdown timing: %#x", smartPower)
	}

	observation.BeeperStatus = model.BeeperStatusMuted
	document = projectedPayloadDocument(t, observation)
	if _, exists := document["beep_enabled"]; exists {
		t.Fatal("lossy muted beeper status was serialized as a boolean")
	}
}

func TestEnabledNUTBeeperProjectsAsEnabled(t *testing.T) {
	document := projectedPayloadDocument(t, model.State{
		Availability: model.AvailabilityAvailable,
		BeeperStatus: model.BeeperStatusEnabled,
	})

	beepEnabled, exists := document["beep_enabled"]
	if !exists {
		t.Fatal("known enabled NUT beeper state was omitted from the projected payload")
	}
	if beepEnabled != true {
		t.Fatalf("known enabled NUT beeper state projected as %v, want true", beepEnabled)
	}
}

func TestDisabledNUTServerAdvertisementIsAbsentFromProjection(t *testing.T) {
	configuration := baseConfig(t)
	if configuration.UniFi.NUTServer.Enabled {
		t.Fatal("test configuration unexpectedly enables downstream NUT server advertisement")
	}
	document := projectedPayloadDocumentForConfiguration(t, configuration, model.State{
		Availability: model.AvailabilityAvailable,
	})

	if _, exists := document["nut_server"]; exists {
		t.Fatalf("disabled downstream NUT server was projected: %v", document["nut_server"])
	}
	smartPower := int64(document["smart_power_caps"].(float64))
	if smartPower&inform.SmartPowerCapabilityNUTInformationAccess != 0 {
		t.Fatalf("disabled downstream NUT server advertised NUT information access: %#x", smartPower)
	}
}

func TestReadOnlySmartPowerMaskIsCarrierSpecific(t *testing.T) {
	observation := model.State{Availability: model.AvailabilityAvailable}
	for _, profile := range []string{inform.ModelUPS2UEU, inform.ModelUPS2UProEU} {
		document := projectedPayloadDocumentForProfile(t, profile, observation)
		got := int64(document["smart_power_caps"].(float64))
		want := int64(inform.SmartPowerCapabilitySafeShutdownAndCycleTime)
		if got != want {
			t.Fatalf("profile %s read-only smart-power caps = %#x, want %#x", profile, got, want)
		}
	}
}

func TestExplicitNUTServerAdvertisementIsSeparateAndCredentialFree(t *testing.T) {
	configuration := baseConfig(t)
	configuration.UniFi.NUTServer = config.NUTServerAdvertisement{Enabled: true, ID: "ups", Port: 3493}
	document := projectedPayloadDocumentForConfiguration(t, configuration, model.State{Availability: model.AvailabilityAvailable})

	server, ok := document["nut_server"].(map[string]any)
	if !ok {
		t.Fatalf("explicit NUT server advertisement missing: %v", document["nut_server"])
	}
	if server["enabled"] != true || server["id"] != "ups" || server["port"] != float64(3493) || server["credential_required"] != false {
		t.Fatalf("wrong NUT server advertisement: %+v", server)
	}
	for _, secret := range []string{"username", "password"} {
		if _, exists := server[secret]; exists {
			t.Fatalf("NUT server advertisement leaked %s", secret)
		}
	}
	smartPower := int64(document["smart_power_caps"].(float64))
	wantSmartPower := inform.SmartPowerCapabilityNUTInformationAccess | inform.SmartPowerCapabilitySafeShutdownAndCycleTime
	if smartPower != wantSmartPower {
		t.Fatalf("explicit NUT server advertisement smart-power caps = %#x, want %#x", smartPower, wantSmartPower)
	}
}

func TestAbsentNUTTopologyUsesConservativeUSWDA26Fallback(t *testing.T) {
	document := projectedPayloadDocument(t, model.State{Availability: model.AvailabilityAvailable})
	outlets := document["outlet_table"].([]any)
	if len(outlets) != 8 {
		t.Fatalf("fallback outlet_table length = %d, want 8", len(outlets))
	}
	for offset, raw := range outlets {
		outlet := raw.(map[string]any)
		wantGroup := float64(offset/4 + 1)
		if outlet["index"] != float64(offset+1) || outlet["relay_group"] != wantGroup || outlet["outlet_caps"] != float64(inform.OutletCapabilityAC) {
			t.Fatalf("fallback outlet %d drifted: %+v", offset+1, outlet)
		}
		for _, absent := range []string{"button_group", "button_state", "relay_state", "outlet_current", "outlet_power"} {
			if _, exists := outlet[absent]; exists {
				t.Fatalf("fallback outlet %d invented %s: %+v", offset+1, absent, outlet)
			}
		}
	}
}

func TestUSPDA2CFallbackKeepsSingletonLayoutWithoutInventedState(t *testing.T) {
	observation := model.State{
		Availability: model.AvailabilityAvailable,
		Groups: []model.OutletGroup{
			{Index: 1, OutletIndices: []int{1, 2, 3, 4}, RelayState: model.RelayOn},
			{Index: 2, OutletIndices: []int{5, 6, 7, 8}, RelayState: model.RelayOff},
		},
		Outlets: make([]model.Outlet, 8),
	}
	for offset := range observation.Outlets {
		observation.Outlets[offset] = model.Outlet{
			Index:      offset + 1,
			RelayGroup: offset/4 + 1,
			Name:       "Fallback outlet " + integerString(offset+1),
			RelayState: model.RelayOn,
		}
	}

	document := projectedPayloadDocumentForProfile(t, inform.ModelUPS2UProEU, observation)
	outlets := document["outlet_table"].([]any)
	if len(outlets) != 9 {
		t.Fatalf("USPDA2C fallback outlet_table length = %d, want 9", len(outlets))
	}
	for offset, raw := range outlets {
		outlet := raw.(map[string]any)
		wantGroup := float64(offset + 1)
		if outlet["relay_group"] != wantGroup || outlet["outlet_caps"] != float64(inform.OutletCapabilityAC) {
			t.Fatalf("USPDA2C destination outlet %d is not singleton: %+v", offset+1, outlet)
		}
		for _, absent := range []string{"button_group", "button_state", "relay_state"} {
			if _, exists := outlet[absent]; exists {
				t.Fatalf("USPDA2C fallback outlet %d invented %s: %+v", offset+1, absent, outlet)
			}
		}
	}
}

func projectedPayloadDocument(t *testing.T, observation model.State) map[string]any {
	return projectedPayloadDocumentForProfile(t, inform.ModelUPS2UEU, observation)
}

func projectedPayloadDocumentForProfile(t *testing.T, profile string, observation model.State) map[string]any {
	t.Helper()
	configuration := baseConfig(t)
	configuration.UniFi.Model = profile
	return projectedPayloadDocumentForConfiguration(t, configuration, observation)
}

func projectedPayloadDocumentForConfiguration(t *testing.T, configuration config.Config, observation model.State) map[string]any {
	t.Helper()
	persistent := state.State{
		Version: 1,
		Identity: state.Identity{
			MAC: configuration.Device.MAC, Serial: configuration.Device.Serial,
			GUID: "00000000-0000-4000-8000-000000000001",
		},
		Adoption: state.Adoption{
			AuthKey: inform.DefaultKey, InformURL: configuration.UniFi.InformURL, CfgVersion: "0",
		},
	}
	now := time.Unix(1_800_000_000, 0).UTC()
	report := projectPowerDevice(
		configuration,
		persistent,
		NetworkIdentity{DeviceIP: "192.0.2.20", InformIP: "192.0.2.10", Netmask: "255.255.255.0"},
		[6]byte{0x02, 0x11, 0x22, 0x33, 0x44, 0x55},
		observation,
		now,
		now.Add(-time.Hour),
		time.Time{},
	)
	payload, err := inform.BuildPowerDevicePayload(report)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(payload, &document); err != nil {
		t.Fatal(err)
	}
	return document
}
