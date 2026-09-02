package inform

import (
	"encoding/json"
	"math"
	"testing"
	"time"
)

func TestUSWDA26PayloadHasEightOutletsInTwoGroups(t *testing.T) {
	report := basePowerReport(ModelUPS2UEU, "1.6.1", 8)
	payload, err := BuildPowerDevicePayload(report)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(payload, &document); err != nil {
		t.Fatal(err)
	}
	if document["model"] != "UPS26" || document["model_display"] != "UPS26" || document["version"] != "1.6.1.413" || document["sysid"] != float64(0xda26) {
		t.Fatalf("wrong USWDA26 fingerprint: model=%v display=%v version=%v sysid=%v", document["model"], document["model_display"], document["version"], document["sysid"])
	}
	if document["guid"] != "317875ca-ad3e-47e9-9430-47e3e2e1ab3d" ||
		document["hash_id"] != "0011223344556677" ||
		document["anon_id"] != "00112233-4455-6677-8899-aabbccddeeff" {
		t.Fatalf("wrong USWDA26 cross-protocol identity: guid=%v hash=%v anon=%v", document["guid"], document["hash_id"], document["anon_id"])
	}
	if document["required_version"] != "1.3.4" {
		t.Fatalf("required_version = %v, want firmware default 1.3.4", document["required_version"])
	}
	if _, exists := document["_type"]; exists {
		t.Fatal("normal outgoing inform must not invent _type")
	}
	for _, absent := range []string{"x_authkey", "_default_key"} {
		if _, exists := document[absent]; exists {
			t.Fatalf("firmware-inexact secret/state field %s was emitted", absent)
		}
	}
	if document["default"] != true || document["state"] != float64(DeviceStatePending) {
		t.Fatalf("pending semantics default/state = %v/%v", document["default"], document["state"])
	}
	outlets := document["outlet_table"].([]any)
	if len(outlets) != 8 {
		t.Fatalf("outlet_table length = %d, want 8", len(outlets))
	}
	for index, raw := range outlets {
		outlet := raw.(map[string]any)
		expectedGroup := float64(index/4 + 1)
		if outlet["index"] != float64(index+1) || outlet["relay_group"] != expectedGroup {
			t.Fatalf("outlet %d topology = %+v", index+1, outlet)
		}
		if index < 4 && outlet["button_group"] != float64(1) {
			t.Fatalf("outlet %d missing standard-outlet button group: %+v", index+1, outlet)
		}
		if index >= 4 {
			if _, exists := outlet["button_group"]; exists {
				t.Fatalf("surge-only outlet %d invented button group: %+v", index+1, outlet)
			}
		}
		wantCaps := float64(65549)
		if index >= 4 {
			wantCaps = 65541
		}
		if outlet["outlet_caps"] != wantCaps {
			t.Fatalf("outlet %d caps = %v, want %v", index+1, outlet["outlet_caps"], wantCaps)
		}
		for _, absent := range []string{"relay_state", "button_state", "outlet_voltage", "outlet_current", "outlet_power", "outlet_power_factor", "outlet_ac_energy_1", "outlet_ac_energy_7", "outlet_ac_energy_30"} {
			if _, exists := outlet[absent]; exists {
				t.Fatalf("unknown %s was invented for outlet %d", absent, index+1)
			}
		}
	}

	vbms := document["vbms_table"].(map[string]any)
	battery := vbms["battpool"].(map[string]any)
	if len(battery) != 0 {
		t.Fatalf("unknown battery fields were invented: %+v", battery)
	}
	for _, absent := range []string{"epo_enabled", "input_thd_level", "is_battery_mode", "avr_mode", "bms_num", "bms_run_anomaly", "bms_version", "bms_log_file"} {
		if _, exists := vbms[absent]; exists {
			t.Fatalf("unknown %s was invented", absent)
		}
	}
	if _, exists := document["system-stats"]; exists {
		t.Fatal("unknown system stats table was invented")
	}
	if document["last_inform"] != float64(0) {
		t.Fatalf("first inform last_inform = %v, want 0", document["last_inform"])
	}
	if _, exists := document["beep_enabled"]; exists {
		t.Fatal("unknown beep state was invented")
	}
	for _, absent := range []string{"board_rev", "manufacturer_id", "reboot_duration", "update_duration", "local_config_changed"} {
		if _, exists := document[absent]; exists {
			t.Fatalf("unknown %s was invented", absent)
		}
	}
	for field, want := range map[string]float64{
		"fw_caps": 16779264, "hw_caps": 128, "sys_error_caps": 0,
		"adoption_caps": 2, "smart_power_caps": 143,
	} {
		if document[field] != want {
			t.Fatalf("%s = %v, want %v", field, document[field], want)
		}
	}
	ifTable := document["if_table"].([]any)[0].(map[string]any)
	portTable := document["port_table"].([]any)[0].(map[string]any)
	if _, exists := ifTable["up"]; exists {
		t.Fatal("unknown interface state was invented")
	}
	if _, exists := portTable["up"]; exists {
		t.Fatal("unknown port state was invented")
	}
}

func TestKnownFalseAndZeroTelemetryIsPreserved(t *testing.T) {
	report := basePowerReport(ModelUPS2UEU, "1.6.1", 8)
	report.VBMS.Battery.LevelPercent = pointer(0)
	report.VBMS.Battery.Charging = pointer(false)
	report.VBMS.BatteryMode = pointer(false)
	report.VBMS.AVRMode = pointer(AVRInactive)
	report.Interface.Up = pointer(false)
	report.BeepEnabled = pointer(false)
	report.Outlets[0].RelayState = pointer(false)
	report.System.CPUPercent = pointer(float64(0))
	payload, err := BuildPowerDevicePayload(report)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(payload, &document); err != nil {
		t.Fatal(err)
	}
	battery := document["vbms_table"].(map[string]any)["battpool"].(map[string]any)
	if battery["batteryLevel"] != float64(0) || battery["ischarging"] != false {
		t.Fatalf("known zero/false battery values omitted: %+v", battery)
	}
	if document["vbms_table"].(map[string]any)["is_battery_mode"] != false || document["beep_enabled"] != false {
		t.Fatal("known false device state omitted")
	}
	outlet := document["outlet_table"].([]any)[0].(map[string]any)
	if outlet["relay_state"] != false {
		t.Fatalf("known false/zero outlet values omitted: %+v", outlet)
	}
	if document["system-stats"].(map[string]any)["cpu"] != "0.0" {
		t.Fatal("known zero CPU value omitted")
	}
}

func TestAdoptedPayloadUsesFirmwareSteadyStateTwo(t *testing.T) {
	report := basePowerReport(ModelUPS2UEU, "1.6.1", 8)
	report.Adoption.AuthKey = controllerTestKey
	report.Adoption.Adopted = true
	payload, err := BuildPowerDevicePayload(report)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(payload, &document); err != nil {
		t.Fatal(err)
	}
	if document["default"] != false || document["state"] != float64(DeviceStateAdopted) {
		t.Fatalf("adopted semantics default/state = %v/%v", document["default"], document["state"])
	}
}

func TestUSPDA2CRequiresNineOutlets(t *testing.T) {
	report := basePowerReport(ModelUPS2UProEU, "1.6.1", 9)
	payload, err := BuildPowerDevicePayload(report)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(payload, &document); err != nil {
		t.Fatal(err)
	}
	if document["model"] != "UPS-2U-Pro" || document["model_display"] != "UPS Pro" || document["version"] != "1.6.1.4933" || document["sysid"] != float64(0xda2c) || len(document["outlet_table"].([]any)) != 9 {
		t.Fatalf("wrong USPDA2C fingerprint: %+v", document)
	}
	if document["required_version"] != "0.0.0" {
		t.Fatalf("required_version = %v, want firmware default 0.0.0", document["required_version"])
	}
	for field, want := range map[string]float64{
		"fw_caps": 16779264, "hw_caps": 136, "sys_error_caps": 0,
		"adoption_caps": 2, "smart_power_caps": 223,
	} {
		if document[field] != want {
			t.Fatalf("%s = %v, want %v", field, document[field], want)
		}
	}
	for index, raw := range document["outlet_table"].([]any) {
		outlet := raw.(map[string]any)
		wantGroup := float64(index + 1)
		if outlet["outlet_caps"] != float64(65539) || outlet["relay_group"] != wantGroup || outlet["button_group"] != wantGroup {
			t.Fatalf("USPDA2C outlet %d fingerprint = %+v", index+1, outlet)
		}
	}

	report.Outlets = report.Outlets[:8]
	if _, err := BuildPowerDevicePayload(report); err == nil {
		t.Fatal("USPDA2C payload with only 8 outlets accepted")
	}
}

func TestResolveUSPDA2CProfileSeparatesWireAndFullVersions(t *testing.T) {
	profile, err := ResolveProfile(DeviceProfile{Model: ModelUPS2UProEU, FirmwareVersion: "1.6.1"})
	if err != nil {
		t.Fatal(err)
	}
	if profile.DeviceModel != "UPS-2U-Pro" || profile.ModelDisplay != "UPS Pro" || profile.Platform != "USPDA2x" ||
		profile.FirmwareVersion != "1.6.1.4933" || profile.DiscoveryVersion != "1.6.1.4933" ||
		profile.FullVersion != "USPDA2x.esp32s3.v1.6.1.4933.a9814b.260723.1639" {
		t.Fatalf("resolved profile drifted: %+v", profile)
	}
}

func TestResolveUSWDA26ProfileSeparatesSelectorAndWireIdentity(t *testing.T) {
	profile, err := ResolveProfile(DeviceProfile{Model: ModelUPS2UEU, FirmwareVersion: "1.6.1"})
	if err != nil {
		t.Fatal(err)
	}
	if profile.DeviceModel != "UPS26" || profile.ModelDisplay != "UPS26" || profile.Platform != "UPS26" ||
		profile.ProfileGUID != "317875ca-ad3e-47e9-9430-47e3e2e1ab3d" ||
		profile.FirmwareVersion != "1.6.1.413" || profile.DiscoveryVersion != "1.6.1.413" ||
		profile.FullVersion != "UPS2U.esp32.v1.6.1.g5457.260723.0556" || profile.SysID != 0xda26 || profile.OutletCount != 8 {
		t.Fatalf("resolved USWDA26 profile drifted: %+v", profile)
	}
}

func TestUSPDA2CRejectsProfileDrift(t *testing.T) {
	report := basePowerReport(ModelUPS2UProEU, "1.6.1.4933", 9)
	report.Outlets[0].RelayGroup = 2
	if _, err := BuildPowerDevicePayload(report); err == nil {
		t.Fatal("USPDA2C non-individual group accepted")
	}
	report = basePowerReport(ModelUPS2UProEU, "1.6.1.4933", 9)
	report.Capabilities.Firmware = pointer(int64(1))
	if _, err := BuildPowerDevicePayload(report); err == nil {
		t.Fatal("USPDA2C capability drift accepted")
	}
	report = basePowerReport(ModelUPS2UProEU, "1.6.2", 9)
	if _, err := BuildPowerDevicePayload(report); err == nil {
		t.Fatal("USPDA2C unverified firmware version accepted")
	}
}

func TestUSWDA26RejectsWrongGroupMapping(t *testing.T) {
	report := basePowerReport(ModelUPS2UEU, "1.6.1", 8)
	report.Outlets[4].RelayGroup = 1
	if _, err := BuildPowerDevicePayload(report); err == nil {
		t.Fatal("invalid 4+4 relay-group topology accepted")
	}
}

func TestPowerDeviceRejectsMissingOrMalformedOpaqueIdentity(t *testing.T) {
	for name, mutate := range map[string]func(*PowerDeviceReport){
		"missing hash":   func(report *PowerDeviceReport) { report.Identity.HashID = "" },
		"uppercase hash": func(report *PowerDeviceReport) { report.Identity.HashID = "00112233445566AA" },
		"missing anon":   func(report *PowerDeviceReport) { report.Identity.AnonID = "" },
		"malformed anon": func(report *PowerDeviceReport) { report.Identity.AnonID = "00112233445566778899aabbccddeeff" },
	} {
		t.Run(name, func(t *testing.T) {
			report := basePowerReport(ModelUPS2UEU, "1.6.1", 8)
			mutate(&report)
			if _, err := BuildPowerDevicePayload(report); err == nil {
				t.Fatal("invalid firmware-required identity accepted")
			}
		})
	}
}

func TestUSWDA26RejectsCapabilityDrift(t *testing.T) {
	report := basePowerReport(ModelUPS2UEU, "1.6.1", 8)
	report.Outlets[0].Capabilities = pointer(65541)
	if _, err := BuildPowerDevicePayload(report); err == nil {
		t.Fatal("wrong standard-outlet capability accepted")
	}
	report = basePowerReport(ModelUPS2UEU, "1.6.1", 8)
	report.Capabilities.SmartPower = pointer(int64(223))
	if _, err := BuildPowerDevicePayload(report); err == nil {
		t.Fatal("wrong USWDA26 smart-power capability accepted")
	}
}

func TestUSWDA26RejectsFirmwareAbsentOutletMeasurements(t *testing.T) {
	report := basePowerReport(ModelUPS2UEU, "1.6.1", 8)
	report.Outlets[0].VoltageV = pointer(float64(230))
	if _, err := BuildPowerDevicePayload(report); err == nil {
		t.Fatal("USWDA26 per-outlet voltage unsupported by firmware was accepted")
	}
}

func TestUSWDA26RejectsUnverifiedFirmwareVersion(t *testing.T) {
	report := basePowerReport(ModelUPS2UEU, "1.6.2", 8)
	if _, err := BuildPowerDevicePayload(report); err == nil {
		t.Fatal("USWDA26 unverified firmware version accepted")
	}
}

func TestPayloadRejectsNonFiniteObservedValue(t *testing.T) {
	report := basePowerReport(ModelUPS2UEU, "1.6.1", 8)
	report.VBMS.Battery.OutputVoltageV = pointer(math.NaN())
	if _, err := BuildPowerDevicePayload(report); err == nil {
		t.Fatal("NaN battery measurement accepted")
	}
}

func TestPayloadRejectsRuntimeBeyondSafetyBound(t *testing.T) {
	report := basePowerReport(ModelUPS2UEU, "1.6.1", 8)
	report.VBMS.Battery.RuntimeSeconds = pointer(uint64(maxRuntimeSeconds + 1))
	if _, err := BuildPowerDevicePayload(report); err == nil {
		t.Fatal("unsafe battery runtime was accepted")
	}
}

func basePowerReport(model, firmware string, outletCount int) PowerDeviceReport {
	adoption, err := NewAdoptionState("http://unifi:8080/inform")
	if err != nil {
		panic(err)
	}
	report := PowerDeviceReport{
		Profile: DeviceProfile{Model: model, FirmwareVersion: firmware},
		Identity: DeviceIdentity{
			MAC: "02:11:22:33:44:55", Serial: "N2UTEST0001", Hostname: "n2u-test",
			IP: "192.0.2.20", InformIP: "192.0.2.10", GUID: "00000000-0000-4000-8000-000000000001",
			HashID: "0011223344556677", AnonID: "00112233-4455-6677-8899-aabbccddeeff",
		},
		Adoption:   adoption,
		ObservedAt: time.Unix(1_800_000_000, 0),
		Uptime:     15 * time.Minute,
		VBMS:       VBMSTelemetry{},
		Interface: InterfaceTelemetry{
			MAC: "02:11:22:33:44:55", IP: "192.0.2.20", Netmask: "255.255.255.0",
		},
		Outlets: make([]OutletTelemetry, outletCount),
	}
	for i := range report.Outlets {
		group := i + 1
		buttonGroup := i + 1
		if model == ModelUPS2UEU {
			group = i/4 + 1
			buttonGroup = 0
			if i < 4 {
				buttonGroup = 1
			}
		}
		report.Outlets[i] = OutletTelemetry{
			Name: "Outlet " + string(rune('1'+i)), RelayGroup: group, ButtonGroup: buttonGroup,
		}
	}
	return report
}

func pointer[T any](value T) *T { return &value }
