package inform

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

const controllerTestKey = "00112233445566778899aabbccddeeff"

func TestMgmtCfgAdoptsAndGCMIsSticky(t *testing.T) {
	state, err := NewAdoptionState("http://unifi:8080/inform")
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"_type":"setparam","mgmt_cfg":"cfgversion=abc123\nauthkey=` + controllerTestKey + `\nuse_aes_gcm=true\n"}`)
	outcome, err := state.ApplyControllerResponse(body)
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Kind != ResponseSetParam || !outcome.StateChanged || !state.Adopted || state.AuthKey != controllerTestKey || state.CfgVersion != "abc123" || !state.UseAESGCM {
		t.Fatalf("unexpected adoption result: outcome=%+v state=%+v", outcome, redactedAdoption(state))
	}

	// Firmware accepts a later key rotation, while GCM remains sticky.
	body = []byte(`{"_type":"setparam","mgmt_cfg":"cfgversion=def456\nauthkey=ffeeddccbbaa99887766554433221100\nuse_aes_gcm=false\n"}`)
	if _, err := state.ApplyControllerResponse(body); err != nil {
		t.Fatal(err)
	}
	if state.AuthKey != "ffeeddccbbaa99887766554433221100" || state.CfgVersion != "def456" || !state.UseAESGCM {
		t.Fatalf("key rotation or sticky GCM drifted: %+v", redactedAdoption(state))
	}
}

func TestMgmtCfgAcceptsFirmwareBooleanTokensAndCRSeparators(t *testing.T) {
	for _, token := range []string{"on", "enabled", "1", "enable", "active", "true"} {
		state, err := NewAdoptionState("http://unifi:8080/inform")
		if err != nil {
			t.Fatal(err)
		}
		body := []byte(`{"_type":"setparam","mgmt_cfg":"cfgversion=1\ruse_aes_gcm=` + token + `\r"}`)
		if _, err := state.ApplyControllerResponse(body); err != nil || !state.UseAESGCM || state.CfgVersion != "1" {
			t.Fatalf("token %q or CR separator rejected: state=%+v err=%v", token, redactedAdoption(state), err)
		}
	}
}

func TestUnsupportedPowerAndNUTServerSettingsAreReportedWithoutValues(t *testing.T) {
	state, err := NewAdoptionState("http://unifi:8080/inform")
	if err != nil {
		t.Fatal(err)
	}
	secret := "must-not-escape"
	body := []byte(`{"_type":"setparam","mgmt_cfg":"cfgversion=next\n","system_cfg":"nutserver.status=enabled\nnutserver.id=ups\nnutserver.port=3493\nnutserver.password=` + secret + `\npower_cycle_on_ac_recovery.status=enabled\npower_cycle_on_ac_recovery.time=60\nbeep.status=disabled\noutlet.status=disabled\nepo.status=enabled\n"}`)
	outcome, err := state.ApplyControllerResponse(body)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"nut-server", "power-cycle-on-ac-recovery", "buzzer", "outlet-power", "emergency-power-off"}
	if fmt.Sprint(outcome.UnsupportedSettings) != fmt.Sprint(want) {
		t.Fatalf("unsupported settings = %v, want %v", outcome.UnsupportedSettings, want)
	}
	if strings.Contains(fmt.Sprint(outcome), secret) {
		t.Fatal("unsupported settings outcome retained a controller-supplied value")
	}
	if state.CfgVersion != "next" || !state.Adopted {
		t.Fatalf("safe adoption fields were not applied: %+v", redactedAdoption(state))
	}
}

func TestSetParamAdoptsKeyAndInformURLTransactionally(t *testing.T) {
	state, err := NewAdoptionState("http://unifi:8080/inform")
	if err != nil {
		t.Fatal(err)
	}
	outcome, err := state.ApplyControllerResponse([]byte(`{"_type":"setparam","mgmt_cfg":"authkey=` + controllerTestKey + `\ninform_url=http://192.0.2.10:8080/inform\n"}`))
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Kind != ResponseSetParam || !outcome.InformURLChanged || !state.Adopted || state.AuthKey != controllerTestKey || state.InformURL != "http://192.0.2.10:8080/inform" {
		t.Fatalf("setparam adoption not applied: outcome=%+v state=%+v", outcome, redactedAdoption(state))
	}

	before := state
	secretURL := "http://user:password@example.invalid/inform"
	_, err = state.ApplyControllerResponse([]byte(`{"_type":"setparam","mgmt_cfg":"cfgversion=changed\ninform_url=` + secretURL + `\n"}`))
	if err == nil || strings.Contains(err.Error(), secretURL) {
		t.Fatalf("unsafe URL accepted or leaked: %v", err)
	}
	if state != before {
		t.Fatal("failed setparam partially mutated state")
	}
}

func TestInvalidMgmtCfgIsTransactionalAndRedacted(t *testing.T) {
	state, err := NewAdoptionState("http://unifi:8080/inform")
	if err != nil {
		t.Fatal(err)
	}
	before := state
	secret := strings.Repeat("z", 32)
	body := []byte(`{"_type":"setparam","mgmt_cfg":"cfgversion=changed\nauthkey=` + secret + `\n"}`)
	_, err = state.ApplyControllerResponse(body)
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("invalid key accepted or leaked: %v", err)
	}
	if state != before {
		t.Fatal("invalid mgmt_cfg partially mutated state")
	}
}

func TestFactoryResetIsOnlyGCMDowngrade(t *testing.T) {
	state := AdoptionState{
		AuthKey: controllerTestKey, InformURL: "http://192.0.2.10:8080/inform",
		CfgVersion: "abc", Adopted: true, UseAESGCM: true,
	}
	outcome, err := state.ApplyControllerResponse([]byte(`{"_type":"setdefault"}`))
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Kind != ResponseFactoryReset || !outcome.StateChanged || state.Adopted || state.AuthKey != DefaultKey || state.CfgVersion != "0" || state.UseAESGCM {
		t.Fatalf("factory reset incomplete: %+v", redactedAdoption(state))
	}
}

func TestDuplicateJSONAndMgmtCfgKeysRejected(t *testing.T) {
	state, err := NewAdoptionState("http://unifi:8080/inform")
	if err != nil {
		t.Fatal(err)
	}
	for _, body := range [][]byte{
		[]byte(`{"_type":"noop","_type":"cmd","cmd":"setdefault"}`),
		[]byte(`{"_type":"setparam","mgmt_cfg":"cfgversion=a\ncfgversion=b"}`),
	} {
		before := state
		if _, err := state.ApplyControllerResponse(body); err == nil {
			t.Fatal("ambiguous response accepted")
		}
		if state != before {
			t.Fatal("ambiguous response mutated state")
		}
	}
}

func TestNoopAndIgnoredCommandHaveNoSecretOutcome(t *testing.T) {
	state, err := NewAdoptionState("http://unifi:8080/inform")
	if err != nil {
		t.Fatal(err)
	}
	outcome, err := state.ApplyControllerResponse([]byte(`{"_type":"noop","interval":15}`))
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Kind != ResponseNoop || outcome.Interval != 15*time.Second || !outcome.StateChanged || !state.Adopted || state.AuthKey != DefaultKey {
		t.Fatalf("unexpected noop: %+v", outcome)
	}
	outcome, err = state.ApplyControllerResponse([]byte(`{"_type":"cmd","cmd":"cmd-provision","key":"must-not-escape"}`))
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Kind != ResponseIgnoredCommand {
		t.Fatalf("unexpected ignored outcome: %+v", outcome)
	}
}

func TestControllerResponseSizeBound(t *testing.T) {
	state, err := NewAdoptionState("http://unifi:8080/inform")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := state.ApplyControllerResponse(make([]byte, maxControllerResponse+1)); err == nil {
		t.Fatal("oversize controller response accepted")
	}
}

func TestUnprovenSetStateIsRejectedWithoutControlIntent(t *testing.T) {
	state, err := NewAdoptionState("http://unifi:8080/inform")
	if err != nil {
		t.Fatal(err)
	}
	before := state
	outcome, err := state.ApplyControllerResponse([]byte(`{"_type":"setstate","cfgversion":"next","outlet_overrides":[{"index":1,"relay_state":false},{"index":8,"relay_state":true}]}`))
	if err == nil || len(outcome.CycleIntents) != 0 {
		t.Fatalf("unproven setstate became executable: outcome=%+v err=%v", outcome, err)
	}
	if state != before {
		t.Fatal("rejected setstate mutated adoption state")
	}
}

func TestTopLevelRebootShape(t *testing.T) {
	state, err := NewAdoptionState("http://unifi:8080/inform")
	if err != nil {
		t.Fatal(err)
	}
	outcome, err := state.ApplyControllerResponse([]byte(`{"_type":"reboot"}`))
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Kind != ResponseReboot || !outcome.RestartRequested {
		t.Fatalf("unexpected reboot outcome: %+v", outcome)
	}
}

func TestRelayControlParsesPowerCycleIntents(t *testing.T) {
	state, err := NewAdoptionState("http://unifi:8080/inform")
	if err != nil {
		t.Fatal(err)
	}
	state.Adopted = true
	before := state
	body := []byte(`{"_type":"cmd","cmd":"relayctl","outlet_table":[{"index":1},{"index":8.9,"delay_time_to_off":0.5,"delay_time_to_on":1.25}]}`)
	outcome, err := state.ApplyControllerResponse(body)
	if err != nil {
		t.Fatal(err)
	}
	want := []OutletCycleIntent{
		{OutletIndex: 1, DelayOff: 0, DelayOn: 6 * time.Second},
		{OutletIndex: 8, DelayOff: 30 * time.Second, DelayOn: 75 * time.Second},
	}
	if outcome.Kind != ResponseRelayControl || len(outcome.CycleIntents) != len(want) {
		t.Fatalf("unexpected relayctl outcome: %+v", outcome)
	}
	for index := range want {
		if outcome.CycleIntents[index] != want[index] {
			t.Fatalf("cycle %d = %+v, want %+v", index, outcome.CycleIntents[index], want[index])
		}
	}
	if state != before {
		t.Fatal("relayctl parser mutated adoption state")
	}
}

func TestRelayControlRejectsUnsafeOrAmbiguousEntries(t *testing.T) {
	for _, table := range []string{
		`null`,
		`[{"delay_time_to_on":0.1}]`,
		`[{"index":0}]`,
		`[{"index":10}]`,
		`[{"index":1.1},{"index":1.9}]`,
		`[{"index":1,"delay_time_to_off":-1}]`,
		`[{"index":1,"delay_time_to_off":10.1}]`,
		`[{"index":1,"delay_time_to_on":0}]`,
		`[{"index":1,"delay_time_to_on":11}]`,
		`[{"index":1,"delay_time_to_on":"0.1"}]`,
		`[{"index":1,"relay_state":true}]`,
		`[{"index":1},{"index":2},{"index":3},{"index":4},{"index":5},{"index":6},{"index":7},{"index":8},{"index":9},{"index":9.5}]`,
	} {
		state, err := NewAdoptionState("http://unifi:8080/inform")
		if err != nil {
			t.Fatal(err)
		}
		before := state
		body := []byte(`{"_type":"cmd","cmd":"relayctl","outlet_table":` + table + `}`)
		if _, err := state.ApplyControllerResponse(body); err == nil {
			t.Fatalf("invalid relayctl accepted: %s", table)
		}
		if state != before {
			t.Fatal("invalid relayctl mutated adoption state")
		}
	}
	state, err := NewAdoptionState("http://unifi:8080/inform")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := state.ApplyControllerResponse([]byte(`{"_type":"cmd","cmd":"relayctl"}`)); err == nil {
		t.Fatal("relayctl without outlet_table accepted")
	}
}

func TestInformURLRequiresExactPath(t *testing.T) {
	for _, value := range []string{"http://unifi:8080", "http://unifi:8080/", "http://unifi:8080/inform/"} {
		if _, err := NewAdoptionState(value); err == nil {
			t.Fatalf("inform URL without exact /inform accepted: %q", value)
		}
	}
}

func TestAdoptionFormattingRedactsKeyAndURL(t *testing.T) {
	state := AdoptionState{AuthKey: controllerTestKey, InformURL: "http://192.0.2.10:8080/inform", CfgVersion: "x", Adopted: true}
	for _, formatted := range []string{fmt.Sprintf("%v", state), fmt.Sprintf("%+v", state), fmt.Sprintf("%#v", state)} {
		if strings.Contains(formatted, controllerTestKey) || strings.Contains(formatted, state.InformURL) {
			t.Fatalf("formatted state leaked secret material: %q", formatted)
		}
	}
}

type redactedState struct {
	InformURL  string
	CfgVersion string
	Adopted    bool
	UseAESGCM  bool
}

func redactedAdoption(state AdoptionState) redactedState {
	return redactedState{state.InformURL, state.CfgVersion, state.Adopted, state.UseAESGCM}
}
