package inform

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestFirmwareTargetMetadataMutationMatrix(t *testing.T) {
	valid := map[string]string{"_type": "upgrade", "version": "1.6.4.432", "url": "file:///never-open", "md5sum": strings.Repeat("a", 32), "sha256sum": strings.Repeat("b", 64), "server_time_in_utc": "1800000000000"}
	for field := range valid {
		for _, value := range []any{nil, false, 1, []string{}, map[string]string{}} {
			fields := make(map[string]any)
			for k, v := range valid {
				fields[k] = v
			}
			fields[field] = value
			body, _ := json.Marshal(fields)
			if _, err := ClassifyFirmwareTarget(body); err == nil {
				t.Fatal("non-string metadata accepted")
			}
		}
		body, _ := json.Marshal(valid)
		key, _ := json.Marshal(field)
		value, _ := json.Marshal(valid[field])
		body = append(body[:len(body)-1], []byte(","+string(key)+":"+string(value)+"}")...)
		if _, err := ClassifyFirmwareTarget(body); err == nil {
			t.Fatal("duplicate metadata accepted")
		}
	}
	for field, values := range map[string][]string{
		"url":                {"", strings.Repeat("a", 2049), "\x00", "\x7f", "é"},
		"md5sum":             {strings.Repeat("g", 32), strings.Repeat("a", 31), strings.Repeat("a", 33)},
		"sha256sum":          {strings.Repeat("g", 64), strings.Repeat("b", 63), strings.Repeat("b", 65)},
		"server_time_in_utc": {"180000000000", "18000000000000", "-800000000000"},
	} {
		for _, value := range values {
			fields := make(map[string]string)
			for k, v := range valid {
				fields[k] = v
			}
			fields[field] = value
			body, _ := json.Marshal(fields)
			if _, err := ClassifyFirmwareTarget(body); err == nil {
				t.Fatal("malformed metadata accepted")
			}
		}
	}
	for _, url := range []string{"file:///etc/passwd", "http://169.254.169.254/latest/meta-data", "http://never-resolve.invalid/private", "$(touch never-execute)", strings.Repeat("a", 2048)} {
		body, _ := json.Marshal(map[string]string{"_type": "upgrade", "version": "1.4.12", "url": url})
		target, err := ClassifyFirmwareTarget(body)
		if err != nil || target != (FirmwareTarget{Version: "1.4.12"}) {
			t.Fatal("inert metadata gained semantics")
		}
	}
	for _, body := range [][]byte{bytes.Repeat([]byte(" "), 16385), {0xff}, []byte(`[]`), []byte(`null`), []byte(`{"version":"1.2.3"}`)} {
		if _, err := ClassifyFirmwareTarget(body); err == nil {
			t.Fatal("invalid envelope accepted")
		}
	}
}

func TestReportedFirmwareChangesOnlyPayloadVersion(t *testing.T) {
	for _, model := range []string{ModelUPS2UEU, ModelUPS2UProEU} {
		t.Run(model, func(t *testing.T) {
			count := 8
			if model == ModelUPS2UProEU {
				count = 9
			}
			r := basePowerReport(model, "1.6.1", count)
			before, err := BuildPowerDevicePayload(r)
			if err != nil {
				t.Fatal(err)
			}
			var baseline map[string]json.RawMessage
			if json.Unmarshal(before, &baseline) != nil {
				t.Fatal("baseline decode")
			}
			for _, version := range []string{"1.6.4.432", "1.4.12", "1.6.1.413"} {
				r.ReportedFirmwareVersion = version
				after, err := BuildPowerDevicePayload(r)
				if err != nil {
					t.Fatal(err)
				}
				var target map[string]json.RawMessage
				if json.Unmarshal(after, &target) != nil {
					t.Fatal("target decode")
				}
				want, _ := json.Marshal(version)
				if !bytes.Equal(target["version"], want) {
					t.Fatal("wrong version")
				}
				target["version"] = baseline["version"]
				if !reflect.DeepEqual(target, baseline) {
					t.Fatal("firmware version changed profile semantics")
				}
			}
			r.ReportedFirmwareVersion = "1.2.3-beta"
			if _, err := BuildPowerDevicePayload(r); err == nil {
				t.Fatal("invalid version escaped payload validation")
			}
		})
	}
}

func FuzzFirmwareTarget(f *testing.F) {
	f.Add([]byte(`{"_type":"upgrade","version":"1.6.4.432"}`))
	f.Add([]byte(`{"_type":"upgrade","version":"1.4.12","url":"file:///never-open"}`))
	f.Fuzz(func(t *testing.T, body []byte) {
		target, err := ClassifyFirmwareTarget(body)
		if err != nil && target != (FirmwareTarget{}) {
			t.Fatal("rejected metadata escaped classifier")
		}
	})
}

func TestFirmwareTargetStrictAndInert(t *testing.T) {
	for _, version := range []string{"1.6.4.432", "1.4.12", "1.6.1.413"} {
		fields := map[string]string{"_type": "upgrade", "version": version, "url": "http://user:secret@127.0.0.1/private?token=do-not-retain", "md5sum": strings.Repeat("a", 32), "sha256sum": strings.Repeat("B", 64), "server_time_in_utc": "0000000000000"}
		body, _ := json.Marshal(fields)
		target, err := ClassifyFirmwareTarget(body)
		if err != nil || target.Version != version {
			t.Fatal("valid target rejected")
		}
		if reflect.TypeOf(target).NumField() != 1 {
			t.Fatal("classifier exposes metadata")
		}
		encoded, _ := json.Marshal(target)
		if strings.Contains(string(encoded), "secret") || strings.Contains(string(encoded), "do-not-retain") {
			t.Fatal("metadata escaped")
		}
	}
	for _, body := range []string{
		`{"_type":"upgrade","version":"1.6.4.432","version":"1.6.1.413"}`,
		`{"_type":"upgrade","Version":"1.6.4.432"}`,
		`{"_type":"upgrade","version":1.6}`,
		`{"_type":"upgrade","version":"1.6.4.432","cmd":"reboot"}`,
		`{"_type":"upgrade","version":"1.6.4.432","mgmt_cfg":"cfgversion=b"}`,
		`{"_type":"upgrade","version":"1.6.4.432","url":null}`,
		`{"_type":"upgrade","version":"1.6.4.432","url":"bad\nurl"}`,
		`{"_type":"upgrade","version":"1.6.4.432","md5sum":"bad"}`,
		`{"_type":"upgrade","version":"1.6.4.432","server_time_in_utc":"180000000000x"}`,
		`{"_type":"upgrade","version":"1.6.4.432"} {}`,
	} {
		if _, err := ClassifyFirmwareTarget([]byte(body)); err == nil {
			t.Fatal("unsafe target accepted")
		}
	}
	for _, version := range []string{"", "1.2", "1..3", "1.2.3.4.5", "01.2.3", "1.2.3-beta", "1.2.3 ", "+1.2.3", "１.2.3", "4294967296.2.3"} {
		body, _ := json.Marshal(map[string]string{"_type": "upgrade", "version": version})
		if _, err := ClassifyFirmwareTarget(body); err == nil {
			t.Fatal("invalid version accepted")
		}
	}
}
