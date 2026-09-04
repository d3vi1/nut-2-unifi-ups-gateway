package inform

import (
	"encoding/json"
	"strings"
	"testing"
)

func receiptJSON(t *testing.T, management, system string) []byte {
	t.Helper()
	body, err := json.Marshal(map[string]string{"_type": "setparam", "mgmt_cfg": management, "system_cfg": system})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// Synthetic values preserve the observed eight-field management response shape.
const receiptManagement = "cfgversion=revision-b\ncapability=notif\nled_enabled=true\nmgmt_url=https://192.0.2.1/manage\nreport_crash=false\nselfrun_guest_mode=pass\nstun_url=stun://192.0.2.1:3478\nuse_aes_gcm=true\n"

func TestConfigReceiptAcceptsObservedManagementWithoutRetainingValues(t *testing.T) {
	for _, management := range []string{receiptManagement, strings.ReplaceAll(receiptManagement, "\n", "\r\n"), "cfgversion=revision-b\n"} {
		receipt, err := ClassifyConfigReceipt(receiptJSON(t, management, "nutserver.password=private-value\nbeep.status=enabled\n"))
		if err != nil {
			t.Fatal(err)
		}
		if receipt.CfgVersion != "revision-b" || strings.Join(receipt.UnsupportedSettings, ",") != "nut-server,buzzer" {
			t.Fatal("receipt lost marker or fixed ignored-setting categories")
		}
		encoded, _ := json.Marshal(receipt)
		for _, secret := range []string{"private-value", "192.0.2.1", "notif", "enabled"} {
			if strings.Contains(string(encoded), secret) {
				t.Fatal("receipt retained controller metadata")
			}
		}
	}
}

func TestConfigReceiptRejectsAmbiguityAndAuthoritySmuggling(t *testing.T) {
	for name, management := range map[string]string{
		"missing": "led_enabled=true", "empty": "cfgversion=", "duplicate": receiptManagement + "cfgversion=other\n",
		"duplicate companion": receiptManagement + "led_enabled=false\n", "unknown": receiptManagement + "new.option=ignored\n",
		"key": receiptManagement + "authkey=" + DefaultKey + "\n", "endpoint": receiptManagement + "inform_url=http://192.0.2.2:8080/inform\n",
		"downgrade":     strings.ReplaceAll(receiptManagement, "use_aes_gcm=true", "use_aes_gcm=false"),
		"invalid bool":  strings.ReplaceAll(receiptManagement, "use_aes_gcm=true", "use_aes_gcm=perhaps"),
		"case":          strings.ReplaceAll(receiptManagement, "cfgversion", "CfgVersion"),
		"unicode alias": "\u200bcfgversion=revision-b\n", "nul": "cfgversion=revision\x00\n", "control": "cfgversion=revision\x1b\n",
		"long marker": "cfgversion=" + strings.Repeat("a", 129), "long line": receiptManagement + "capability=" + strings.Repeat("a", 256),
		"long body": strings.Repeat("\n", 64<<10) + receiptManagement, "many lines": strings.Repeat("\n", 257) + receiptManagement,
		"malformed": receiptManagement + "without-equals\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ClassifyConfigReceipt(receiptJSON(t, management, "")); err == nil {
				t.Fatal("unsafe management accepted")
			}
		})
	}
	for _, body := range []string{
		`null`, `[]`, `{"_type":"noop","mgmt_cfg":"cfgversion=b"}`,
		`{"_type":"setparam","_type":"setparam","mgmt_cfg":"cfgversion=b"}`,
		`{"_type":"setparam","mgmt_cfg":"cfgversion=b","mgmt_cfg":"cfgversion=c"}`,
		`{"_type":"setparam","mgmt_cfg":"cfgversion=b","cmd":"relayctl"}`,
		`{"_type":"setparam","mgmt_cfg":"cfgversion=b","interval":10}`,
		`{"_type":"setparam","mgmt_cfg":"cfgversion=b","version":"upgrade"}`,
		`{"_type":"setparam","mgmt_cfg":"cfgversion=b","outlet_table":[]}`,
		`{"_type":"setparam","mgmt_cfg":"cfgversion=b","system_cfg":null}`,
		`{"_type":"setparam","mgmt_cfg":"cfgversion=b","System_cfg":"ignored"}`,
		`{"_type":"setparam","mgmt_cfg":"cfgversion=b"} {}`,
	} {
		if _, err := ClassifyConfigReceipt([]byte(body)); err == nil {
			t.Fatal("unsafe top-level response accepted")
		}
	}
}

func TestConfigReceiptObservedOuterMetadata(t *testing.T) {
	fields := map[string]string{"_type": "setparam", "mgmt_cfg": receiptManagement, "system_cfg": "beep.status=enabled\n", "cfgversion": "revision-b", "server_time_in_utc": "1800000000000", "blocked_sta": ""}
	body, _ := json.Marshal(fields)
	r, err := ClassifyConfigReceipt(body)
	if err != nil || r.CfgVersion != "revision-b" {
		t.Fatal("observed outer metadata rejected")
	}
	encoded, _ := json.Marshal(r)
	if strings.Contains(string(encoded), "1800000000000") || strings.Contains(string(encoded), "blocked_sta") {
		t.Fatal("outer metadata retained")
	}
	for name, value := range map[string]string{"cfgversion": "different", "blocked_sta": "client", "server_time_in_utc": "180000000000x"} {
		t.Run(name, func(t *testing.T) {
			original := fields[name]
			defer func() { fields[name] = original }()
			fields[name] = value
			body, _ := json.Marshal(fields)
			if _, err := ClassifyConfigReceipt(body); err == nil {
				t.Fatal("invalid metadata accepted")
			}
		})
	}
	for _, stamp := range []string{"", "180000000000", "18000000000000", "+800000000000", "180000000000\n", "１８０００００００００００"} {
		fields["server_time_in_utc"] = stamp
		body, _ := json.Marshal(fields)
		if _, err := ClassifyConfigReceipt(body); err == nil {
			t.Fatal("invalid timestamp accepted")
		}
	}
	for _, stamp := range []string{"0000000000000", "9999999999999"} {
		fields["server_time_in_utc"] = stamp
		body, _ := json.Marshal(fields)
		if _, err := ClassifyConfigReceipt(body); err != nil {
			t.Fatal("timestamp was interpreted as freshness")
		}
	}
	for _, outer := range []string{"", "revision-B", " revision-b", "revision-b "} {
		fields["cfgversion"] = outer
		body, _ := json.Marshal(fields)
		if _, err := ClassifyConfigReceipt(body); err == nil {
			t.Fatal("outer marker mismatch accepted")
		}
	}
	fields["cfgversion"] = "revision-b"
	fields["blocked_sta"] = " "
	body, _ = json.Marshal(fields)
	if _, err := ClassifyConfigReceipt(body); err == nil {
		t.Fatal("nonempty blocked list accepted")
	}
	for _, field := range []string{"cfgversion", "blocked_sta", "server_time_in_utc"} {
		for _, raw := range []string{"null", "0", "false", "[]", "{}"} {
			body := []byte(`{"_type":"setparam","mgmt_cfg":"cfgversion=b","` + field + `":` + raw + `}`)
			if _, err := ClassifyConfigReceipt(body); err == nil {
				t.Fatal("non-string metadata accepted")
			}
		}
		valid := map[string]string{"cfgversion": "b", "blocked_sta": "", "server_time_in_utc": "1800000000000"}[field]
		body := []byte(`{"_type":"setparam","mgmt_cfg":"cfgversion=b","` + field + `":"` + valid + `","` + field + `":"` + valid + `"}`)
		if _, err := ClassifyConfigReceipt(body); err == nil {
			t.Fatal("duplicate metadata accepted")
		}
		body = []byte(`{"_type":"setparam","mgmt_cfg":"cfgversion=b","` + strings.ToUpper(field) + `":"` + valid + `"}`)
		if _, err := ClassifyConfigReceipt(body); err == nil {
			t.Fatal("case alias accepted")
		}
	}
}

func FuzzConfigReceiptNeverReturnsControllerMetadata(f *testing.F) {
	f.Add([]byte(`{"_type":"setparam","mgmt_cfg":"cfgversion=seed"}`))
	f.Fuzz(func(t *testing.T, body []byte) {
		r, err := ClassifyConfigReceipt(body)
		if err != nil {
			return
		}
		if !validConfigValue(r.CfgVersion, 128) {
			t.Fatal("invalid marker escaped")
		}
		if len(r.UnsupportedSettings) > 5 {
			t.Fatal("unbounded categories")
		}
		for _, category := range r.UnsupportedSettings {
			switch category {
			case "nut-server", "power-cycle-on-ac-recovery", "buzzer", "outlet-power", "emergency-power-off":
			default:
				t.Fatal("untrusted category escaped")
			}
		}
	})
}
