package gateway

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/d3vi1/nut-2-unifi-ups-gateway/internal/config"
	"github.com/d3vi1/nut-2-unifi-ups-gateway/internal/state"
	"github.com/d3vi1/nut-2-unifi-ups-gateway/internal/unifi/inform"
)

func receiptResponse(t *testing.T, version string) []byte {
	t.Helper()
	body, err := json.Marshal(map[string]string{
		"_type":      "setparam",
		"mgmt_cfg":   "cfgversion=" + version + "\ncapability=notif\nled_enabled=true\nmgmt_url=https://192.0.2.99/manage\nreport_crash=false\nselfrun_guest_mode=pass\nstun_url=stun://192.0.2.99:3478\nuse_aes_gcm=true\n",
		"system_cfg": "nutserver.status=disabled\nnutserver.password=do-not-disclose\nbeep.status=enabled\npower_cycle_on_ac_recovery.status=enabled\n",
	})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func receiptConfiguration(t *testing.T, mode string) config.Config {
	t.Helper()
	c := baseConfig(t)
	c.UniFi.ConfigReceiptMode = mode
	c.Runtime.StaleAfter = 30 * time.Minute
	seedManagedGCMState(t, c, testControllerKey, "baseline")
	return c
}

func TestConfigReceiptObservedResponseAndRestart(t *testing.T) {
	for _, mode := range []string{"memory", "persistent"} {
		t.Run(mode, func(t *testing.T) {
			c := receiptConfiguration(t, mode)
			now := time.Unix(1_800_000_000, 0)
			before, _ := os.ReadFile(c.Runtime.StateFile)
			var requests []string
			var counter uint32
			controller := &functionalController{exchange: func(_ context.Context, _ string, request []byte) ([]byte, error) {
				requests = append(requests, decodedRequestCfgVersion(t, request, testControllerKey, inform.ModeGCM))
				counter++
				var nonce [16]byte
				binary.BigEndian.PutUint32(nonce[:4], counter)
				body := receiptResponse(t, "received-b")
				if counter > 2 {
					body = []byte(`{"_type":"noop"}`)
				}
				return encodeGCMControllerResponse(t, testControllerKey, nonce, body), nil
			}, authorize: func(context.Context, string, string) error {
				t.Fatal("receipt attempted controller transition")
				return nil
			}}
			service := newReplayTestGateway(t, c, now, controller, func(string, state.State) error { t.Fatal("receipt rewrote adoption"); return nil })
			var logs bytes.Buffer
			service.logger = slog.New(slog.NewTextHandler(&logs, nil))
			writes := 0
			service.saveReceipt = func(path string, r state.Receipt) error {
				writes++
				if service.reportedCfgVersion != "baseline" {
					t.Fatal("marker advanced before commit")
				}
				return state.SaveReceipt(path, r)
			}
			for i := 0; i < 3; i++ {
				out, err := service.InformOnce(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				if out.StateChanged || out.InformURLChanged || out.RestartRequested || out.Interval != 0 {
					t.Fatal("receipt leaked execution authority")
				}
			}
			if strings.Join(requests, ",") != "baseline,received-b,received-b" {
				t.Fatal("next inform did not report accepted marker")
			}
			wantWrites := 0
			if mode == "persistent" {
				wantWrites = 1
			}
			if writes != wantWrites {
				t.Fatal("stable configuration rewrote storage")
			}
			after, _ := os.ReadFile(c.Runtime.StateFile)
			if !bytes.Equal(before, after) {
				t.Fatal("adoption file changed")
			}
			for _, secret := range []string{"received-b", "do-not-disclose", testControllerKey, "192.0.2.99"} {
				if strings.Contains(logs.String(), secret) {
					t.Fatal("receipt log leaked input")
				}
			}
			restarted := newReplayTestGateway(t, c, now, controller, nil)
			if err := func() error { _, err := restarted.InformOnce(context.Background()); return err }(); err != nil {
				t.Fatal(err)
			}
			want := "baseline"
			if mode == "persistent" {
				want = "received-b"
			}
			if requests[len(requests)-1] != want {
				t.Fatal("restart report did not reflect storage mode")
			}
			if mode == "persistent" {
				replay := encodeGCMControllerResponse(t, testControllerKey, [16]byte{0, 0, 0, 1}, receiptResponse(t, "received-b"))
				controller.exchange = func(context.Context, string, []byte) ([]byte, error) { return replay, nil }
				if _, err := restarted.InformOnce(context.Background()); !errors.Is(err, ErrControllerResponseReplay) {
					t.Fatal("transition replay survived restart")
				}
			}
			// The old binary still uses this same v1 reader; receipt is independent.
			if _, err := state.LoadOrCreate(c.Runtime.StateFile, c.Device.MAC, c.Device.Serial, c.UniFi.InformURL, inform.DefaultKey); err != nil {
				t.Fatal("receipt broke state-v1 compatibility")
			}
		})
	}
}

func TestConfigReceiptFailedCommitKeepsMarkerAndBlocksFurtherWrites(t *testing.T) {
	c := receiptConfiguration(t, "persistent")
	now := time.Unix(1_800_000_000, 0)
	counter := byte(0)
	controller := &functionalController{exchange: func(context.Context, string, []byte) ([]byte, error) {
		counter++
		return encodeGCMControllerResponse(t, testControllerKey, [16]byte{counter}, receiptResponse(t, "new-marker")), nil
	}}
	service := newReplayTestGateway(t, c, now, controller, nil)
	writes := 0
	service.saveReceipt = func(string, state.Receipt) error { writes++; return errors.New("private filesystem path") }
	for i := 0; i < 2; i++ {
		if _, err := service.InformOnce(context.Background()); err == nil {
			t.Fatal("failed commit accepted")
		}
	}
	if writes != 1 || service.reportedCfgVersion != "baseline" || service.receipt.CfgVersion != "" || service.gcmReplay.contains([16]byte{1}) {
		t.Fatal("failed commit advanced marker, nonce, or kept writing")
	}
	rec := httptest.NewRecorder()
	service.monitor.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if !strings.Contains(rec.Body.String(), `"configuration_receipt":"storage_error"`) {
		t.Fatal("storage failure absent from diagnostics")
	}
}

func TestConfigReceiptRejectsEffectfulResponsesWithoutSideEffects(t *testing.T) {
	for name, body := range map[string][]byte{
		"unknown":     []byte(`{"_type":"setparam","mgmt_cfg":"cfgversion=b\nunknown=x\n"}`),
		"key":         []byte(`{"_type":"setparam","mgmt_cfg":"cfgversion=b\nauthkey=ffeeddccbbaa99887766554433221100\n"}`),
		"destination": []byte(`{"_type":"setparam","mgmt_cfg":"cfgversion=b\ninform_url=http://192.0.2.99:8080/inform\n"}`),
		"downgrade":   []byte(`{"_type":"setparam","mgmt_cfg":"cfgversion=b\nuse_aes_gcm=false\n"}`),
		"relay":       []byte(`{"_type":"setparam","mgmt_cfg":"cfgversion=b\n","cmd":"relayctl","outlet_table":[{"index":1}]}`),
		"duplicate":   []byte(`{"_type":"setparam","mgmt_cfg":"cfgversion=b\ncfgversion=c\n"}`),
	} {
		t.Run(name, func(t *testing.T) {
			c := receiptConfiguration(t, "persistent")
			now := time.Unix(1_800_000_000, 0)
			controller := &functionalController{exchange: func(context.Context, string, []byte) ([]byte, error) {
				return encodeGCMControllerResponse(t, testControllerKey, [16]byte{1}, body), nil
			}, authorize: func(context.Context, string, string) error { t.Fatal("unauthorized destination"); return nil }}
			service := newReplayTestGateway(t, c, now, controller, func(string, state.State) error { t.Fatal("unauthorized adoption mutation"); return nil })
			before := service.persistent
			service.saveReceipt = func(string, state.Receipt) error { t.Fatal("ineligible response written"); return nil }
			if _, err := service.InformOnce(context.Background()); err == nil {
				t.Fatal("ineligible response succeeded")
			}
			if service.reportedCfgVersion != "baseline" || !reflect.DeepEqual(before, service.persistent) {
				t.Fatal("rejection changed state")
			}
		})
	}
}

func TestConfigReceiptRateLimitAllowsLegitimateReturnToOldVersion(t *testing.T) {
	c := receiptConfiguration(t, "persistent")
	now := time.Unix(1_800_000_000, 0)
	version := "a"
	counter := uint32(0)
	controller := &functionalController{exchange: func(context.Context, string, []byte) ([]byte, error) {
		counter++
		var nonce [16]byte
		binary.BigEndian.PutUint32(nonce[:4], counter)
		return encodeGCMControllerResponse(t, testControllerKey, nonce, receiptResponse(t, version)), nil
	}}
	service := newReplayTestGateway(t, c, now, controller, nil)
	service.now = func() time.Time { return now }
	if _, err := service.InformOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	version = "b"
	now = now.Add(time.Second)
	if _, err := service.InformOnce(context.Background()); err == nil {
		t.Fatal("write rate limit bypassed")
	}
	if service.reportedCfgVersion != "a" {
		t.Fatal("rate-limited marker advanced")
	}
	now = now.Add(receiptWriteInterval)
	if _, err := service.InformOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	version = "a"
	now = now.Add(receiptWriteInterval)
	if _, err := service.InformOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if service.reportedCfgVersion != "a" || len(service.receipt.Nonces) != 3 {
		t.Fatal("legitimate A-B-A return blocked")
	}
}

func TestConfigReceiptContextMismatchAndCorruptionDoNotAffectAdoption(t *testing.T) {
	c := receiptConfiguration(t, "persistent")
	now := time.Unix(1_800_000_000, 0)
	controller := &functionalController{exchange: func(context.Context, string, []byte) ([]byte, error) {
		return encodeGCMControllerResponse(t, testControllerKey, [16]byte{1}, receiptResponse(t, "received")), nil
	}}
	service := newReplayTestGateway(t, c, now, controller, nil)
	if _, err := service.InformOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	saved := service.persistent
	saved.Adoption.CfgVersion = "new-adoption-base"
	if err := state.Save(c.Runtime.StateFile, saved); err != nil {
		t.Fatal(err)
	}
	restarted := newReplayTestGateway(t, c, now, controller, nil)
	if restarted.reportedCfgVersion != "new-adoption-base" || restarted.receipt.CfgVersion != "" {
		t.Fatal("old context restored a receipt")
	}
	if err := os.WriteFile(state.ReceiptPath(c.Runtime.StateFile), []byte("corrupt"), 0o600); err != nil {
		t.Fatal(err)
	}
	restarted = newReplayTestGateway(t, c, now, controller, nil)
	if !restarted.receiptBlocked || restarted.reportedCfgVersion != "new-adoption-base" || !restarted.persistent.Adoption.Adopted {
		t.Fatal("corrupt receipt broke adoption or was silently trusted")
	}
}

func TestConfigReceiptNonceProtectionSurvivesRoutineNoops(t *testing.T) {
	c := receiptConfiguration(t, "memory")
	now := time.Unix(1_800_000_000, 0)
	counter := uint32(0)
	first := encodeGCMControllerResponse(t, testControllerKey, [16]byte{1}, receiptResponse(t, "first"))
	controller := &functionalController{exchange: func(context.Context, string, []byte) ([]byte, error) {
		counter++
		if counter == 1 || counter == state.MaxGCMReplayNonces+3 {
			return first, nil
		}
		var nonce [16]byte
		binary.BigEndian.PutUint32(nonce[4:8], counter)
		return encodeGCMControllerResponse(t, testControllerKey, nonce, []byte(`{"_type":"noop"}`)), nil
	}}
	service := newReplayTestGateway(t, c, now, controller, nil)
	for i := 0; i < state.MaxGCMReplayNonces+2; i++ {
		if _, err := service.InformOnce(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := service.InformOnce(context.Background()); !errors.Is(err, ErrControllerResponseReplay) {
		t.Fatal("noops evicted protected receipt nonce")
	}
}

func TestConfigReceiptsDoNotWidenOtherTrustModes(t *testing.T) {
	for _, variant := range []string{"off", "default-key", "CBC", "HTTPS"} {
		t.Run(variant, func(t *testing.T) {
			c := receiptConfiguration(t, "persistent")
			key := testControllerKey
			mode := inform.ModeGCM
			switch variant {
			case "off":
				c.UniFi.ConfigReceiptMode = "off"
			case "default-key":
				key = inform.DefaultKey
				seedManagedGCMState(t, c, key, "baseline")
			case "CBC":
				mode = inform.ModeCBC
				seedManagedCBCState(t, c, key, "baseline")
			case "HTTPS":
				c.UniFi.InformURL = "https://192.0.2.10:8443/inform"
				seedManagedGCMState(t, c, key, "baseline")
			}
			controller := &functionalController{exchange: func(context.Context, string, []byte) ([]byte, error) {
				if mode == inform.ModeCBC {
					return encodeCBCControllerResponse(t, key, receiptResponse(t, "new")), nil
				}
				return encodeGCMControllerResponse(t, key, [16]byte{1}, receiptResponse(t, "new")), nil
			}}
			service := newReplayTestGateway(t, c, time.Unix(1_800_000_000, 0), controller, nil)
			service.saveReceipt = func(string, state.Receipt) error { t.Fatal("receipt escaped eligible trust mode"); return nil }
			if _, err := service.InformOnce(context.Background()); err != nil {
				t.Fatal(err)
			}
			if service.receipt.Epoch != "" {
				t.Fatal("ineligible session created receipt")
			}
			if _, err := os.Stat(state.ReceiptPath(c.Runtime.StateFile)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("receipt file created outside eligible mode")
			}
		})
	}
}
