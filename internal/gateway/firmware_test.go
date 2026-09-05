package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/d3vi1/nut-2-unifi-ups-gateway/internal/state"
	"github.com/d3vi1/nut-2-unifi-ups-gateway/internal/unifi/discovery"
	"github.com/d3vi1/nut-2-unifi-ups-gateway/internal/unifi/inform"
)

func firmwareResponse(t *testing.T, version, url string) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]string{"_type": "upgrade", "version": version, "url": url, "md5sum": strings.Repeat("a", 32), "sha256sum": strings.Repeat("b", 64)})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestFirmwareTargetGatewayLifecycleAndNoEgress(t *testing.T) {
	c := receiptConfiguration(t, "persistent")
	c.UniFi.ReportedFirmwareSync = true
	now := time.Unix(1800000000, 0)
	var hits atomic.Int64
	trap := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer trap.Close()
	privateURL := trap.URL + "/never-fetch?token=do-not-retain"
	body := receiptResponse(t, "configuration-b")
	var nonce byte
	var sent []map[string]any
	controller := &functionalController{exchange: func(_ context.Context, _ string, request []byte) ([]byte, error) {
		packet, err := inform.Decode(request, testControllerKey)
		if err != nil {
			t.Fatal(err)
		}
		var payload map[string]any
		if json.Unmarshal(packet.Payload, &payload) != nil {
			t.Fatal("payload")
		}
		sent = append(sent, payload)
		nonce++
		return encodeGCMControllerResponse(t, testControllerKey, [16]byte{nonce}, body), nil
	}, authorize: func(context.Context, string, string) error { t.Fatal("firmware URL gained authority"); return nil }}
	g := newReplayTestGateway(t, c, now, controller, func(string, state.State) error { t.Fatal("adoption mutation"); return nil })
	g.now = func() time.Time { return now }
	var logs bytes.Buffer
	g.logger = slog.New(slog.NewTextHandler(&logs, nil))
	if _, err := g.InformOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	cfgBefore, _ := os.ReadFile(state.ReceiptPath(c.Runtime.StateFile))
	adoptionBefore, _ := os.ReadFile(c.Runtime.StateFile)
	writes := 0
	g.saveFirmwareReceipt = func(path string, r state.FirmwareReceipt) error {
		writes++
		if g.reportedFirmwareVersion == r.Version {
			t.Fatal("published before commit")
		}
		ann, err := g.discoveryAnnouncement(discovery.V2, discovery.CommandAnnouncement)
		if err != nil {
			t.Fatal(err)
		}
		if ann.VersionText == r.Version {
			t.Fatal("discovery published before commit")
		}
		return state.SaveFirmwareReceipt(path, r)
	}
	for _, target := range []string{"1.6.4.432", "1.6.4.432", "1.4.12", "1.6.4.432"} {
		now = now.Add(40 * time.Second)
		body = firmwareResponse(t, target, privateURL)
		out, err := g.InformOnce(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if out.Kind != inform.ResponseReportedFirmware || out.StateChanged || out.RestartRequested || out.Interval != 0 || out.UpgradeVersion != "" || out.InformURLChanged {
			t.Fatal("firmware execution authority escaped")
		}
		ann, err := g.discoveryAnnouncement(discovery.V2, discovery.CommandAnnouncement)
		if err != nil || ann.VersionText != target || ann.Firmware != discovery.USWDA26Firmware {
			t.Fatal("discovery target/provenance mismatch")
		}
		if g.reportedCfgVersion != "configuration-b" {
			t.Fatal("firmware transition erased cfg receipt")
		}
	}
	if writes != 3 {
		t.Fatalf("writes=%d", writes)
	}
	cfgAfter, _ := os.ReadFile(state.ReceiptPath(c.Runtime.StateFile))
	adoptionAfter, _ := os.ReadFile(c.Runtime.StateFile)
	if !bytes.Equal(cfgBefore, cfgAfter) || !bytes.Equal(adoptionBefore, adoptionAfter) {
		t.Fatal("firmware rewrote independent state")
	}
	body = []byte(`{"_type":"noop"}`)
	restarted := newReplayTestGateway(t, c, now, controller, nil)
	if restarted.reportedFirmwareVersion != "1.6.4.432" || restarted.reportedCfgVersion != "configuration-b" {
		t.Fatal("restart lost receipts")
	}
	if _, err := restarted.InformOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if sent[len(sent)-1]["version"] != "1.6.4.432" {
		t.Fatal("restart inform lost version")
	}
	// Fresh config-only changes must not erase the firmware target or its file.
	fwBefore, _ := os.ReadFile(state.FirmwareReceiptPath(c.Runtime.StateFile))
	body = receiptResponse(t, "configuration-c")
	if _, err := restarted.InformOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	fwAfter, _ := os.ReadFile(state.FirmwareReceiptPath(c.Runtime.StateFile))
	if !bytes.Equal(fwBefore, fwAfter) || restarted.reportedFirmwareVersion != "1.6.4.432" {
		t.Fatal("cfg transition erased firmware")
	}
	controller.exchange = func(context.Context, string, []byte) ([]byte, error) {
		return encodeGCMControllerResponse(t, testControllerKey, [16]byte{2}, firmwareResponse(t, "1.6.4.432", privateURL)), nil
	}
	if _, err := restarted.InformOnce(context.Background()); !errors.Is(err, ErrControllerResponseReplay) {
		t.Fatal("firmware transition replay survived restart")
	}
	for _, endpoint := range []string{"/readyz", "/metrics"} {
		rec := httptest.NewRecorder()
		g.monitor.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, endpoint, nil))
		logs.WriteString(rec.Body.String())
	}
	logs.Write(fwAfter)
	if strings.Contains(logs.String(), "do-not-retain") || strings.Contains(logs.String(), trap.URL) || hits.Load() != 0 {
		t.Fatal("inert URL reached sink")
	}
	if _, err := state.LoadOrCreate(c.Runtime.StateFile, c.Device.MAC, c.Device.Serial, c.UniFi.InformURL, inform.DefaultKey); err != nil {
		t.Fatal("rollback state broken")
	}
}

func TestFirmwareFailureRateLimitAndReplayIsolation(t *testing.T) {
	for _, failure := range []string{"write", "post-rename", "config-blocked", "rate-limit", "clock-regression"} {
		t.Run(failure, func(t *testing.T) {
			c := receiptConfiguration(t, "persistent")
			c.UniFi.ReportedFirmwareSync = true
			now := time.Unix(1800000000, 0)
			var nonce byte
			target := "1.6.4.432"
			controller := &functionalController{exchange: func(context.Context, string, []byte) ([]byte, error) {
				nonce++
				return encodeGCMControllerResponse(t, testControllerKey, [16]byte{nonce}, firmwareResponse(t, target, "file:///no-execution")), nil
			}}
			g := newReplayTestGateway(t, c, now, controller, nil)
			g.now = func() time.Time { return now }
			writes := 0
			g.saveFirmwareReceipt = func(path string, r state.FirmwareReceipt) error {
				writes++
				if failure == "write" {
					return errors.New("private write failure")
				}
				if err := state.SaveFirmwareReceipt(path, r); err != nil {
					return err
				}
				if failure == "post-rename" {
					return errors.New("directory sync ambiguity")
				}
				return nil
			}
			if failure == "config-blocked" {
				g.receiptBlocked = true
			}
			if failure == "rate-limit" || failure == "clock-regression" {
				if _, err := g.InformOnce(context.Background()); err != nil {
					t.Fatal(err)
				}
				target = "1.4.12"
				if failure == "clock-regression" {
					now = now.Add(-time.Second)
				}
			}
			before := g.reportedFirmwareVersion
			for i := 0; i < 2; i++ {
				var err error
				if failure == "clock-regression" {
					nonce++
					err = g.acceptFirmwareTarget(inform.FirmwareTarget{Version: target}, [16]byte{nonce}, now)
				} else {
					_, err = g.InformOnce(context.Background())
				}
				if err == nil {
					t.Fatal("blocked target accepted")
				}
			}
			if g.reportedFirmwareVersion != before || writes > 1 {
				t.Fatal("failure advanced target or amplified writes")
			}
			if g.firmwareReceipt.Contains([16]byte{nonce}) {
				t.Fatal("failed target nonce committed")
			}
		})
	}
}

func TestFirmwareDiscoveryConcurrentSnapshots(t *testing.T) {
	c := receiptConfiguration(t, "persistent")
	c.UniFi.ReportedFirmwareSync = true
	now := time.Unix(1800000000, 0)
	g := newReplayTestGateway(t, c, now, &functionalController{exchange: func(context.Context, string, []byte) ([]byte, error) { return nil, errors.New("not used") }}, nil)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			ann, err := g.discoveryAnnouncement(discovery.V2, discovery.CommandAnnouncement)
			if err != nil {
				t.Error(err)
				return
			}
			if ann.VersionText != "1.6.1.413" && ann.VersionText != "1.6.4.432" && ann.VersionText != "1.4.12" {
				t.Error("torn target")
			}
		}
	}()
	for i := 0; i < 8; i++ {
		v := "1.6.4.432"
		if i%2 == 1 {
			v = "1.4.12"
		}
		g.informMu.Lock()
		err := g.acceptFirmwareTarget(inform.FirmwareTarget{Version: v}, [16]byte{byte(i + 1)}, now.Add(time.Duration(i)*40*time.Second))
		g.informMu.Unlock()
		if err != nil {
			t.Fatal(err)
		}
	}
	wg.Wait()
}

func TestFirmwareSyncOffAndMalformedCannotMutate(t *testing.T) {
	for _, body := range [][]byte{[]byte(`{"_type":"upgrade","version":"1.6.4.432","cmd":"reboot"}`), []byte(`{"_type":"upgrade","version":"1.6.4.432","url":null}`)} {
		c := receiptConfiguration(t, "persistent")
		c.UniFi.ReportedFirmwareSync = true
		g := newReplayTestGateway(t, c, time.Unix(1800000000, 0), &functionalController{exchange: func(context.Context, string, []byte) ([]byte, error) {
			return encodeGCMControllerResponse(t, testControllerKey, [16]byte{1}, body), nil
		}}, nil)
		before := g.persistent
		g.saveFirmwareReceipt = func(string, state.FirmwareReceipt) error { t.Fatal("rejected target saved"); return nil }
		if _, err := g.InformOnce(context.Background()); err == nil {
			t.Fatal("malformed upgrade succeeded")
		}
		if !reflect.DeepEqual(before, g.persistent) || g.reportedFirmwareVersion != "" {
			t.Fatal("rejection mutated state")
		}
	}
	c := receiptConfiguration(t, "persistent")
	if err := os.WriteFile(state.FirmwareReceiptPath(c.Runtime.StateFile), []byte("corrupt-off-cache"), 0600); err != nil {
		t.Fatal(err)
	}
	g := newReplayTestGateway(t, c, time.Unix(1800000000, 0), &functionalController{exchange: func(context.Context, string, []byte) ([]byte, error) {
		return encodeGCMControllerResponse(t, testControllerKey, [16]byte{1}, firmwareResponse(t, "1.6.4.432", "http://127.0.0.1/unused")), nil
	}}, nil)
	g.saveFirmwareReceipt = func(string, state.FirmwareReceipt) error { t.Fatal("disabled sync wrote"); return nil }
	out, err := g.InformOnce(context.Background())
	if err != nil || out.RestartRequested || g.reportedFirmwareVersion != "" || g.firmwareBlocked {
		t.Fatal("off mode touched firmware state")
	}
}

func TestFirmwareReceiptStartupIsolation(t *testing.T) {
	for _, change := range []string{"corrupt", "config-corrupt", "source", "key", "origin"} {
		t.Run(change, func(t *testing.T) {
			c := receiptConfiguration(t, "persistent")
			c.UniFi.ReportedFirmwareSync = true
			now := time.Unix(1800000000, 0)
			controller := &functionalController{exchange: func(context.Context, string, []byte) ([]byte, error) { return nil, errors.New("unused") }}
			g := newReplayTestGateway(t, c, now, controller, nil)
			if err := g.acceptFirmwareTarget(inform.FirmwareTarget{Version: "1.6.4.432"}, [16]byte{1}, now); err != nil {
				t.Fatal(err)
			}
			switch change {
			case "corrupt", "config-corrupt":
				path := state.FirmwareReceiptPath(c.Runtime.StateFile)
				if change == "config-corrupt" {
					path = state.ReceiptPath(c.Runtime.StateFile)
				}
				if os.WriteFile(path, []byte("corrupt"), 0600) != nil {
					t.Fatal("write")
				}
			case "source":
				c.UniFi.Model = inform.ModelUPS2UProEU
			case "key":
				seedManagedGCMState(t, c, "ffeeddccbbaa99887766554433221100", "baseline")
			case "origin":
				c.UniFi.InformURL = "http://192.0.2.11:8080/inform"
				seedManagedGCMState(t, c, testControllerKey, "baseline")
			}
			restarted := newReplayTestGateway(t, c, now, controller, nil)
			if restarted.reportedFirmwareVersion != "" {
				t.Fatal("stale or corrupt target restored")
			}
			if (change == "corrupt") != restarted.firmwareBlocked {
				t.Fatal("wrong firmware blocking state")
			}
			if change == "config-corrupt" && !restarted.receiptBlocked {
				t.Fatal("corrupt dependency not blocked")
			}
		})
	}
}

func TestFirmwareDiscoveryCarrierFields(t *testing.T) {
	for _, model := range []string{inform.ModelUPS2UEU, inform.ModelUPS2UProEU} {
		c := receiptConfiguration(t, "persistent")
		c.UniFi.ReportedFirmwareSync = true
		c.UniFi.Model = model
		now := time.Unix(1800000000, 0)
		g := newReplayTestGateway(t, c, now, &functionalController{}, nil)
		baseline, err := g.discoveryAnnouncement(discovery.V2, discovery.CommandAnnouncement)
		if err != nil {
			t.Fatal(err)
		}
		if err := g.acceptFirmwareTarget(inform.FirmwareTarget{Version: "1.4.12"}, [16]byte{1}, now); err != nil {
			t.Fatal(err)
		}
		target, err := g.discoveryAnnouncement(discovery.V2, discovery.CommandAnnouncement)
		if err != nil {
			t.Fatal(err)
		}
		if target.VersionText != "1.4.12" {
			t.Fatal("short version not mirrored")
		}
		target.VersionText = baseline.VersionText
		if model == inform.ModelUPS2UProEU {
			if target.Firmware != "1.4.12" {
				t.Fatal("Pro firmware TLV not mirrored")
			}
			target.Firmware = baseline.Firmware
		}
		target.Sequence = baseline.Sequence
		if !reflect.DeepEqual(target, baseline) {
			t.Fatal("discovery identity/profile changed")
		}
	}
}

func TestFirmwareSyncDoesNotWidenTrustModes(t *testing.T) {
	for _, variant := range []string{"default-key", "CBC", "HTTPS"} {
		t.Run(variant, func(t *testing.T) {
			c := receiptConfiguration(t, "persistent")
			c.UniFi.ReportedFirmwareSync = true
			key := testControllerKey
			switch variant {
			case "default-key":
				key = inform.DefaultKey
				seedManagedGCMState(t, c, key, "baseline")
			case "CBC":
				seedManagedCBCState(t, c, key, "baseline")
			case "HTTPS":
				c.UniFi.InformURL = "https://192.0.2.10:8443/inform"
				seedManagedGCMState(t, c, key, "baseline")
			}
			controller := &functionalController{exchange: func(context.Context, string, []byte) ([]byte, error) {
				body := firmwareResponse(t, "1.4.12", "file:///unused")
				if variant == "CBC" {
					return encodeCBCControllerResponse(t, key, body), nil
				}
				return encodeGCMControllerResponse(t, key, [16]byte{1}, body), nil
			}}
			g := newReplayTestGateway(t, c, time.Unix(1800000000, 0), controller, nil)
			g.saveFirmwareReceipt = func(string, state.FirmwareReceipt) error { t.Fatal("ineligible target saved"); return nil }
			_, _ = g.InformOnce(context.Background()) // Preserve the legacy trust-mode outcome, never create a target receipt.
			if g.reportedFirmwareVersion != "" || g.firmwareEpoch != "" {
				t.Fatal("target escaped eligible trust mode")
			}
			if _, err := os.Stat(state.FirmwareReceiptPath(c.Runtime.StateFile)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("ineligible file created")
			}
		})
	}
}
