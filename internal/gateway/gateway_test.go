package gateway

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/d3vi1/nut-2-unifi-ups-gateway/internal/config"
	"github.com/d3vi1/nut-2-unifi-ups-gateway/internal/health"
	"github.com/d3vi1/nut-2-unifi-ups-gateway/internal/nut"
	"github.com/d3vi1/nut-2-unifi-ups-gateway/internal/state"
	"github.com/d3vi1/nut-2-unifi-ups-gateway/internal/unifi/discovery"
	"github.com/d3vi1/nut-2-unifi-ups-gateway/internal/unifi/inform"
)

const testControllerKey = "00112233445566778899aabbccddeeff"

func TestCycleWithFakeNUTAndHTTPControllerPersistsAdoption(t *testing.T) {
	nutAddress := startFakeNUT(t, []string{
		`VAR ups ups.status "OL"`,
		`VAR ups battery.charge "100"`,
		`VAR ups battery.runtime "2040"`,
		`VAR ups input.voltage "230.1"`,
		`VAR ups output.voltage "229.9"`,
		`VAR ups ups.realpower "225"`,
	})

	var (
		controllerURL string
		requestJSON   map[string]any
	)
	controllerServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/inform" || request.Header.Get("Content-Type") != "application/x-binary" {
			t.Errorf("unexpected inform request: %s %s", request.Method, request.URL.Path)
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		body, err := io.ReadAll(io.LimitReader(request.Body, 2<<20))
		if err != nil {
			t.Error(err)
			return
		}
		decoded, err := inform.Decode(body, inform.DefaultKey)
		if err != nil {
			t.Errorf("decode request: %v", err)
			return
		}
		if err := json.Unmarshal(decoded.Payload, &requestJSON); err != nil {
			t.Errorf("decode request JSON: %v", err)
			return
		}
		encoder, err := inform.NewEncoder()
		if err != nil {
			t.Error(err)
			return
		}
		replyJSON := []byte(`{"_type":"setparam","mgmt_cfg":"cfgversion=1\nauthkey=` + testControllerKey + `\ninform_url=` + controllerURL + `/inform\n"}`)
		reply, err := encoder.Encode(inform.Packet{MAC: decoded.MAC, Payload: replyJSON}, inform.DefaultKey, inform.ModeCBC)
		if err != nil {
			t.Error(err)
			return
		}
		response.Header().Set("Content-Type", "application/x-binary")
		_, _ = response.Write(reply)
	}))
	defer controllerServer.Close()
	controllerURL = controllerServer.URL

	configuration := baseConfig(t)
	configuration.NUT.Address = nutAddress
	configuration.UniFi.InformURL = controllerURL + "/inform"
	monitor := health.New(configuration.Runtime.StaleAfter)
	service, err := New(context.Background(), configuration, Options{
		Monitor: monitor,
		Network: NetworkIdentity{DeviceIP: "192.0.2.20", InformIP: "192.0.2.10", Netmask: "255.255.255.0"},
	})
	if err != nil {
		t.Fatal(err)
	}
	outcome, err := service.Cycle(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Kind != inform.ResponseSetParam {
		t.Fatalf("outcome kind = %d, want adoption", outcome.Kind)
	}
	if requestJSON["model"] != "UPS26" || requestJSON["version"] != "1.6.1.413" || requestJSON["required_version"] != "1.3.4" {
		t.Fatalf("unexpected model payload: %v", requestJSON["model"])
	}
	if requestJSON["guid"] != "317875ca-ad3e-47e9-9430-47e3e2e1ab3d" {
		t.Fatalf("unexpected profile GUID: %v", requestJSON["guid"])
	}
	announcement, err := service.discoveryAnnouncement(discovery.V2, discovery.CommandAnnouncement)
	if err != nil {
		t.Fatal(err)
	}
	if announcement.HashID == nil || announcement.AnonID == nil {
		t.Fatal("discovery omitted opaque device identifiers")
	}
	if requestJSON["hash_id"] != hex.EncodeToString(announcement.HashID[:]) {
		t.Fatal("inform hash_id does not match discovery TLV 0x27")
	}
	anonText, ok := requestJSON["anon_id"].(string)
	if !ok {
		t.Fatal("inform omitted textual anon_id")
	}
	if anonText[14] != '8' || anonText[19] != '4' {
		t.Fatalf("firmware-specific anonymous UUID normalization drifted: %s", anonText)
	}
	anonBytes, err := hex.DecodeString(strings.ReplaceAll(anonText, "-", ""))
	if err != nil || !bytes.Equal(anonBytes, announcement.AnonID[:]) {
		t.Fatal("inform anon_id does not match discovery TLV 0x2a")
	}
	outlets, ok := requestJSON["outlet_table"].([]any)
	if !ok || len(outlets) != 8 {
		t.Fatalf("outlet topology = %#v", requestJSON["outlet_table"])
	}
	persisted, err := state.LoadOrCreate(configuration.Runtime.StateFile, configuration.Device.MAC, configuration.Device.Serial, configuration.UniFi.InformURL, inform.DefaultKey)
	if err != nil {
		t.Fatal(err)
	}
	if !persisted.Adoption.Adopted || persisted.Adoption.AuthKey != testControllerKey {
		t.Fatal("adoption state was not persisted")
	}
	info, err := os.Stat(configuration.Runtime.StateFile)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("state file is not owner-only: info=%v err=%v", info, err)
	}
	_, ready := monitor.Snapshot(time.Now())
	if !ready {
		t.Fatal("valid NUT observation did not make the gateway ready")
	}
}

func TestInvalidOrFailedPollNeverReusesPriorTelemetry(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	tests := []struct {
		name      string
		snapshots []nut.Snapshot
		errors    []error
		calls     int
	}{
		{
			name: "missing status",
			snapshots: []nut.Snapshot{{CollectedAt: now, Variables: map[string]string{
				"battery.charge": "99",
			}}},
			calls: 1,
		},
		{
			name: "stale observation",
			snapshots: []nut.Snapshot{{CollectedAt: now.Add(-time.Minute), Variables: map[string]string{
				"ups.status": "OL", "battery.charge": "99",
			}}},
			calls: 1,
		},
		{
			name: "failed poll invalidates prior valid snapshot",
			snapshots: []nut.Snapshot{
				{CollectedAt: now, Variables: map[string]string{"ups.status": "OL"}},
				{},
			},
			errors: []error{nil, errors.New("upstream unavailable")},
			calls:  2,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			configuration := baseConfig(t)
			controller := &encodedController{payload: []byte(`{"_type":"noop"}`)}
			poller := &sequencePoller{snapshots: test.snapshots, errors: test.errors}
			service, err := New(context.Background(), configuration, Options{
				Poller: poller, Controller: controller, Now: func() time.Time { return now },
				Network: NetworkIdentity{DeviceIP: "192.0.2.20", InformIP: "192.0.2.10", Netmask: "255.255.255.0"},
			})
			if err != nil {
				t.Fatal(err)
			}
			for index := 0; index < test.calls; index++ {
				_ = service.PollOnce(context.Background())
			}
			if _, err := service.InformOnce(context.Background()); err == nil {
				t.Fatal("invalid upstream state was informed")
			}
			if controller.calls != 0 {
				t.Fatalf("controller called %d times", controller.calls)
			}
		})
	}
}

func TestSkippedInformPreservesLastControllerReachability(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	configuration := baseConfig(t)
	monitor := health.New(configuration.Runtime.StaleAfter)
	controller := &encodedController{payload: []byte(`{"_type":"noop"}`)}
	service, err := New(context.Background(), configuration, Options{
		Poller: &sequencePoller{
			snapshots: []nut.Snapshot{
				{CollectedAt: now, Variables: map[string]string{"ups.status": "OL"}},
				{},
			},
			errors: []error{nil, errors.New("upstream unavailable")},
		},
		Controller: controller,
		Monitor:    monitor,
		Now:        func() time.Time { return now },
		Network:    NetworkIdentity{DeviceIP: "192.0.2.20", InformIP: "192.0.2.10", Netmask: "255.255.255.0"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := service.PollOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := service.InformOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if snapshot, _ := monitor.Snapshot(now); !snapshot.ControllerReachable {
		t.Fatal("successful controller exchange did not establish reachability")
	}
	if err := service.PollOnce(context.Background()); err == nil {
		t.Fatal("second poll unexpectedly succeeded")
	}
	if _, err := service.InformOnce(context.Background()); err == nil {
		t.Fatal("inform unexpectedly used invalid upstream state")
	}
	if snapshot, _ := monitor.Snapshot(now); !snapshot.ControllerReachable {
		t.Fatal("locally skipped inform cleared prior controller reachability")
	}
	if controller.calls != 1 {
		t.Fatalf("controller calls = %d, want 1", controller.calls)
	}
	recorder := httptest.NewRecorder()
	monitor.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	metrics := recorder.Body.String()
	if !strings.Contains(metrics, "n2u_informs_total 1\n") || !strings.Contains(metrics, "n2u_inform_errors_total 0\n") {
		t.Fatalf("locally skipped inform changed attempt counters:\n%s", metrics)
	}
}

func TestHTTPInformResponseClassificationUpdatesHealth(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	tests := []struct {
		name              string
		status            int
		wantPending       bool
		wantErrors        string
		wantPendingMetric string
	}{
		{name: "404 pending", status: http.StatusNotFound, wantPending: true, wantErrors: "0", wantPendingMetric: "1"},
		{name: "503 failure", status: http.StatusServiceUnavailable, wantErrors: "1", wantPendingMetric: "0"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
				response.WriteHeader(test.status)
			}))
			defer server.Close()

			configuration := baseConfig(t)
			configuration.UniFi.InformURL = server.URL + "/inform"
			monitor := health.New(configuration.Runtime.StaleAfter)
			controller, err := NewHTTPController(configuration.UniFi.InformTimeout)
			if err != nil {
				t.Fatal(err)
			}
			service, err := New(context.Background(), configuration, Options{
				Poller: &sequencePoller{snapshots: []nut.Snapshot{{
					CollectedAt: now,
					Variables:   map[string]string{"ups.status": "OL"},
				}}},
				Controller: controller,
				Monitor:    monitor,
				Now:        func() time.Time { return now },
				Network:    NetworkIdentity{DeviceIP: "192.0.2.20", InformIP: "192.0.2.10", Netmask: "255.255.255.0"},
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := service.PollOnce(context.Background()); err != nil {
				t.Fatal(err)
			}
			_, err = service.InformOnce(context.Background())
			if err == nil {
				t.Fatal("non-success HTTP response was accepted")
			}
			if errors.Is(err, ErrAdoptionPending) != test.wantPending {
				t.Fatalf("pending classification = %v, want %v: %v", errors.Is(err, ErrAdoptionPending), test.wantPending, err)
			}
			snapshot, _ := monitor.Snapshot(now)
			if !snapshot.ControllerReachable || snapshot.Adopted {
				t.Fatalf("health after HTTP response = %+v", snapshot)
			}
			if !service.lastInform.IsZero() || service.persistent.Adoption.Adopted {
				t.Fatal("rejected HTTP response changed committed adoption state")
			}
			recorder := httptest.NewRecorder()
			monitor.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))
			metrics := recorder.Body.String()
			for _, metric := range []string{
				"n2u_informs_total 1\n",
				"n2u_inform_errors_total " + test.wantErrors + "\n",
				"n2u_inform_pending_total " + test.wantPendingMetric + "\n",
			} {
				if !strings.Contains(metrics, metric) {
					t.Fatalf("missing metric %q:\n%s", metric, metrics)
				}
			}
		})
	}
}

func TestPendingInformLoggingIsDiagnosticWithoutWarningSpam(t *testing.T) {
	var output bytes.Buffer
	service := &Gateway{logger: slog.New(slog.NewTextHandler(&output, &slog.HandlerOptions{Level: slog.LevelDebug}))}
	service.logInformFailure(ErrAdoptionPending)
	logLine := output.String()
	if !strings.Contains(logLine, "level=DEBUG") || !strings.Contains(logLine, "pending or device profile unrecognized") {
		t.Fatalf("pending diagnostic log = %q", logLine)
	}
	if strings.Contains(logLine, "level=WARN") {
		t.Fatalf("pending inform emitted warning: %q", logLine)
	}
}

func TestPollingContinuesWhileControllerExchangeIsBlocked(t *testing.T) {
	configuration := baseConfig(t)
	controller := newBlockingController()
	poller := &signalingPoller{
		called: make(chan struct{}, 16),
		snapshot: nut.Snapshot{
			Variables: map[string]string{"ups.status": "OL"},
		},
	}
	service, err := New(context.Background(), configuration, Options{
		Poller: poller, Controller: controller, Now: time.Now,
		Network: NetworkIdentity{DeviceIP: "192.0.2.20", InformIP: "192.0.2.10", Netmask: "255.255.255.0"},
	})
	if err != nil {
		t.Fatal(err)
	}
	// New validates production intervals before test seams shorten this one.
	service.configuration.Runtime.PollInterval = 5 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	initialPollDone := make(chan struct{})
	var workers sync.WaitGroup
	workers.Add(2)
	go func() {
		defer workers.Done()
		service.pollLoop(ctx, initialPollDone)
	}()
	go func() {
		defer workers.Done()
		service.informLoop(ctx, initialPollDone)
	}()

	select {
	case <-controller.started:
	case <-time.After(time.Second):
		cancel()
		t.Fatal("controller exchange did not start")
	}
	for polls := 0; polls < 2; polls++ {
		select {
		case <-poller.called:
		case <-time.After(time.Second):
			cancel()
			t.Fatalf("poll %d did not complete while controller was blocked", polls+1)
		}
	}
	cancel()
	done := make(chan struct{})
	go func() {
		workers.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("poll and inform workers did not stop after cancellation")
	}
}

func TestUnprovenControllerWritesNeverReachNUT(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	responses := []struct {
		body      string
		kind      inform.ResponseKind
		wantError bool
	}{
		{body: `{"_type":"setstate","outlet_overrides":[{"index":1,"relay_state":false}]}`, wantError: true},
		{body: `{"_type":"cmd","cmd":"relayctl","outlet_table":[{"index":1,"delay_time_to_off":0,"delay_time_to_on":0.1}]}`, kind: inform.ResponseRelayControl},
	}
	for _, response := range responses {
		configuration := baseConfig(t)
		poller := &writeCapablePoller{snapshot: nut.Snapshot{
			CollectedAt: now,
			Variables:   map[string]string{"ups.status": "OL", "outlet.group.1.status": "on"},
		}}
		service, err := New(context.Background(), configuration, Options{
			Poller: poller, Controller: &encodedController{payload: []byte(response.body)}, Now: func() time.Time { return now },
			Network: NetworkIdentity{DeviceIP: "192.0.2.20", InformIP: "192.0.2.10", Netmask: "255.255.255.0"},
		})
		if err != nil {
			t.Fatal(err)
		}
		outcome, err := service.Cycle(context.Background())
		if response.wantError {
			if err == nil {
				t.Fatal("unsupported controller response was accepted")
			}
		} else {
			if err != nil {
				t.Fatal(err)
			}
			if outcome.Kind != response.kind {
				t.Fatalf("response kind = %d, want %d", outcome.Kind, response.kind)
			}
		}
		if len(poller.commands) != 0 {
			t.Fatalf("unproven controller write reached NUT: %v", poller.commands)
		}
	}
}

func TestControllerCannotExtendLocalInformInterval(t *testing.T) {
	tests := []struct {
		name      string
		requested time.Duration
		maximum   time.Duration
		want      time.Duration
	}{
		{name: "zero remains unchanged signal", maximum: 10 * time.Second},
		{name: "shorter controller interval", requested: 4 * time.Second, maximum: 10 * time.Second, want: 4 * time.Second},
		{name: "longer controller interval is capped", requested: 24 * time.Hour, maximum: 10 * time.Second, want: 10 * time.Second},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := cappedInformInterval(test.requested, test.maximum); got != test.want {
				t.Fatalf("interval = %s, want %s", got, test.want)
			}
		})
	}

	now := time.Unix(1_800_000_000, 0).UTC()
	configuration := baseConfig(t)
	service, err := New(context.Background(), configuration, Options{
		Poller: &sequencePoller{snapshots: []nut.Snapshot{{
			CollectedAt: now,
			Variables:   map[string]string{"ups.status": "OL"},
		}}},
		Controller: &encodedController{payload: []byte(`{"_type":"noop","interval":86400}`)},
		Now:        func() time.Time { return now },
		Network:    NetworkIdentity{DeviceIP: "192.0.2.20", InformIP: "192.0.2.10", Netmask: "255.255.255.0"},
	})
	if err != nil {
		t.Fatal(err)
	}
	outcome, err := service.Cycle(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Interval != configuration.UniFi.InformInterval {
		t.Fatalf("gateway interval = %s, want local maximum %s", outcome.Interval, configuration.UniFi.InformInterval)
	}
}

func TestDiscoveryIdentityIsStableAndReflectsAdoption(t *testing.T) {
	configuration := baseConfig(t)
	configuration.UniFi.Model = inform.ModelUPS2UProEU
	configuration.UniFi.Version = "1.6.1"
	service, err := New(context.Background(), configuration, Options{
		Poller: &sequencePoller{}, Controller: &encodedController{payload: []byte(`{"_type":"noop"}`)},
		Network: NetworkIdentity{DeviceIP: "192.0.2.20", InformIP: "192.0.2.10", Netmask: "255.255.255.0"},
	})
	if err != nil {
		t.Fatal(err)
	}
	pending, err := service.discoveryAnnouncement(discovery.V2, discovery.CommandAnnouncement)
	if err != nil {
		t.Fatal(err)
	}
	if pending.Sequence != 1 {
		t.Fatalf("first discovery sequence = %d, want 1", pending.Sequence)
	}
	service.mu.Lock()
	service.persistent.Adoption.AuthKey = testControllerKey
	service.persistent.Adoption.Adopted = true
	service.mu.Unlock()
	adopted, err := service.discoveryAnnouncement(discovery.V2, discovery.CommandAnnouncement)
	if err != nil {
		t.Fatal(err)
	}
	if pending.IsDefault == nil || !*pending.IsDefault || adopted.IsDefault == nil || *adopted.IsDefault {
		t.Fatal("discovery is_default did not follow adoption state")
	}
	if pending.Sequence+1 != adopted.Sequence || pending.HashID == nil || adopted.HashID == nil || *pending.HashID != *adopted.HashID || *pending.AnonID != *adopted.AnonID {
		t.Fatal("discovery sequence or stable derived identity is wrong")
	}
	if *pending.HashID == [8]byte{} || *pending.AnonID == [16]byte{} || string(pending.HashID[:]) == string(pending.AnonID[:8]) {
		t.Fatal("domain-separated discovery identifiers are empty or equal")
	}
	if adopted.Model != "UPSPROEU" || adopted.Platform != "esp32s3" || adopted.Hardware != "ESP32-S3" || adopted.Firmware != "1.6.1.4933" || adopted.VersionText != "1.6.1.4933" || adopted.BoardID == nil || *adopted.BoardID != 0xda2c {
		t.Fatalf("unexpected Pro discovery fingerprint: %+v", adopted)
	}
}

func baseConfig(t *testing.T) config.Config {
	t.Helper()
	return config.Config{
		NUT: config.NUT{Address: "127.0.0.1:3493", UPSName: "ups", Timeout: time.Second},
		UniFi: config.UniFi{
			Model: inform.ModelUPS2UEU, Version: "1.6.1", InformURL: "http://192.0.2.10:8080/inform",
			InformInterval: 10 * time.Second, InformTimeout: time.Second, DiscoveryInterval: 30 * time.Second,
		},
		Device: config.Device{MAC: "02:11:22:33:44:55", Serial: "N2UTEST0001", Hostname: "n2u-test", IP: "192.0.2.20"},
		Runtime: config.Runtime{
			StateFile: filepath.Join(t.TempDir(), "state.json"), HealthAddress: "127.0.0.1:0",
			PollInterval: time.Second, StaleAfter: 20 * time.Second,
		},
		LogLevel: "info",
	}
}

type sequencePoller struct {
	mu        sync.Mutex
	snapshots []nut.Snapshot
	errors    []error
	index     int
}

func (p *sequencePoller) Poll(context.Context) (nut.Snapshot, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	index := p.index
	p.index++
	var snapshot nut.Snapshot
	if index < len(p.snapshots) {
		snapshot = p.snapshots[index]
	}
	if index < len(p.errors) {
		return snapshot, p.errors[index]
	}
	return snapshot, nil
}

type encodedController struct {
	payload []byte
	calls   int
}

func (c *encodedController) Exchange(_ context.Context, _ string, request []byte) ([]byte, error) {
	c.calls++
	decoded, err := inform.Decode(request, inform.DefaultKey)
	if err != nil {
		return nil, err
	}
	encoder, err := inform.NewEncoder()
	if err != nil {
		return nil, err
	}
	return encoder.Encode(inform.Packet{MAC: decoded.MAC, Payload: c.payload}, inform.DefaultKey, inform.ModeCBC)
}

func (*encodedController) AuthorizeTransition(context.Context, string, string) error { return nil }

type signalingPoller struct {
	called   chan struct{}
	snapshot nut.Snapshot
}

func (p *signalingPoller) Poll(context.Context) (nut.Snapshot, error) {
	snapshot := p.snapshot
	snapshot.CollectedAt = time.Now()
	p.called <- struct{}{}
	return snapshot, nil
}

type blockingController struct {
	started chan struct{}
	once    sync.Once
}

func newBlockingController() *blockingController {
	return &blockingController{started: make(chan struct{})}
}

func (c *blockingController) Exchange(ctx context.Context, _ string, _ []byte) ([]byte, error) {
	c.once.Do(func() { close(c.started) })
	<-ctx.Done()
	return nil, ctx.Err()
}

func (*blockingController) AuthorizeTransition(context.Context, string, string) error { return nil }

type writeCapablePoller struct {
	snapshot nut.Snapshot
	commands []string
}

func (p *writeCapablePoller) Poll(context.Context) (nut.Snapshot, error) {
	return p.snapshot, nil
}

func (p *writeCapablePoller) InstantCommand(_ context.Context, command string) error {
	p.commands = append(p.commands, command)
	return nil
}

func startFakeNUT(t *testing.T, variables []string) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var wait sync.WaitGroup
	wait.Add(1)
	go func() {
		defer wait.Done()
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		defer connection.Close()
		reader := bufio.NewReader(connection)
		writer := bufio.NewWriter(connection)
		expectLine(t, reader, "LIST VAR ups")
		writeLines(t, writer, append(append([]string{"BEGIN LIST VAR ups"}, variables...), "END LIST VAR ups")...)
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		wait.Wait()
	})
	return listener.Addr().String()
}

func expectLine(t *testing.T, reader *bufio.Reader, expected string) {
	t.Helper()
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Errorf("read fake NUT request: %v", err)
		return
	}
	if strings.TrimSpace(line) != expected {
		t.Errorf("fake NUT request = %q, want %q", strings.TrimSpace(line), expected)
	}
}

func writeLines(t *testing.T, writer *bufio.Writer, lines ...string) {
	t.Helper()
	for _, line := range lines {
		if _, err := writer.WriteString(line + "\n"); err != nil {
			t.Errorf("write fake NUT response: %v", err)
			return
		}
	}
	if err := writer.Flush(); err != nil {
		t.Errorf("flush fake NUT response: %v", err)
	}
}
