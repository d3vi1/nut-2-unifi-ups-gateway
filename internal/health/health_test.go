package health

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestReadinessTracksFreshUpstream(t *testing.T) {
	m := New(10 * time.Second)
	now := time.Now()
	if _, ready := m.Snapshot(now); ready {
		t.Fatal("new monitor must not be ready")
	}
	m.MarkPoll(now, true)
	if _, ready := m.Snapshot(now.Add(9 * time.Second)); !ready {
		t.Fatal("fresh upstream should be ready")
	}
	if _, ready := m.Snapshot(now.Add(11 * time.Second)); ready {
		t.Fatal("stale upstream must not be ready")
	}
}

func TestHandlersExposeNoIdentity(t *testing.T) {
	m := New(time.Minute)
	m.MarkPoll(time.Now(), true)
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	for _, forbidden := range []string{"mac", "serial", "auth_key", "password"} {
		if strings.Contains(strings.ToLower(rec.Body.String()), forbidden) {
			t.Fatalf("health output contains forbidden field %q", forbidden)
		}
	}
}

func TestInformReachabilityIsIndependentOfResponseSuccess(t *testing.T) {
	m := New(time.Minute)
	now := time.Now()
	m.MarkInform(now, true, InformFailure)
	snapshot, _ := m.Snapshot(now)
	if !snapshot.ControllerReachable {
		t.Fatal("a received controller response must establish reachability")
	}
	recorder := httptest.NewRecorder()
	m.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	metrics := recorder.Body.String()
	if !strings.Contains(metrics, "n2u_informs_total 1\n") || !strings.Contains(metrics, "n2u_inform_errors_total 1\n") {
		t.Fatalf("unexpected inform metrics:\n%s", metrics)
	}

	m.MarkInform(now.Add(time.Second), false, InformFailure)
	snapshot, _ = m.Snapshot(now.Add(time.Second))
	if snapshot.ControllerReachable {
		t.Fatal("a failed controller exchange must clear reachability")
	}
}

func TestPendingInformHasDedicatedMetricAndIsNotAnError(t *testing.T) {
	m := New(time.Minute)
	now := time.Now()
	m.MarkInform(now, true, InformPending)
	snapshot, _ := m.Snapshot(now)
	if !snapshot.ControllerReachable {
		t.Fatal("a pending HTTP response must establish reachability")
	}
	recorder := httptest.NewRecorder()
	m.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	metrics := recorder.Body.String()
	for _, metric := range []string{
		"n2u_informs_total 1\n",
		"n2u_inform_errors_total 0\n",
		"n2u_inform_pending_total 1\n",
	} {
		if !strings.Contains(metrics, metric) {
			t.Fatalf("missing metric %q:\n%s", metric, metrics)
		}
	}
}

func TestServerBoundsRequestHeaders(t *testing.T) {
	server := Server("127.0.0.1:0", http.NotFoundHandler())
	if server.MaxHeaderBytes != maxHealthHeaderBytes {
		t.Fatalf("MaxHeaderBytes = %d, want %d", server.MaxHeaderBytes, maxHealthHeaderBytes)
	}
	if server.ReadHeaderTimeout <= 0 || server.ReadTimeout <= 0 || server.WriteTimeout <= 0 || server.IdleTimeout <= 0 {
		t.Fatal("health server must retain bounded I/O timeouts")
	}
}

func TestServerDisablesKeepAlives(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := Server(listener.Addr().String(), http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	serveResult := make(chan error, 1)
	go func() {
		serveResult <- server.Serve(LimitConnections(listener))
	}()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			t.Errorf("shutdown health server: %v", err)
		}
		select {
		case err := <-serveResult:
			if !errors.Is(err, http.ErrServerClosed) {
				t.Errorf("Serve returned %v, want http.ErrServerClosed", err)
			}
		case <-time.After(time.Second):
			t.Error("health server did not stop after shutdown")
		}
	})

	var dials atomic.Int32
	dialer := &net.Dialer{Timeout: time.Second}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			dials.Add(1)
			return dialer.DialContext(ctx, network, address)
		},
	}
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport, Timeout: time.Second}

	for requestNumber := 1; requestNumber <= 2; requestNumber++ {
		response, err := client.Get("http://" + listener.Addr().String() + "/healthz")
		if err != nil {
			t.Fatalf("request %d: %v", requestNumber, err)
		}
		_, readErr := io.Copy(io.Discard, response.Body)
		closeErr := response.Body.Close()
		if readErr != nil {
			t.Fatalf("read response %d: %v", requestNumber, readErr)
		}
		if closeErr != nil {
			t.Fatalf("close response %d: %v", requestNumber, closeErr)
		}
		if !response.Close {
			t.Fatalf("response %d did not require closing its connection", requestNumber)
		}
	}
	if got := dials.Load(); got != 2 {
		t.Fatalf("connection dials = %d, want 2 for two sequential requests", got)
	}
}

func TestLimitedListenerBoundsAggregateConnections(t *testing.T) {
	underlying := newQueuedListener()
	listener := limitConnections(underlying, 1)
	firstServer, firstClient := net.Pipe()
	defer firstClient.Close()
	underlying.connections <- firstServer
	first, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}

	secondResult := make(chan error, 1)
	secondServer, secondClient := net.Pipe()
	defer secondClient.Close()
	underlying.connections <- secondServer
	go func() {
		connection, err := listener.Accept()
		if connection != nil {
			_ = connection.Close()
		}
		secondResult <- err
	}()

	select {
	case err := <-secondResult:
		t.Fatalf("second connection escaped the aggregate limit: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	if got := underlying.acceptCalls.Load(); got != 1 {
		t.Fatalf("underlying Accept calls = %d, want 1 while capacity is full", got)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-secondResult:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("second Accept did not proceed after capacity was released")
	}
	if got := underlying.acceptCalls.Load(); got != 2 {
		t.Fatalf("underlying Accept calls = %d, want 2", got)
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestLimitedListenerCloseUnblocksSaturatedAccept(t *testing.T) {
	underlying := newQueuedListener()
	listener := limitConnections(underlying, 1)
	server, client := net.Pipe()
	defer client.Close()
	underlying.connections <- server
	accepted, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer accepted.Close()

	result := make(chan error, 1)
	go func() {
		_, err := listener.Accept()
		result <- err
	}()
	select {
	case err := <-result:
		t.Fatalf("capacity-blocked Accept returned before close: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if err := listener.Close(); err != nil {
		t.Fatalf("second listener close = %v, want idempotent success", err)
	}
	select {
	case err := <-result:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("blocked Accept error = %v, want net.ErrClosed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("closing listener did not wake capacity-blocked Accept")
	}
}

func TestLimitedConnectionReleasesCapacityOnce(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	var releases atomic.Int32
	connection := &limitedConnection{Conn: server, release: func() { releases.Add(1) }}
	_ = connection.Close()
	_ = connection.Close()
	if got := releases.Load(); got != 1 {
		t.Fatalf("capacity releases = %d, want 1", got)
	}
}

type queuedListener struct {
	connections chan net.Conn
	done        chan struct{}
	closeOnce   sync.Once
	acceptCalls atomic.Int32
}

func newQueuedListener() *queuedListener {
	return &queuedListener{connections: make(chan net.Conn, 4), done: make(chan struct{})}
}

func (l *queuedListener) Accept() (net.Conn, error) {
	l.acceptCalls.Add(1)
	select {
	case connection := <-l.connections:
		return connection, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *queuedListener) Close() error {
	l.closeOnce.Do(func() { close(l.done) })
	return nil
}

func (*queuedListener) Addr() net.Addr { return testAddress("health-test") }

type testAddress string

func (a testAddress) Network() string { return string(a) }
func (a testAddress) String() string  { return string(a) }
