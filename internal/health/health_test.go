package health

import (
	"net/http"
	"net/http/httptest"
	"strings"
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
