// Package health exposes a deliberately small, identity-free health surface.
package health

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

const (
	maxHealthHeaderBytes = 16 << 10
	maxHealthConnections = 32
)

type Monitor struct {
	mu                        sync.RWMutex
	started                   time.Time
	staleAfter                time.Duration
	upstreamAt                time.Time
	upstreamOK                bool
	informAt                  time.Time
	informOK                  bool
	adopted                   bool
	receiptStatus             ReceiptStatus
	ignoredControllerSettings int

	pollsTotal         atomic.Uint64
	pollErrorsTotal    atomic.Uint64
	informsTotal       atomic.Uint64
	informErrorsTotal  atomic.Uint64
	informPendingTotal atomic.Uint64
}

type ReceiptStatus uint8

const (
	ReceiptDisabled ReceiptStatus = iota
	ReceiptPending
	ReceiptReceived
	ReceiptStored
	ReceiptRejected
	ReceiptStorageError
	ReceiptRateLimited
)

func (s ReceiptStatus) String() string {
	switch s {
	case ReceiptPending:
		return "pending"
	case ReceiptReceived:
		return "received"
	case ReceiptStored:
		return "stored"
	case ReceiptRejected:
		return "rejected"
	case ReceiptStorageError:
		return "storage_error"
	case ReceiptRateLimited:
		return "rate_limited"
	default:
		return "disabled"
	}
}

func (m *Monitor) RecordConfigReceipt(status ReceiptStatus) {
	m.mu.Lock()
	m.receiptStatus = status
	m.mu.Unlock()
}
func (m *Monitor) SetIgnoredControllerSettings(count int) {
	if count < 0 || count > 5 {
		return
	}
	m.mu.Lock()
	m.ignoredControllerSettings = count
	m.mu.Unlock()
}

// InformResult classifies the result of one actual controller exchange.
type InformResult uint8

const (
	InformFailure InformResult = iota
	InformSuccess
	InformPending
)

func New(staleAfter time.Duration) *Monitor {
	return &Monitor{started: time.Now(), staleAfter: staleAfter}
}

func (m *Monitor) MarkPoll(now time.Time, ok bool) {
	m.pollsTotal.Add(1)
	if !ok {
		m.pollErrorsTotal.Add(1)
	}
	m.mu.Lock()
	m.upstreamOK = ok
	if ok {
		m.upstreamAt = now
	}
	m.mu.Unlock()
}

// MarkInform records one actual controller exchange attempt. reached describes
// whether the exchange returned an HTTP response, while result distinguishes a
// committed TNBU exchange, HTTP 404 adoption-pending response, and real error.
// Local precondition and projection failures must not call MarkInform.
func (m *Monitor) MarkInform(now time.Time, reached bool, result InformResult) {
	m.informsTotal.Add(1)
	switch result {
	case InformSuccess:
	case InformPending:
		m.informPendingTotal.Add(1)
	default:
		m.informErrorsTotal.Add(1)
	}
	m.mu.Lock()
	m.informOK = reached
	if reached {
		m.informAt = now
	}
	m.mu.Unlock()
}

func (m *Monitor) SetAdopted(v bool) {
	m.mu.Lock()
	m.adopted = v
	m.mu.Unlock()
}

type snapshot struct {
	ConfigReceipt             string `json:"configuration_receipt"`
	IgnoredControllerSettings int    `json:"ignored_controller_setting_categories"`
	Status                    string `json:"status"`
	UpstreamFresh             bool   `json:"upstream_fresh"`
	ControllerReachable       bool   `json:"controller_reachable"`
	Adopted                   bool   `json:"adopted"`
	UptimeSeconds             int64  `json:"uptime_seconds"`
}

func (m *Monitor) Snapshot(now time.Time) (snapshot, bool) {
	m.mu.RLock()
	fresh := m.upstreamOK && !m.upstreamAt.IsZero() && now.Sub(m.upstreamAt) <= m.staleAfter
	s := snapshot{
		ConfigReceipt:             m.receiptStatus.String(),
		IgnoredControllerSettings: m.ignoredControllerSettings,
		Status:                    "not_ready",
		UpstreamFresh:             fresh,
		ControllerReachable:       m.informOK,
		Adopted:                   m.adopted,
		UptimeSeconds:             int64(now.Sub(m.started).Seconds()),
	}
	m.mu.RUnlock()
	if fresh {
		s.Status = "ready"
	}
	return s, fresh
}

func (m *Monitor) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "alive"})
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		s, ready := m.Snapshot(time.Now())
		code := http.StatusServiceUnavailable
		if ready {
			code = http.StatusOK
		}
		writeJSON(w, code, s)
	})
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, _ *http.Request) {
		s, ready := m.Snapshot(time.Now())
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		fmt.Fprintf(w, "# HELP n2u_ready Whether upstream NUT telemetry is fresh.\n")
		fmt.Fprintf(w, "# TYPE n2u_ready gauge\n")
		fmt.Fprintf(w, "n2u_ready %s\n", boolNumber(ready))
		fmt.Fprintf(w, "# TYPE n2u_controller_reachable gauge\n")
		fmt.Fprintf(w, "n2u_controller_reachable %s\n", boolNumber(s.ControllerReachable))
		fmt.Fprintf(w, "# TYPE n2u_adopted gauge\n")
		fmt.Fprintf(w, "n2u_adopted %s\n", boolNumber(s.Adopted))
		fmt.Fprintf(w, "# TYPE n2u_nut_polls_total counter\n")
		fmt.Fprintf(w, "n2u_nut_polls_total %d\n", m.pollsTotal.Load())
		fmt.Fprintf(w, "# TYPE n2u_nut_poll_errors_total counter\n")
		fmt.Fprintf(w, "n2u_nut_poll_errors_total %d\n", m.pollErrorsTotal.Load())
		fmt.Fprintf(w, "# TYPE n2u_informs_total counter\n")
		fmt.Fprintf(w, "n2u_informs_total %d\n", m.informsTotal.Load())
		fmt.Fprintf(w, "# TYPE n2u_inform_errors_total counter\n")
		fmt.Fprintf(w, "n2u_inform_errors_total %d\n", m.informErrorsTotal.Load())
		fmt.Fprintf(w, "# HELP n2u_inform_pending_total HTTP 404 inform responses; adoption may be pending or the profile may be unrecognized.\n")
		fmt.Fprintf(w, "# TYPE n2u_inform_pending_total counter\n")
		fmt.Fprintf(w, "n2u_inform_pending_total %d\n", m.informPendingTotal.Load())
		fmt.Fprintln(w, "# HELP n2u_ignored_controller_setting_categories Unsupported setting categories in the last eligible configuration receipt; no settings are applied.")
		fmt.Fprintln(w, "# TYPE n2u_ignored_controller_setting_categories gauge")
		fmt.Fprintf(w, "n2u_ignored_controller_setting_categories %d\n", s.IgnoredControllerSettings)
		fmt.Fprintln(w, "# TYPE n2u_config_receipt_status gauge")
		for _, status := range []ReceiptStatus{ReceiptDisabled, ReceiptPending, ReceiptReceived, ReceiptStored, ReceiptRejected, ReceiptStorageError, ReceiptRateLimited} {
			fmt.Fprintf(w, "n2u_config_receipt_status{status=%q} %s\n", status.String(), boolNumber(status.String() == s.ConfigReceipt))
		}
	})
	return mux
}

func Server(address string, handler http.Handler) *http.Server {
	server := &http.Server{
		Addr:              address,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    maxHealthHeaderBytes,
		BaseContext: func(_ net.Listener) context.Context {
			return context.Background()
		},
	}
	server.SetKeepAlivesEnabled(false)
	return server
}

// LimitConnections bounds aggregate health-listener socket and goroutine
// consumption. Capacity is acquired before Accept so net/http can never own
// more than maxHealthConnections live connections. Closing the listener also
// wakes an Accept blocked on capacity.
func LimitConnections(listener net.Listener) net.Listener {
	return limitConnections(listener, maxHealthConnections)
}

type limitedListener struct {
	net.Listener
	slots     chan struct{}
	done      chan struct{}
	closeOnce sync.Once
	closeErr  error
}

func limitConnections(listener net.Listener, maximum int) *limitedListener {
	if maximum < 1 {
		panic("health: connection limit must be positive")
	}
	return &limitedListener{
		Listener: listener,
		slots:    make(chan struct{}, maximum),
		done:     make(chan struct{}),
	}
}

func (l *limitedListener) Accept() (net.Conn, error) {
	select {
	case l.slots <- struct{}{}:
	case <-l.done:
		return nil, net.ErrClosed
	}

	connection, err := l.Listener.Accept()
	if err != nil {
		<-l.slots
		return nil, err
	}
	return &limitedConnection{
		Conn: connection,
		release: func() {
			<-l.slots
		},
	}, nil
}

func (l *limitedListener) Close() error {
	l.closeOnce.Do(func() {
		close(l.done)
		l.closeErr = l.Listener.Close()
	})
	return l.closeErr
}

type limitedConnection struct {
	net.Conn
	releaseOnce sync.Once
	release     func()
}

func (c *limitedConnection) Close() error {
	err := c.Conn.Close()
	c.releaseOnce.Do(c.release)
	return err
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func boolNumber(v bool) string {
	if v {
		return strconv.FormatInt(1, 10)
	}
	return strconv.FormatInt(0, 10)
}
