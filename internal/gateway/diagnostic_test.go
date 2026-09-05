package gateway

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/d3vi1/nut-2-unifi-ups-gateway/internal/diagnostic"
)

type diagnosticTransport func(*http.Request) (*http.Response, error)

func (f diagnosticTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestControllerDiagnosticsKeepTypedCausesAndNoIdentities(t *testing.T) {
	for _, tt := range []struct {
		cause error
		want  string
	}{
		{&net.DNSError{Name: "private.invalid", Err: "secret"}, "controller_dns"},
		{&net.OpError{Op: "secret", Err: os.ErrDeadlineExceeded}, "controller_timeout"},
		{errors.New("secret serial 02:11:22:33:44:55"), "controller_transport"},
	} {
		controller := &HTTPController{client: &http.Client{Transport: diagnosticTransport(func(*http.Request) (*http.Response, error) {
			return nil, tt.cause
		})}}
		_, err := controller.Exchange(context.Background(), "http://private.invalid/inform", []byte("secret packet"))
		if err == nil || err.Error() != tt.want || !errors.Is(err, tt.cause) || controllerResponseReceived(err) {
			t.Fatalf("transport classification/cause changed: %v", err)
		}
		var output bytes.Buffer
		g := &Gateway{logger: slog.New(slog.NewJSONHandler(&output, nil))}
		g.logInformFailure(err)
		if !strings.Contains(output.String(), `"reason":"`+tt.want+`"`) || strings.Contains(output.String(), "secret") || strings.Contains(output.String(), "private") || strings.Contains(output.String(), "02:11") {
			t.Fatal("diagnostic output lost its privacy boundary")
		}
	}
}

func TestHTTPDiagnosticPreservesReachedAndPending(t *testing.T) {
	for _, tt := range []struct {
		status int
		reason string
	}{{503, "controller_http"}, {200, "controller_protocol"}, {404, "pending"}} {
		t.Run(tt.reason, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.status)
			}))
			defer server.Close()
			controller, err := NewHTTPController(time.Second)
			if err != nil {
				t.Fatal(err)
			}
			_, err = controller.Exchange(context.Background(), server.URL+"/inform", []byte("secret"))
			if err == nil || !controllerResponseReceived(err) {
				t.Fatal("HTTP response no longer counts as reached")
			}
			if tt.reason == "pending" {
				if !errors.Is(err, ErrAdoptionPending) {
					t.Fatal("lost pending sentinel")
				}
			} else if diagnostic.Reason(err, diagnostic.ControllerProtocol) != tt.reason {
				t.Fatal("incorrect HTTP reason")
			}
		})
	}
}

func TestLogReasonsNeverUseArbitraryOuterErrorText(t *testing.T) {
	for _, tt := range []struct {
		err    error
		reason string
	}{
		{fmt.Errorf("secret: %w", ErrControllerResponseReplay), "controller_replay"},
		{diagnostic.Wrap(diagnostic.StateWrite, errors.New("secret")), "state_write"},
		{errors.New("secret private.invalid 02:11:22:33:44:55"), "controller_protocol"},
	} {
		var output bytes.Buffer
		g := &Gateway{logger: slog.New(slog.NewJSONHandler(&output, nil))}
		g.logInformFailure(tt.err)
		if strings.Contains(output.String(), "secret") || !strings.Contains(output.String(), `"reason":"`+tt.reason+`"`) {
			t.Fatal("inform logging is not closed")
		}
		output.Reset()
		g.logPollFailure(diagnostic.Wrap(diagnostic.NUTTelemetry, tt.err))
		if strings.Contains(output.String(), "secret") || !strings.Contains(output.String(), `"reason":"nut_telemetry"`) {
			t.Fatal("poll logging is not closed")
		}
	}
}

func TestStartupDNSFailureHasFixedReason(t *testing.T) {
	_, err := ResolveNetworkIdentity(context.Background(), "192.0.2.20", "http://private.invalid:8080/inform", staticResolver{addresses: map[string][]net.IP{}})
	if diagnostic.Reason(err, diagnostic.Internal) != "controller_dns" {
		t.Fatal("startup DNS classification lost")
	}
}
