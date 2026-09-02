package gateway

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/d3vi1/nut-2-unifi-ups-gateway/internal/unifi/inform"
)

const maxControllerWireResponse = inform.HeaderLength + (1 << 20)

// ErrAdoptionPending classifies the HTTP 404 commonly returned while UniFi
// Network has not yet accepted an initial inform. It is not proof that the
// device is adoptable: a persistent 404 can also mean an unsupported profile.
var ErrAdoptionPending = errors.New("controller inform is pending or unrecognized")

// controllerResponseError records that the HTTP exchange reached a controller
// and received a response, even though that response was not a usable TNBU
// reply. It deliberately retains no URL, response body, or request material.
type controllerResponseError struct {
	cause error
}

func (e *controllerResponseError) Error() string { return e.cause.Error() }
func (e *controllerResponseError) Unwrap() error { return e.cause }

func controllerResponseReceived(err error) bool {
	var responseError *controllerResponseError
	return errors.Is(err, ErrAdoptionPending) || errors.As(err, &responseError)
}

// Controller exchanges an already encoded TNBU packet with UniFi Network and
// authorizes controller-requested changes to the inform endpoint.
type Controller interface {
	Exchange(context.Context, string, []byte) ([]byte, error)
	AuthorizeTransition(context.Context, string, string) error
}

// Resolver is the net.Resolver subset used only to derive startup network
// identity. Controller-origin authorization deliberately performs no DNS
// equivalence check.
type Resolver interface {
	LookupIP(context.Context, string, string) ([]net.IP, error)
}

// HTTPController is a bounded inform client. It deliberately ignores proxy
// environment variables so an adoption key cannot leave through an ambient
// HTTP proxy.
type HTTPController struct {
	client *http.Client
}

// NewHTTPController constructs an inform client with bounded I/O and TLS 1.2+
// for HTTPS controllers.
func NewHTTPController(timeout time.Duration) (*HTTPController, error) {
	if timeout <= 0 || timeout > time.Minute {
		return nil, errors.New("controller timeout must be positive and at most one minute")
	}
	transport := &http.Transport{
		Proxy:                  nil,
		DialContext:            (&net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:      true,
		MaxIdleConns:           4,
		MaxIdleConnsPerHost:    2,
		IdleConnTimeout:        30 * time.Second,
		TLSHandshakeTimeout:    timeout,
		ResponseHeaderTimeout:  timeout,
		ExpectContinueTimeout:  time.Second,
		DisableCompression:     true,
		MaxResponseHeaderBytes: 16 << 10,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12},
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return &HTTPController{client: client}, nil
}

// Exchange posts one opaque TNBU body and returns one bounded opaque reply.
// Neither packet content nor controller-issued keys are retained in errors.
func (c *HTTPController) Exchange(ctx context.Context, endpoint string, packet []byte) ([]byte, error) {
	if c == nil || c.client == nil || len(packet) == 0 || len(packet) > inform.HeaderLength+(1<<20) {
		return nil, errors.New("controller exchange has invalid input")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(packet))
	if err != nil {
		return nil, errors.New("create controller request")
	}
	request.Header.Set("Content-Type", "application/x-binary")
	request.Header.Set("User-Agent", "ESP32 HTTP Client/1.0")

	response, err := c.client.Do(request)
	if err != nil {
		return nil, errors.New("controller request failed")
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotFound {
		return nil, &controllerResponseError{cause: ErrAdoptionPending}
	}
	if response.StatusCode != http.StatusOK {
		return nil, &controllerResponseError{cause: errors.New("controller returned a non-success status")}
	}
	if response.ContentLength > maxControllerWireResponse {
		return nil, &controllerResponseError{cause: errors.New("controller response exceeds limit")}
	}
	limited := &io.LimitedReader{R: response.Body, N: maxControllerWireResponse + 1}
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, &controllerResponseError{cause: errors.New("read controller response")}
	}
	if len(body) == 0 || len(body) > maxControllerWireResponse {
		return nil, &controllerResponseError{cause: errors.New("controller response has invalid size")}
	}
	return body, nil
}

// AuthorizeTransition permits only the exact configured origin. DNS-based
// equivalence is intentionally rejected: persisting a controller-supplied
// hostname after one matching lookup would create a rebinding window.
func (c *HTTPController) AuthorizeTransition(_ context.Context, current, proposed string) error {
	if c == nil || c.client == nil {
		return errors.New("controller client is unavailable")
	}
	from, err := parseControllerURL(current)
	if err != nil {
		return err
	}
	to, err := parseControllerURL(proposed)
	if err != nil {
		return err
	}
	if !sameOrigin(from, to) {
		return errors.New("controller inform origin change is not authorized")
	}
	return nil
}

func parseControllerURL(raw string) (*url.URL, error) {
	if len(raw) == 0 || len(raw) > 2048 {
		return nil, errors.New("invalid controller inform URL")
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("invalid controller inform URL")
	}
	if u.Path != "/inform" {
		return nil, errors.New("invalid controller inform URL path")
	}
	return u, nil
}

func sameOrigin(left, right *url.URL) bool {
	return strings.EqualFold(left.Scheme, right.Scheme) &&
		strings.EqualFold(left.Hostname(), right.Hostname()) &&
		effectivePort(left) == effectivePort(right)
}

func effectivePort(u *url.URL) string {
	if port := u.Port(); port != "" {
		return port
	}
	if strings.EqualFold(u.Scheme, "https") {
		return "443"
	}
	return "80"
}
