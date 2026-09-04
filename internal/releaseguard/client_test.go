package releaseguard

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestProductionHTTPClientIsBounded(t *testing.T) {
	github := newGitHubService()
	if github.apiBase.String() != githubAPIOrigin || github.uploadBase.String() != githubUploadOrigin {
		t.Fatal("production origins are not fixed to GitHub")
	}
	if github.client.Timeout <= 0 || github.client.Timeout > 30*time.Second {
		t.Fatalf("unexpected overall timeout: %v", github.client.Timeout)
	}
	transport, ok := github.client.Transport.(*http.Transport)
	if !ok {
		t.Fatal("production transport has an unexpected type")
	}
	if transport.Proxy != nil || !transport.DisableCompression || !transport.DisableKeepAlives || transport.ResponseHeaderTimeout <= 0 || transport.TLSHandshakeTimeout <= 0 || transport.MaxResponseHeaderBytes <= 0 {
		t.Fatal("production transport safety bounds are incomplete")
	}
	if transport.TLSClientConfig == nil || transport.TLSClientConfig.MinVersion < tls.VersionTLS12 {
		t.Fatal("production transport permits TLS below 1.2")
	}
	if github.client.CheckRedirect == nil {
		t.Fatal("redirect policy is missing")
	}
}

func TestRequestUsesHeaderCredentialAndRejectsRedirect(t *testing.T) {
	const secret = "release-token-never-in-url-or-error"
	var redirected atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/redirected" {
			redirected.Store(true)
			writer.WriteHeader(http.StatusOK)
			return
		}
		if request.Header.Get("Authorization") != "Bearer "+secret {
			t.Error("missing bearer header")
		}
		if request.Header.Get("X-GitHub-Api-Version") != apiVersion {
			t.Error("missing pinned API version")
		}
		if strings.Contains(request.RequestURI, secret) {
			t.Error("credential appeared in request URI")
		}
		http.Redirect(writer, request, "/redirected", http.StatusFound)
	}))
	defer server.Close()
	github, err := newService(server.Client(), server.URL, server.URL)
	if err != nil {
		t.Fatal(err)
	}
	_, err = github.apiJSON(context.Background(), secret, http.MethodGet, "/redirect", nil, nil, http.StatusOK)
	if err == nil {
		t.Fatal("redirect unexpectedly succeeded")
	}
	if redirected.Load() {
		t.Fatal("redirect target was contacted")
	}
	if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), server.URL) {
		t.Fatal("request error exposed sensitive request context")
	}
}

func TestRequestTimeoutIsSanitized(t *testing.T) {
	const secret = "timeout-token-never-print"
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		time.Sleep(100 * time.Millisecond)
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()
	client := server.Client()
	client.Timeout = 10 * time.Millisecond
	github, err := newService(client, server.URL, server.URL)
	if err != nil {
		t.Fatal(err)
	}
	_, err = github.apiJSON(context.Background(), secret, http.MethodGet, "/slow", nil, nil, http.StatusOK)
	if err == nil {
		t.Fatal("timed-out request unexpectedly succeeded")
	}
	if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), server.URL) {
		t.Fatal("timeout error exposed sensitive request context")
	}
}

func TestRequestRejectsBoundedAndUnexpectedResponses(t *testing.T) {
	const secret = "bounded-response-token"
	tests := []struct {
		name   string
		status int
		body   string
	}{
		{name: "oversized", status: http.StatusOK, body: strings.Repeat("x", maxResponseBody+1)},
		{name: "unexpected status", status: http.StatusInternalServerError, body: "secret-response-body"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				writer.WriteHeader(test.status)
				_, _ = writer.Write([]byte(test.body))
			}))
			defer server.Close()
			github, err := newService(server.Client(), server.URL, server.URL)
			if err != nil {
				t.Fatal(err)
			}
			_, err = github.apiJSON(context.Background(), secret, http.MethodGet, "/bounded", nil, nil, http.StatusOK)
			if err == nil {
				t.Fatal("unsafe response unexpectedly succeeded")
			}
			if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), test.body) {
				t.Fatal("response error exposed sensitive data")
			}
		})
	}
}

func TestDecodeJSONRejectsMalformedOrAmbiguousInput(t *testing.T) {
	tests := [][]byte{
		nil,
		[]byte(`{`),
		[]byte(`{"enabled":true,"enabled":false}`),
		[]byte(`{"nested":{"id":1,"id":2}}`),
		[]byte(`{"enabled":true} trailing`),
	}
	for _, payload := range tests {
		var destination map[string]any
		if err := decodeJSON(payload, &destination); err == nil {
			t.Fatalf("decodeJSON(%q) unexpectedly succeeded", payload)
		}
	}
}

func TestParseOriginRejectsCredentialAndNonHTTPOrigins(t *testing.T) {
	invalid := []string{"", "api.github.com", "ftp://api.github.com", "https://user@example.com", "https://example.com?q=1", "https://example.com/#fragment"}
	for _, origin := range invalid {
		if _, err := parseOrigin(origin); err == nil {
			t.Errorf("parseOrigin(%q) unexpectedly succeeded", origin)
		}
	}
}
