package main

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHealthcheckUsesConfiguredListener(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/healthz" {
			response.WriteHeader(http.StatusNotFound)
			return
		}
		response.WriteHeader(http.StatusOK)
	})}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })
	if err := runHealthcheck(context.Background(), listener.Addr().String()); err != nil {
		t.Fatal(err)
	}
}

func TestStartupErrorsUseSafeReasons(t *testing.T) {
	t.Run("configuration", func(t *testing.T) {
		t.Setenv("N2U_UNKNOWN_secret", "private")
		var stdout, stderr bytes.Buffer
		if run(context.Background(), nil, &stdout, &stderr) != 2 || !strings.Contains(stderr.String(), "reason=configuration_invalid") || strings.Contains(stderr.String(), "secret") || strings.Contains(stderr.String(), "private") {
			t.Fatal("configuration diagnostic leaked or lost its reason")
		}
	})
	for _, tt := range []struct {
		mode   os.FileMode
		reason string
	}{{0600, "state_invalid"}, {0644, "state_permissions"}} {
		t.Run(tt.reason, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "private-state.json")
			if err := os.WriteFile(path, []byte(`{"secret-password":"private"}`), tt.mode); err != nil {
				t.Fatal(err)
			}
			t.Setenv("N2U_STATE_FILE", path)
			t.Setenv("N2U_INFORM_URL", "http://127.0.0.1:8080/inform")
			var stdout, stderr bytes.Buffer
			if run(context.Background(), nil, &stdout, &stderr) != 1 || !strings.Contains(stderr.String(), `"reason":"`+tt.reason+`"`) || strings.Contains(stderr.String(), "secret") || strings.Contains(stderr.String(), "private") {
				t.Fatal("state diagnostic leaked or lost its reason")
			}
		})
	}
}

func TestVersionAndUsageAreSideEffectFree(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"version"}, &stdout, &stderr); code != 0 {
		t.Fatalf("version exit code = %d", code)
	}
	if stdout.Len() == 0 || stderr.Len() != 0 {
		t.Fatalf("unexpected output: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := run(context.Background(), []string{"unexpected"}, &stdout, &stderr); code != 2 {
		t.Fatalf("usage exit code = %d", code)
	}
}
