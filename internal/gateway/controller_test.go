package gateway

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHTTPControllerBoundsStatusAndRedirects(t *testing.T) {
	t.Run("firmware HTTP fingerprint", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			if request.Header.Get("Content-Type") != "application/x-binary" ||
				request.Header.Get("User-Agent") != "ESP32 HTTP Client/1.0" ||
				request.Header.Get("Accept") != "" {
				t.Errorf("unexpected HTTP fingerprint: content-type=%q user-agent=%q accept=%q",
					request.Header.Get("Content-Type"), request.Header.Get("User-Agent"), request.Header.Get("Accept"))
			}
			_, _ = response.Write([]byte("reply"))
		}))
		defer server.Close()
		client, err := NewHTTPController(time.Second)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := client.Exchange(context.Background(), server.URL+"/inform", []byte("packet")); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("404 is adoption pending and reached", func(t *testing.T) {
		server := httptest.NewServer(http.NotFoundHandler())
		defer server.Close()
		client, err := NewHTTPController(time.Second)
		if err != nil {
			t.Fatal(err)
		}
		_, err = client.Exchange(context.Background(), server.URL+"/inform", []byte("packet"))
		if !errors.Is(err, ErrAdoptionPending) {
			t.Fatalf("404 error = %v, want ErrAdoptionPending", err)
		}
		if !controllerResponseReceived(err) {
			t.Fatal("404 response was not classified as controller-reached")
		}
	})

	t.Run("bounded response", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
			response.Header().Set("Content-Length", "1048617")
			response.WriteHeader(http.StatusOK)
		}))
		defer server.Close()
		client, err := NewHTTPController(time.Second)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := client.Exchange(context.Background(), server.URL+"/inform", []byte("packet")); err == nil {
			t.Fatal("oversized controller response accepted")
		}
	})

	t.Run("cross-origin redirect", func(t *testing.T) {
		destination := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			t.Error("cross-origin destination was reached")
		}))
		defer destination.Close()
		source := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			http.Redirect(response, request, destination.URL+"/inform", http.StatusTemporaryRedirect)
		}))
		defer source.Close()
		client, err := NewHTTPController(time.Second)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := client.Exchange(context.Background(), source.URL+"/inform", []byte("packet")); err == nil {
			t.Fatal("cross-origin controller redirect accepted")
		}
	})

	t.Run("same-origin redirect rejected", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			if request.URL.Path == "/inform" {
				http.Redirect(response, request, "/reply", http.StatusTemporaryRedirect)
				return
			}
			_, _ = io.WriteString(response, "reply")
		}))
		defer server.Close()
		client, err := NewHTTPController(time.Second)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := client.Exchange(context.Background(), server.URL+"/inform", []byte("packet")); err == nil {
			t.Fatal("same-origin redirect was followed")
		}
	})

	t.Run("non-200 success status rejected", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
			response.WriteHeader(http.StatusNoContent)
		}))
		defer server.Close()
		client, err := NewHTTPController(time.Second)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := client.Exchange(context.Background(), server.URL+"/inform", []byte("packet")); err == nil {
			t.Fatal("firmware-incompatible non-200 status accepted")
		} else if !controllerResponseReceived(err) || errors.Is(err, ErrAdoptionPending) {
			t.Fatalf("non-200 response classification = %v", err)
		}
	})
}

func TestControllerTransitionRequiresExactOrigin(t *testing.T) {
	client, err := NewHTTPController(time.Second)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := client.AuthorizeTransition(ctx, "http://controller.local:8080/inform", "http://controller.local:8080/inform"); err != nil {
		t.Fatal(err)
	}
	for _, proposed := range []string{
		"http://controller-ip:8080/inform",
		"http://other.local:8080/inform",
		"https://controller-ip:8080/inform",
		"http://controller-ip:8443/inform",
	} {
		if err := client.AuthorizeTransition(ctx, "http://controller.local:8080/inform", proposed); err == nil {
			t.Fatalf("unsafe controller transition accepted: %s", proposed)
		}
	}
}

func TestHTTPControllerErrorsDoNotEchoPacketOrURL(t *testing.T) {
	client, err := NewHTTPController(100 * time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	secret := "secret-packet-material"
	endpoint := "http://127.0.0.1:1/inform"
	_, err = client.Exchange(context.Background(), endpoint, []byte(secret))
	if err == nil || strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), endpoint) {
		t.Fatalf("error leaked request material: %v", err)
	}
	if controllerResponseReceived(err) {
		t.Fatal("transport failure was classified as a controller response")
	}
}

type staticResolver struct {
	addresses map[string][]net.IP
}

func (r staticResolver) LookupIP(_ context.Context, _ string, host string) ([]net.IP, error) {
	return append([]net.IP(nil), r.addresses[host]...), nil
}
