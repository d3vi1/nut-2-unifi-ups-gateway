package gateway

import (
	"context"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestBoundHTTPPinsAddressWithoutLosingHost(t *testing.T) {
	observed := make(chan bool, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, _ := net.SplitHostPort(r.RemoteAddr)
		observed <- host == "127.0.0.1" && strings.HasPrefix(r.Host, "controller.invalid:")
		_, _ = w.Write([]byte("reply"))
	}))
	defer server.Close()
	_, port, _ := net.SplitHostPort(server.Listener.Addr().String())
	client, err := newBoundHTTPController(time.Second, "127.0.0.1", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	defer client.client.CloseIdleConnections()
	if _, err := client.Exchange(context.Background(), "http://controller.invalid:"+port+"/inform", []byte("request")); err != nil {
		t.Fatal(err)
	}
	if !<-observed {
		t.Fatal("HTTP source or Host did not match selected identity")
	}
}

func TestBoundHTTPNeverFallsBackToAnotherSource(t *testing.T) {
	const absent = "192.0.2.253"
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, address := range addresses {
		if ip, ok := address.(*net.IPNet); ok && ip.IP.Equal(net.ParseIP(absent)) {
			t.Skip("test source is assigned on this runner")
		}
	}
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); _, _ = w.Write([]byte("reply")) }))
	defer server.Close()
	client, err := newBoundHTTPController(time.Second, absent, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	defer client.client.CloseIdleConnections()
	if _, err := client.Exchange(context.Background(), server.URL+"/inform", []byte("request")); err == nil {
		t.Fatal("absent source silently fell back")
	}
	if calls.Load() != 0 {
		t.Fatal("request used an unselected source")
	}
}

func TestBoundHTTPSStillVerifiesOriginalHostname(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("reply")) }))
	defer server.Close()
	client, err := newBoundHTTPController(time.Second, "127.0.0.1", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	defer client.client.CloseIdleConnections()
	transport := client.client.Transport.(*http.Transport)
	transport.TLSClientConfig.RootCAs = x509.NewCertPool()
	transport.TLSClientConfig.RootCAs.AddCert(server.Certificate())
	if _, err := client.Exchange(context.Background(), server.URL+"/inform", []byte("request")); err != nil {
		t.Fatal(err)
	}
	_, port, _ := net.SplitHostPort(server.Listener.Addr().String())
	if _, err := client.Exchange(context.Background(), "https://wrong-name.invalid:"+port+"/inform", []byte("request")); err == nil {
		t.Fatal("pinned IP bypassed TLS hostname verification")
	}
}
