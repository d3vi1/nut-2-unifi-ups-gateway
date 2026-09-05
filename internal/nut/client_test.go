package nut

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"

	"github.com/d3vi1/nut-2-unifi-ups-gateway/internal/diagnostic"
)

func TestPollAuthenticatesAndParsesQuotedVariables(t *testing.T) {
	address := serveOnce(t, func(connection net.Conn) {
		server := newTestServer(t, connection)
		server.expect(`USERNAME monitor`)
		server.reply("OK")
		server.expect(`PASSWORD "correct horse"`)
		server.reply("OK")
		server.expect("LIST VAR ups")
		server.reply("BEGIN LIST VAR ups")
		server.reply(`VAR ups device.mfr "ACME \"Power\" \\ Rack"`)
		server.reply(`VAR ups battery.charge "100"`)
		server.reply("END LIST VAR ups")
	})

	client := mustClient(t, Config{
		Address:  address,
		UPSName:  "ups",
		Username: "monitor",
		Password: "correct horse",
	})
	snapshot, err := client.Poll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got, want := snapshot.Variables["device.mfr"], `ACME "Power" \ Rack`; got != want {
		t.Fatalf("manufacturer = %q, want %q", got, want)
	}
}

func TestPollIsReadOnlyAndStopsAfterVariables(t *testing.T) {
	address := serveOnce(t, func(connection net.Conn) {
		server := newTestServer(t, connection)
		server.expect("LIST VAR ups")
		server.reply("BEGIN LIST VAR ups")
		server.reply(`VAR ups ups.status "OL"`)
		server.reply("END LIST VAR ups")
		if line, err := server.reader.ReadString('\n'); err == nil {
			t.Errorf("unexpected request after LIST VAR: %q", line)
		}
	})

	client := mustClient(t, Config{Address: address, UPSName: "ups"})
	snapshot, err := client.Poll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Variables["ups.status"] != "OL" {
		t.Fatalf("lost valid telemetry: %+v", snapshot)
	}
}

func TestPollRejectsDuplicateAndOversizedData(t *testing.T) {
	t.Run("duplicate variable", func(t *testing.T) {
		address := serveOnce(t, func(connection net.Conn) {
			server := newTestServer(t, connection)
			server.expect("LIST VAR ups")
			server.reply("BEGIN LIST VAR ups")
			server.reply(`VAR ups ups.status "OL"`)
			server.reply(`VAR ups ups.status "OB"`)
		})
		client := mustClient(t, Config{Address: address, UPSName: "ups"})
		if _, err := client.Poll(context.Background()); err == nil || diagnostic.Reason(err, diagnostic.Internal) != "nut_protocol" || !strings.Contains(errors.Unwrap(err).Error(), "duplicate") {
			t.Fatalf("expected duplicate rejection, got %v", err)
		}
	})

	t.Run("line limit", func(t *testing.T) {
		address := serveOnce(t, func(connection net.Conn) {
			server := newTestServer(t, connection)
			server.expect("LIST VAR ups")
			server.reply("BEGIN LIST VAR ups")
			server.reply(`VAR ups device.description "` + strings.Repeat("x", 600) + `"`)
		})
		client := mustClient(t, Config{
			Address:      address,
			UPSName:      "ups",
			MaxLineBytes: 256,
		})
		if _, err := client.Poll(context.Background()); err == nil {
			t.Fatal("expected oversized line rejection")
		}
	})

	t.Run("total byte limit", func(t *testing.T) {
		address := serveOnce(t, func(connection net.Conn) {
			server := newTestServer(t, connection)
			server.expect("LIST VAR ups")
			server.reply("BEGIN LIST VAR ups")
			server.reply(`VAR ups device.description "` + strings.Repeat("x", 300) + `"`)
			server.reply(`VAR ups device.model "` + strings.Repeat("y", 300) + `"`)
		})
		client := mustClient(t, Config{
			Address:       address,
			UPSName:       "ups",
			MaxTotalBytes: 512,
		})
		if _, err := client.Poll(context.Background()); err == nil || diagnostic.Reason(err, diagnostic.Internal) != "nut_protocol" || !strings.Contains(errors.Unwrap(err).Error(), "byte limit") {
			t.Fatalf("expected total byte limit rejection, got %v", err)
		}
	})

	t.Run("wire bytes include padding", func(t *testing.T) {
		address := serveOnce(t, func(connection net.Conn) {
			server := newTestServer(t, connection)
			server.expect("LIST VAR ups")
			server.reply("BEGIN LIST VAR ups")
			server.reply(`VAR ups ups.status "OL"` + strings.Repeat(" ", 600))
		})
		client := mustClient(t, Config{
			Address:       address,
			UPSName:       "ups",
			MaxTotalBytes: 512,
		})
		if _, err := client.Poll(context.Background()); err == nil || diagnostic.Reason(err, diagnostic.Internal) != "nut_protocol" || !strings.Contains(errors.Unwrap(err).Error(), "byte limit") {
			t.Fatalf("expected padded wire line rejection, got %v", err)
		}
	})
}

func TestAuthenticationErrorDoesNotExposePassword(t *testing.T) {
	address := serveOnce(t, func(connection net.Conn) {
		server := newTestServer(t, connection)
		server.expect("USERNAME monitor")
		server.reply("OK")
		server.expect("PASSWORD swordfish")
		server.reply("ERR ACCESS-DENIED")
	})
	client := mustClient(t, Config{
		Address:  address,
		UPSName:  "ups",
		Username: "monitor",
		Password: "swordfish",
	})
	_, err := client.Poll(context.Background())
	if err == nil {
		t.Fatal("expected authentication failure")
	}
	if strings.Contains(err.Error(), "swordfish") {
		t.Fatalf("password leaked in error: %v", err)
	}
}

func TestPollDiagnosticCodesDoNotEchoServerInput(t *testing.T) {
	for _, tt := range []struct{ reply, reason string }{
		{"ERR ACCESS-DENIED", "nut_auth"},
		{"ERR UNKNOWN-UPS", "nut_unknown_ups"},
		{"ERR DATA-STALE", "nut_unavailable"},
		{"ERR DRIVER-NOT-CONNECTED", "nut_unavailable"},
		{"ERR secret-serial-password", "nut_protocol"},
		{"VAR secret-serial-password", "nut_protocol"},
	} {
		t.Run(tt.reason+tt.reply, func(t *testing.T) {
			address := serveOnce(t, func(connection net.Conn) {
				server := newTestServer(t, connection)
				server.expect("LIST VAR ups")
				server.reply(tt.reply)
			})
			_, err := mustClient(t, Config{Address: address, UPSName: "ups"}).Poll(context.Background())
			if err == nil || err.Error() != tt.reason || diagnostic.Reason(err, diagnostic.Internal) != tt.reason {
				t.Fatalf("incorrect fixed diagnostic: %v", err)
			}
		})
	}
}

func TestAuthenticationDoesNotSendLoginOrCommandRequests(t *testing.T) {
	address := serveOnce(t, func(connection net.Conn) {
		server := newTestServer(t, connection)
		server.expect("USERNAME monitor")
		server.reply("OK")
		server.expect("PASSWORD swordfish")
		server.reply("OK")
		server.expect("LIST VAR ups")
		server.reply("BEGIN LIST VAR ups")
		server.reply(`VAR ups ups.status "OL"`)
		server.reply("END LIST VAR ups")
	})
	client := mustClient(t, Config{
		Address:  address,
		UPSName:  "ups",
		Username: "monitor",
		Password: "swordfish",
	})
	if _, err := client.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestCredentialsRejectProtocolControlCharacters(t *testing.T) {
	_, err := New(Config{
		Address:  "127.0.0.1:3493",
		UPSName:  "ups",
		Username: "monitor",
		Password: "unsafe\tpassword",
	})
	if err == nil {
		t.Fatal("expected protocol control character to fail validation")
	}
}

func TestParseLine(t *testing.T) {
	tests := []struct {
		name string
		line string
		want []string
	}{
		{name: "empty quoted value", line: `VAR ups device.desc ""`, want: []string{"VAR", "ups", "device.desc", ""}},
		{name: "spaces and escapes", line: `VAR ups device.desc "rack \"A\" \\ room"`, want: []string{"VAR", "ups", "device.desc", `rack "A" \ room`}},
		{name: "tabs", line: "OK\tgood", want: []string{"OK", "good"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := parseLine(test.line)
			if err != nil {
				t.Fatal(err)
			}
			if fmt.Sprint(got) != fmt.Sprint(test.want) {
				t.Fatalf("tokens = %#v, want %#v", got, test.want)
			}
		})
	}
	for _, malformed := range []string{
		`VAR ups device.desc "unterminated`,
		`VAR ups device.desc "bad\n"`,
		`VAR ups device.desc "closed"suffix`,
	} {
		if _, err := parseLine(malformed); err == nil {
			t.Fatalf("expected %q to be rejected", malformed)
		}
	}
}

func mustClient(t *testing.T, config Config) *Client {
	t.Helper()
	client, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

type testServer struct {
	t      *testing.T
	reader *bufio.Reader
	writer *bufio.Writer
}

func newTestServer(t *testing.T, connection net.Conn) *testServer {
	t.Helper()
	return &testServer{
		t:      t,
		reader: bufio.NewReader(connection),
		writer: bufio.NewWriter(connection),
	}
}

func (s *testServer) expect(expected string) {
	s.t.Helper()
	line, err := s.reader.ReadString('\n')
	if err != nil {
		s.t.Errorf("read request: %v", err)
		return
	}
	if got := strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r"); got != expected {
		s.t.Errorf("request = %q, want %q", got, expected)
	}
}

func (s *testServer) reply(line string) {
	s.t.Helper()
	if _, err := s.writer.WriteString(line + "\n"); err != nil {
		s.t.Errorf("write response: %v", err)
		return
	}
	if err := s.writer.Flush(); err != nil {
		s.t.Errorf("flush response: %v", err)
	}
}

func serveOnce(t *testing.T, handler func(net.Conn)) string {
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
		handler(connection)
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		wait.Wait()
	})
	return listener.Addr().String()
}
