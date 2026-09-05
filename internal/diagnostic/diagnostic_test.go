package diagnostic

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
)

func TestDiagnosticsAreClosedAndPreserveCause(t *testing.T) {
	cause := errors.New("secret-key http://private.invalid/token serial-private")
	for _, code := range []Code{StateWrite, ControllerProtocol, Code(255)} {
		err := Wrap(code, cause)
		if !errors.Is(err, cause) {
			t.Fatal("lost cause identity")
		}
		for _, text := range []string{err.Error(), fmt.Sprintf("%+v", err), fmt.Sprintf("%#v", err), Reason(err, Internal)} {
			if strings.Contains(text, "secret") || strings.Contains(text, "private") || text != code.String() {
				t.Fatal("untrusted text escaped")
			}
		}
	}
	if Wrap(Internal, nil) != nil || Reason(cause, StateInvalid) != "state_invalid" {
		t.Fatal("fallback contract")
	}
	if got := Reason(Network(&net.DNSError{Name: "private.invalid", Err: "secret"}, ControllerDNS, ControllerTimeout, ControllerTransport), Internal); got != "controller_dns" {
		t.Fatal(got)
	}
	if got := Reason(Network(&net.DNSError{Name: "private.invalid", IsTimeout: true}, NUTDNS, NUTTimeout, NUTConnect), Internal); got != "nut_dns" {
		t.Fatal(got)
	}
}

func TestFallbackAndNetworkClassification(t *testing.T) {
	cause := &net.OpError{Op: "private", Addr: &net.TCPAddr{IP: net.IPv4(192, 0, 2, 7)}, Err: os.ErrDeadlineExceeded}
	err := Network(cause, ControllerDNS, ControllerTimeout, ControllerTransport)
	err = Fallback(Internal, fmt.Errorf("private wrapper: %w", err))
	var networkError *net.OpError
	if err.Error() != "controller_timeout" || !errors.As(err, &networkError) || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal("fallback lost the classification or typed cause")
	}
	if Fallback(Internal, nil) != nil || Network(nil, NUTDNS, NUTTimeout, NUTConnect) != nil {
		t.Fatal("nil error was changed")
	}
	if Reason(Network(errors.New("untrusted"), NUTDNS, NUTTimeout, NUTConnect), Internal) != "nut_connect" {
		t.Fatal("unknown network error did not use fixed fallback")
	}
	for code := 0; code < 256; code++ {
		text := Reason(Wrap(Code(code), errors.New("untrusted")), Internal)
		if text != Code(code).String() || strings.ContainsAny(text, ":/ .\n") {
			t.Fatal("diagnostic vocabulary is not bounded")
		}
	}
}
