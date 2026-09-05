// Package diagnostic provides a closed vocabulary for operational logs.
// Causes remain available to errors.Is/As, but never become diagnostic text.
package diagnostic

import (
	"errors"
	"net"
)

type Code uint8

const (
	Internal Code = iota
	Configuration
	StateRead
	StateInvalid
	StatePermissions
	StateWrite
	IdentityMismatch
	ControllerDNS
	ControllerRoute
	ControllerTransport
	ControllerTimeout
	ControllerHTTP
	ControllerProtocol
	ControllerReplay
	NUTDNS
	NUTConnect
	NUTTimeout
	NUTAuth
	NUTUnknownUPS
	NUTUnavailable
	NUTProtocol
	NUTTelemetry
	HealthBind
	DiscoveryBind
)

var names = [...]string{
	"internal_error", "configuration_invalid", "state_read", "state_invalid",
	"state_permissions", "state_write", "identity_mismatch", "controller_dns",
	"controller_route", "controller_transport", "controller_timeout",
	"controller_http", "controller_protocol", "controller_replay", "nut_dns",
	"nut_connect", "nut_timeout", "nut_auth", "nut_unknown_ups", "nut_unavailable",
	"nut_protocol", "nut_telemetry", "health_bind", "discovery_bind",
}

func (c Code) String() string {
	if int(c) >= len(names) {
		return names[Internal]
	}
	return names[c]
}

type failure struct {
	code  Code
	cause error
}

func (e *failure) Error() string    { return e.code.String() }
func (e *failure) GoString() string { return e.Error() }
func (e *failure) Unwrap() error    { return e.cause }

func Wrap(code Code, err error) error {
	if err == nil {
		return nil
	}
	return &failure{code: code, cause: err}
}

// Fallback preserves an existing classification while keeping outer text inert.
func Fallback(code Code, err error) error {
	if err == nil {
		return nil
	}
	var known *failure
	if errors.As(err, &known) {
		code = known.code
	}
	return Wrap(code, err)
}

// Reason never derives a label from an error message or a server response.
func Reason(err error, fallback Code) string {
	var known *failure
	if errors.As(err, &known) {
		return known.code.String()
	}
	return fallback.String()
}

// Network classifies standard-library error types without emitting addresses.
func Network(err error, dns, timeout, fallback Code) error {
	var dnsError *net.DNSError
	var networkError net.Error
	switch {
	case errors.As(err, &dnsError):
		return Wrap(dns, err)
	case errors.As(err, &networkError) && networkError.Timeout():
		return Wrap(timeout, err)
	default:
		return Wrap(fallback, err)
	}
}
