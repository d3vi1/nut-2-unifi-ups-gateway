// Package nut implements the small, read-mostly subset of the Network UPS
// Tools client protocol used by the gateway.
//
// Every poll uses a fresh bounded connection. This package intentionally has
// no write-command API: gateway v1 cannot issue an upstream power operation.
package nut

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/d3vi1/nut-2-unifi-ups-gateway/internal/diagnostic"
)

const (
	defaultTimeout       = 5 * time.Second
	defaultMaxLineBytes  = 64 * 1024
	defaultMaxListItems  = 4096
	defaultMaxTotalBytes = 4 << 20
)

// Config defines a NUT connection and its local safety boundary.
type Config struct {
	Address       string
	UPSName       string
	Username      string
	Password      string
	Timeout       time.Duration
	MaxLineBytes  int
	MaxListItems  int
	MaxTotalBytes int
}

// Snapshot is one bounded observation of an upstream UPS. Variables are copied
// into an immutable-by-convention map owned by the caller.
type Snapshot struct {
	UPSName     string
	Variables   map[string]string
	CollectedAt time.Time
}

// ServerError represents a protocol-level ERR response. Only the bounded error
// code is retained; arbitrary server response text is never propagated.
type ServerError struct {
	Code string
}

func (e *ServerError) Error() string { return "nut server error: " + e.Code }

// Client is safe for concurrent use. It does not keep credentials or protocol
// connections outside the immutable configuration supplied to New.
type Client struct {
	config Config
	dialer net.Dialer
	now    func() time.Time
}

// New validates config and constructs a client. Username and password must be
// provided together. Passwords may contain spaces but never line breaks.
func New(config Config) (*Client, error) {
	if config.Address == "" {
		return nil, errors.New("nut address cannot be empty")
	}
	if _, _, err := net.SplitHostPort(config.Address); err != nil {
		return nil, fmt.Errorf("invalid nut address: %w", err)
	}
	if !safeToken(config.UPSName) {
		return nil, errors.New("invalid nut UPS name")
	}
	if (config.Username == "") != (config.Password == "") {
		return nil, errors.New("nut username and password must be supplied together")
	}
	if config.Username != "" {
		if err := validCredential(config.Username); err != nil {
			return nil, errors.New("invalid nut username")
		}
		if err := validCredential(config.Password); err != nil {
			return nil, errors.New("invalid nut password")
		}
	}
	if config.Timeout == 0 {
		config.Timeout = defaultTimeout
	}
	if config.Timeout < 0 || config.Timeout > 10*time.Minute {
		return nil, errors.New("nut timeout must be positive and at most 10 minutes")
	}
	if config.MaxLineBytes == 0 {
		config.MaxLineBytes = defaultMaxLineBytes
	}
	if config.MaxLineBytes < 256 || config.MaxLineBytes > 1024*1024 {
		return nil, errors.New("nut maximum line size must be between 256 bytes and 1 MiB")
	}
	if config.MaxListItems == 0 {
		config.MaxListItems = defaultMaxListItems
	}
	if config.MaxListItems < 1 || config.MaxListItems > 65536 {
		return nil, errors.New("nut maximum list size must be between 1 and 65536")
	}
	if config.MaxTotalBytes == 0 {
		config.MaxTotalBytes = defaultMaxTotalBytes
	}
	if config.MaxTotalBytes < 256 || config.MaxTotalBytes > 64<<20 {
		return nil, errors.New("nut maximum variable data size must be between 256 bytes and 64 MiB")
	}

	return &Client{
		config: config,
		dialer: net.Dialer{Timeout: config.Timeout},
		now:    time.Now,
	}, nil
}

// Poll performs the read-only LIST VAR exchange and returns one complete
// snapshot. It never requests or executes the server's instant commands.
func (c *Client) Poll(ctx context.Context) (Snapshot, error) {
	protocol, err := c.connect(ctx)
	if err != nil {
		return Snapshot{}, err
	}
	defer protocol.close()
	if err := c.authenticate(protocol); err != nil {
		return Snapshot{}, classifyPollError(err, diagnostic.NUTAuth)
	}
	variables, err := c.listVariables(protocol)
	if err != nil {
		return Snapshot{}, classifyPollError(err, diagnostic.NUTProtocol)
	}
	return Snapshot{
		UPSName:     c.config.UPSName,
		Variables:   variables,
		CollectedAt: c.now().UTC(),
	}, nil
}

func classifyPollError(err error, fallback diagnostic.Code) error {
	var server *ServerError
	if errors.As(err, &server) {
		switch server.Code {
		case "ACCESS-DENIED", "INVALID-PASSWORD", "PASSWORD-REQUIRED", "USERNAME-REQUIRED":
			return diagnostic.Wrap(diagnostic.NUTAuth, err)
		case "UNKNOWN-UPS":
			return diagnostic.Wrap(diagnostic.NUTUnknownUPS, err)
		case "DATA-STALE", "DRIVER-NOT-CONNECTED":
			return diagnostic.Wrap(diagnostic.NUTUnavailable, err)
		}
	}
	return diagnostic.Network(err, diagnostic.NUTDNS, diagnostic.NUTTimeout, fallback)
}

func (c *Client) connect(ctx context.Context) (*wire, error) {
	conn, err := c.dialer.DialContext(ctx, "tcp", c.config.Address)
	if err != nil {
		return nil, diagnostic.Network(err, diagnostic.NUTDNS, diagnostic.NUTTimeout, diagnostic.NUTConnect)
	}
	deadline := c.now().Add(c.config.Timeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := conn.SetDeadline(deadline); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("set nut connection deadline: %w", err)
	}
	protocol := newWire(conn, c.config.MaxLineBytes)
	protocol.stop = context.AfterFunc(ctx, func() {
		_ = conn.SetDeadline(time.Now())
	})
	return protocol, nil
}

func (c *Client) authenticate(protocol *wire) error {
	if c.config.Username == "" {
		return nil
	}
	if err := protocol.write("USERNAME "+formatArgument(c.config.Username), "username"); err != nil {
		return err
	}
	if err := protocol.expectOK("username"); err != nil {
		return err
	}
	if err := protocol.write("PASSWORD "+formatArgument(c.config.Password), "password"); err != nil {
		return err
	}
	if err := protocol.expectOK("password"); err != nil {
		return err
	}
	return nil
}

func (c *Client) listVariables(protocol *wire) (map[string]string, error) {
	if err := protocol.write("LIST VAR "+c.config.UPSName, "list variables"); err != nil {
		return nil, err
	}
	begin := []string{"BEGIN", "LIST", "VAR", c.config.UPSName}
	if err := protocol.expect(begin, "list variables"); err != nil {
		return nil, err
	}
	variables := make(map[string]string)
	totalBytes := 0
	for count := 0; ; {
		tokens, rawBytes, err := protocol.read("list variables")
		if err != nil {
			return nil, err
		}
		if tokensEqual(tokens, []string{"END", "LIST", "VAR", c.config.UPSName}) {
			return variables, nil
		}
		if len(tokens) != 4 || tokens[0] != "VAR" || tokens[1] != c.config.UPSName || !safeToken(tokens[2]) {
			return nil, errors.New("malformed nut variable list entry")
		}
		if count >= c.config.MaxListItems {
			return nil, errors.New("nut variable list exceeds configured item limit")
		}
		if _, duplicate := variables[tokens[2]]; duplicate {
			return nil, errors.New("duplicate nut variable in list")
		}
		if rawBytes > c.config.MaxTotalBytes-totalBytes {
			return nil, errors.New("nut variable list exceeds configured byte limit")
		}
		totalBytes += rawBytes
		// Unquoted parser tokens are substrings of the complete wire line. Clone
		// retained fields so a short key cannot pin a padded maximum-size line.
		variables[strings.Clone(tokens[2])] = strings.Clone(tokens[3])
		count++
	}
}

type wire struct {
	conn   net.Conn
	reader *bufio.Scanner
	writer *bufio.Writer
	stop   func() bool
}

func newWire(conn net.Conn, maxLineBytes int) *wire {
	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 4096), maxLineBytes)
	return &wire{conn: conn, reader: scanner, writer: bufio.NewWriterSize(conn, 4096)}
}

func (w *wire) close() {
	if w.stop != nil {
		w.stop()
	}
	_ = w.conn.Close()
}

func (w *wire) write(line, operation string) error {
	if strings.ContainsAny(line, "\r\n") {
		return fmt.Errorf("%s: request contains a line break", operation)
	}
	if _, err := w.writer.WriteString(line + "\n"); err != nil {
		return fmt.Errorf("%s: write request: %w", operation, err)
	}
	if err := w.writer.Flush(); err != nil {
		return fmt.Errorf("%s: flush request: %w", operation, err)
	}
	return nil
}

func (w *wire) read(operation string) ([]string, int, error) {
	if !w.reader.Scan() {
		if err := w.reader.Err(); err != nil {
			return nil, 0, fmt.Errorf("%s: read response: %w", operation, err)
		}
		return nil, 0, fmt.Errorf("%s: read response: %w", operation, io.ErrUnexpectedEOF)
	}
	raw := strings.TrimSuffix(w.reader.Text(), "\r")
	rawBytes := len(raw)
	tokens, err := parseLine(raw)
	if err != nil {
		return nil, rawBytes, fmt.Errorf("%s: malformed response", operation)
	}
	if len(tokens) >= 1 && tokens[0] == "ERR" {
		code := "SERVER-ERROR"
		if len(tokens) >= 2 && safeErrorCode(tokens[1]) {
			code = tokens[1]
		}
		return nil, rawBytes, &ServerError{Code: code}
	}
	return tokens, rawBytes, nil
}

func (w *wire) expect(expected []string, operation string) error {
	tokens, _, err := w.read(operation)
	if err != nil {
		return err
	}
	if !tokensEqual(tokens, expected) {
		return fmt.Errorf("%s: unexpected nut response", operation)
	}
	return nil
}

func (w *wire) expectOK(operation string) error {
	return w.expect([]string{"OK"}, operation)
}

func tokensEqual(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func validCredential(value string) error {
	if value == "" || len(value) > 4096 || !utf8.ValidString(value) {
		return errors.New("invalid credential")
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return errors.New("invalid credential")
		}
	}
	return nil
}

func formatArgument(value string) string {
	if !strings.ContainsAny(value, " \t\"\\") {
		return value
	}
	var encoded strings.Builder
	encoded.Grow(len(value) + 2)
	encoded.WriteByte('"')
	for _, character := range value {
		if character == '"' || character == '\\' {
			encoded.WriteByte('\\')
		}
		encoded.WriteRune(character)
	}
	encoded.WriteByte('"')
	return encoded.String()
}

func safeToken(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-' {
			continue
		}
		return false
	}
	return true
}

func safeErrorCode(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for _, r := range value {
		if (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			continue
		}
		return false
	}
	return true
}
