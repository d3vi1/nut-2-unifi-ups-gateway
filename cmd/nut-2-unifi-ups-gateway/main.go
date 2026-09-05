package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/d3vi1/nut-2-unifi-ups-gateway/internal/config"
	"github.com/d3vi1/nut-2-unifi-ups-gateway/internal/diagnostic"
	"github.com/d3vi1/nut-2-unifi-ups-gateway/internal/gateway"
)

var (
	version   = "dev"
	revision  = "unknown"
	buildDate = "unknown"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) > 1 {
		fmt.Fprintln(stderr, "usage: nut-2-unifi-ups-gateway [healthcheck|version]")
		return 2
	}
	if len(args) == 1 {
		switch args[0] {
		case "healthcheck":
			if err := runHealthcheck(ctx, os.Getenv("N2U_HEALTH_ADDRESS")); err != nil {
				fmt.Fprintln(stderr, "healthcheck failed")
				return 1
			}
			return 0
		case "version", "--version":
			fmt.Fprintf(stdout, "nut-2-unifi-ups-gateway %s (revision %s, built %s)\n", version, revision, buildDate)
			return 0
		default:
			fmt.Fprintln(stderr, "usage: nut-2-unifi-ups-gateway [healthcheck|version]")
			return 2
		}
	}

	configuration, err := config.Load()
	if err != nil {
		fmt.Fprintln(stderr, "configuration is invalid; reason="+diagnostic.Reason(err, diagnostic.Configuration))
		return 2
	}
	level, err := parseLogLevel(configuration.LogLevel)
	if err != nil {
		fmt.Fprintln(stderr, "configuration is invalid: N2U_LOG_LEVEL must be debug, info, warn, or error")
		return 2
	}
	logger := slog.New(slog.NewJSONHandler(stderr, &slog.HandlerOptions{Level: level}))
	service, err := gateway.New(ctx, configuration, gateway.Options{Logger: logger})
	if err != nil {
		logger.Error("gateway initialization failed", "reason", diagnostic.Reason(err, diagnostic.Internal))
		return 1
	}
	logger.Info("gateway started", "version", version, "model", configuration.UniFi.Model)
	if err := service.Run(ctx); err != nil {
		logger.Error("gateway stopped unexpectedly", "reason", diagnostic.Reason(err, diagnostic.Internal))
		return 1
	}
	logger.Info("gateway stopped")
	return 0
}

func parseLogLevel(raw string) (slog.Level, error) {
	switch strings.ToLower(raw) {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, errors.New("invalid log level")
	}
}

func runHealthcheck(parent context.Context, address string) error {
	if address == "" {
		address = "127.0.0.1:9199"
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return errors.New("invalid health address")
	}
	switch host {
	case "", "0.0.0.0":
		host = "127.0.0.1"
	case "::", "[::]":
		host = "::1"
	}
	target := (&url.URL{Scheme: "http", Host: net.JoinHostPort(host, port), Path: "/healthz"}).String()
	ctx, cancel := context.WithTimeout(parent, 2*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return errors.New("create health request")
	}
	client := &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			Proxy:                  nil,
			DialContext:            (&net.Dialer{Timeout: time.Second}).DialContext,
			DisableKeepAlives:      true,
			DisableCompression:     true,
			MaxResponseHeaderBytes: 8 << 10,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("health redirect rejected")
		},
	}
	response, err := client.Do(request)
	if err != nil {
		return errors.New("health request failed")
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1024))
	if response.StatusCode != http.StatusOK {
		return errors.New("health endpoint is not OK")
	}
	return nil
}
