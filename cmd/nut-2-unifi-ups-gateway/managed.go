package main

import (
	"context"
	"log/slog"
	"time"

	"github.com/d3vi1/nut-2-unifi-ups-gateway/internal/config"
	"github.com/d3vi1/nut-2-unifi-ups-gateway/internal/diagnostic"
	"github.com/d3vi1/nut-2-unifi-ups-gateway/internal/gateway"
	"github.com/d3vi1/nut-2-unifi-ups-gateway/internal/netconfig"
)

// runManaged waits without advertising health or a UPS until the independently
// privileged netagent has configured the interface. A changed/lost heartbeat
// cancels all I/O, joins the old gateway, and then revalidates the local NIC and
// persisted MAC before reopening the existing adoption state.
func runManaged(ctx context.Context, c config.Config, logger *slog.Logger) int {
	logger.Info("waiting for managed network")
	for ctx.Err() == nil {
		s, err := netconfig.ReadStatus(c.Runtime.NetworkStatusFile, time.Now())
		if err != nil {
			if !pause(ctx, time.Second/10) {
				break
			}
			continue
		}
		attempt, cancel := context.WithCancel(ctx)
		done := make(chan struct{})
		go func() { defer close(done); watchNetwork(attempt, cancel, c.Runtime.NetworkStatusFile, s) }()
		current := c
		current.Device.IP = s.Address
		service, err := gateway.New(attempt, current, gateway.Options{Logger: logger})
		if err != nil {
			cancel()
			<-done
			// Identity/state errors are not masked as DHCP retries.
			logger.Error("gateway initialization failed", "reason", diagnostic.Reason(err, diagnostic.Internal))
			return 1
		}
		logger.Info("gateway started", "version", version, "network_mode", "separate", "address_source", "netagent")
		err = service.Run(attempt)
		wasCancelled := attempt.Err() != nil
		cancel()
		<-done
		if err != nil && !wasCancelled {
			logger.Error("gateway stopped unexpectedly", "reason", diagnostic.Reason(err, diagnostic.Internal))
			return 1
		}
		if ctx.Err() == nil {
			logger.Info("managed network changed or expired; gateway stopped")
			if !pause(ctx, time.Second/10) {
				break
			}
		}
	}
	return 0
}

func pause(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func watchNetwork(ctx context.Context, cancel context.CancelFunc, path string, initial netconfig.Status) {
	defer cancel()
	lastSequence := initial.Sequence
	advanced := time.Now()
	for pause(ctx, 100*time.Millisecond) {
		now := time.Now()
		s, err := netconfig.ReadStatus(path, now)
		if err != nil || !s.SameNetwork(initial) || s.Sequence < lastSequence {
			return
		}
		if s.Sequence > lastSequence {
			lastSequence = s.Sequence
			advanced = now
		}
		// Monotonic liveness bound also covers wall-clock steps and a frozen file.
		if now.Sub(advanced) > 3*time.Second {
			return
		}
	}
}
