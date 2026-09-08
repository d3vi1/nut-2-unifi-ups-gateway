package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/d3vi1/nut-2-unifi-ups-gateway/internal/netconfig"
)

func TestManagedWatcherCancelsOnWithdrawalOrGenerationChange(t *testing.T) {
	for _, change := range []string{"remove", "generation", "address", "regression", "expire"} {
		t.Run(change, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "status.json")
			s := netconfig.Status{Generation: strings.Repeat("a", 32), Sequence: 10, Address: "192.0.2.30", Prefix: 24, Router: "192.0.2.1", ValidUntil: time.Now().Add(2 * time.Second)}
			initial := s
			switch change {
			case "generation":
				s.Generation = strings.Repeat("b", 32)
			case "address":
				s.Address = "192.0.2.31"
			case "regression":
				s.Sequence = 9
			case "expire":
				s.ValidUntil = time.Now().Add(-time.Second)
			}
			if change != "remove" {
				b, _ := json.Marshal(s)
				if err := os.WriteFile(p, b, 0644); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan struct{})
			go func() { defer close(done); watchNetwork(ctx, cancel, p, initial) }()
			select {
			case <-done:
				if ctx.Err() == nil {
					t.Fatal("watcher did not cancel gateway")
				}
			case <-time.After(time.Second):
				t.Fatal("watcher ignored invalidated status")
			}
		})
	}
}
