//go:build linux

// n2u-netagent is an optional, separately privileged container network owner.
// Its environment and mounts must not contain NUT credentials or adoption state.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/d3vi1/nut-2-unifi-ups-gateway/internal/netagent"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if len(os.Args) != 1 {
		fmt.Fprintln(os.Stderr, "network agent accepts no arguments")
		os.Exit(2)
	}
	mode := os.Getenv("N2U_NET_MODE")
	if mode == "" {
		mode = "dhcp"
	}
	err := netagent.Run(ctx, netagent.Config{MAC: os.Getenv("N2U_NET_MAC"), Mode: mode, StaticCIDR: os.Getenv("N2U_NET_STATIC_CIDR"), Router: os.Getenv("N2U_NET_ROUTER")})
	if err != nil {
		fmt.Fprintln(os.Stderr, "network agent stopped; network_configuration_failed")
		os.Exit(1)
	}
}
