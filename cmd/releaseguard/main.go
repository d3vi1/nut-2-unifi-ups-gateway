package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/d3vi1/nut-2-unifi-ups-gateway/internal/releaseguard"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Getenv, os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, getenv func(string) string, stdout, stderr io.Writer) int {
	if len(args) != 1 {
		printUsage(stderr)
		return 2
	}
	if args[0] == "verify-index" {
		if err := releaseguard.VerifyIndex(getenv); err != nil {
			fmt.Fprintln(stderr, "releaseguard:", err)
			return 1
		}
		fmt.Fprintln(stdout, "releaseguard: verify-index verified")
		return 0
	}
	release, err := releaseguard.LoadContext(getenv)
	if err != nil {
		fmt.Fprintln(stderr, "releaseguard: invalid environment:", err)
		return 2
	}
	guard := releaseguard.New()
	switch args[0] {
	case "trust":
		err = guard.Trust(ctx, release)
	case "reserve":
		err = guard.Reserve(ctx, release)
	case "verify-reserved":
		err = guard.VerifyReserved(ctx, release, getenv)
	case "verify-image-source":
		err = guard.VerifyImageSource(ctx, release)
	case "verify-attestation":
		err = guard.VerifyAttestation(ctx, release, getenv)
	case "bind":
		err = guard.Bind(ctx, release, getenv)
	case "verify-bound":
		err = guard.VerifyBound(ctx, release, getenv)
	case "upload-assets":
		err = guard.UploadAssets(ctx, release, getenv)
	case "publish":
		err = guard.Publish(ctx, release, getenv)
	default:
		printUsage(stderr)
		return 2
	}
	if err != nil {
		fmt.Fprintln(stderr, "releaseguard:", err)
		return 1
	}
	fmt.Fprintln(stdout, "releaseguard:", args[0], "verified")
	return 0
}

func printUsage(writer io.Writer) {
	fmt.Fprintln(writer, "usage: releaseguard <trust|reserve|verify-reserved|verify-image-source|verify-index|verify-attestation|bind|verify-bound|upload-assets|publish>")
}
