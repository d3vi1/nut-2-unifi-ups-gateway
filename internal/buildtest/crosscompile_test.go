package buildtest

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

func TestCrossCompile(t *testing.T) {
	if testing.Short() {
		t.Skip("cross compilation skipped in short mode")
	}
	root := filepath.Clean(filepath.Join("..", ".."))
	targets := []struct {
		name, arch, arm string
	}{
		{name: "linux-amd64", arch: "amd64"},
		{name: "linux-arm64", arch: "arm64"},
		{name: "linux-armv7", arch: "arm", arm: "7"},
		{name: "linux-386", arch: "386"},
	}
	for _, target := range targets {
		t.Run(target.name, func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "gateway")
			cmd := exec.Command("go", "build", "-trimpath", "-buildvcs=false", "-o", out, "./cmd/nut-2-unifi-ups-gateway")
			cmd.Dir = root
			cmd.Env = append(filteredEnv(os.Environ(), "GOOS", "GOARCH", "GOARM", "CGO_ENABLED"),
				"GOOS=linux", "GOARCH="+target.arch, "GOARM="+target.arm, "CGO_ENABLED=0")
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("cross build from %s on %s/%s: %v\n%s", root, runtime.GOOS, runtime.GOARCH, err, output)
			}
		})
	}
}

func filteredEnv(env []string, names ...string) []string {
	blocked := make(map[string]bool, len(names))
	for _, name := range names {
		blocked[name] = true
	}
	out := env[:0]
	for _, entry := range env {
		name := entry
		for i, r := range entry {
			if r == '=' {
				name = entry[:i]
				break
			}
		}
		if !blocked[name] {
			out = append(out, entry)
		}
	}
	return out
}
