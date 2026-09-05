package buildtest

import (
	"os/exec"
	"path/filepath"
	"testing"
)

// This helper is CI-only; Node is supplied by the hosted Actions runner.
// No JavaScript runtime or credential helper is included in the gateway image.
func TestAttestationCredentialBridge(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Fatal("Node is required to test the CI attestation credential bridge")
	}
	command := exec.Command(node, "--test", filepath.Join(".github", "scripts", "attestation-auth.test.mjs"))
	command.Dir = filepath.Join("..", "..")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("CI credential bridge tests failed: %v\n%s", err, output)
	}
}
