package buildtest

import (
	"bufio"
	"os"
	"path/filepath"
	"testing"
)

const pinnedDockerfileFrontend = "# syntax=docker/dockerfile:1.12.1@sha256:93bfd3b68c109427185cd78b4779fc82b484b0b7618e36d0f104d4d801e66d25"

func TestDockerfileFrontendIsPinned(t *testing.T) {
	dockerfile := filepath.Clean(filepath.Join("..", "..", "Dockerfile"))
	file, err := os.Open(dockerfile)
	if err != nil {
		t.Fatalf("open %s: %v", dockerfile, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			t.Fatalf("read first line of %s: %v", dockerfile, err)
		}
		t.Fatalf("%s is empty", dockerfile)
	}
	if got := scanner.Text(); got != pinnedDockerfileFrontend {
		t.Fatalf("Dockerfile frontend is not the reviewed immutable reference:\n got: %q\nwant: %q", got, pinnedDockerfileFrontend)
	}
}
