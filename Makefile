.PHONY: all build test check cross clean

all: check

build:
	CGO_ENABLED=0 go build -trimpath -buildvcs=false -o bin/nut-2-unifi-ups-gateway ./cmd/nut-2-unifi-ups-gateway

test:
	go test -race ./...

check:
	gofmt -w .
	go test -race ./...
	go vet ./...
	go test ./... -run TestCrossCompile

cross:
	go test ./internal/buildtest -run TestCrossCompile -count=1

clean:
	rm -rf bin dist coverage.out
