## Summary

## Evidence classification

- [ ] PROVEN
- [ ] CANDIDATE
- [ ] UNKNOWN made explicit
- [ ] BLOCKED_EXTERNAL made explicit

## Safety

- [ ] Read-only remains the default.
- [ ] No NUT power-write method or controller execution path was added.
- [ ] No secrets, full identities, firmware, or packet captures are included.

## Verification

- [ ] `gofmt -w .`
- [ ] `go test -race ./...`
- [ ] `go vet ./...`
- [ ] Four Linux target builds
