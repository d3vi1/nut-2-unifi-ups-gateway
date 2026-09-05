## Summary

## Evidence classification

- [ ] PROVEN
- [ ] OBSERVED
- [ ] CANDIDATE
- [ ] UNKNOWN made explicit
- [ ] BLOCKED_EXTERNAL made explicit

## Safety

- [ ] The runtime still has no NUT power-write path.
- [ ] No NUT power-write method or controller execution path was added.
- [ ] No secrets, full identities, firmware, or packet captures are included.

## Verification

- [ ] `gofmt -w .`
- [ ] `go test -race ./...`
- [ ] `go vet ./...`
- [ ] Four Linux target builds
