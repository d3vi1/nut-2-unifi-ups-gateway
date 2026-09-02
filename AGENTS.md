# NUT 2 UniFi UPS Gateway contributor instructions

## Mission

Bridge a standards-compliant NUT upstream to a conservatively emulated UniFi
UPS, with `USWDA26` as the default exact 4+4 profile. Preserve the boundary between observed upstream telemetry,
reverse-engineered UniFi compatibility, and operations that can switch power.

## Non-negotiable invariants

- Gateway v1 is read-only telemetry. Do not add a NUT command method or any
  controller-to-power execution path without a new evidence review and major
  safety design.
- Never log NUT passwords, UniFi adoption keys, complete MAC addresses, serials,
  controller replies, or packet captures.
- Do not mutate host networking, firewall rules, controller configuration, or
  unrelated Container Manager projects.
- Reject ambiguous, stale, malformed, or incomplete upstream state. Never
  invent healthy battery data to keep the emulated device online.
- Keep the runtime dependency-free apart from the Go standard library. The
  final container must remain a static, non-root `scratch` image.
- Keep site addresses, SSH targets, credentials, and deployment notes in the
  ignored `AGENTS-local.md`, never in tracked files.

## Required checks

Run before every commit:

```text
gofmt -w .
go test -race ./...
go vet ./...
go test ./... -run TestCrossCompile
```

Container and workflow changes also require the repository policy checks and
all four target builds: `linux/amd64`, `linux/arm64`, `linux/arm/v7`, and
`linux/386`.

## Evidence vocabulary

- `PROVEN`: observed in the exact UPS firmware, controller, or an executed test.
- `CANDIDATE`: plausible compatibility behavior not yet accepted by the target
  controller.
- `UNKNOWN`: unresolved and not safe to expose as a supported capability.
- `BLOCKED_EXTERNAL`: requires credentials, controller state, or hardware not
  present in the current test.
