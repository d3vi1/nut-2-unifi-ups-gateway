# NUT 2 UniFi UPS Gateway contributor instructions

## Mission

Bridge a standards-compliant NUT upstream to a conservatively emulated UniFi
UPS, with `USWDA26` as the default controller-recognized carrier and NUT as the
source of observed outlet topology. Preserve the boundary between observed
upstream telemetry, reverse-engineered UniFi compatibility, and operations that
can switch power.

## Non-negotiable invariants

- Gateway v1 is read-only telemetry. Do not add a NUT command method or any
  controller-to-power execution path without a new evidence review and major
  safety design.
- Do not advertise writable smart-power features that v1 cannot execute.
  Downstream NUT information access is default-off and may describe only an
  independently verified, credential-free service at the emulated device IP;
  never derive it merely from the upstream client address.
- Do not infer relay, automatic-relay, or metering capabilities from outlet
  count, group membership, or UPS-wide measurements. Relay capability requires
  an affirmative NUT switchability fact on the outlet, its exactly matched
  group, or the global outlet collection; metering requires a direct outlet
  current, real-power, or apparent-power variable.
- Never log NUT passwords, UniFi adoption keys, complete MAC addresses, serials,
  controller replies, or packet captures.
- Do not mutate host networking, firewall rules, controller configuration, or
  unrelated Container Manager projects.
- Reject ambiguous, stale, malformed, or incomplete upstream state. Never
  invent healthy battery data to keep the emulated device online.
- Preserve electrical units: real power and nominal real power are W; apparent
  power is VA. Do not infer missing W or amperage precision from load, model,
  voltage, or current.
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
- `OBSERVED`: visible runtime or UI state without proof of the private protocol
  mechanism that produced it.
- `CANDIDATE`: plausible compatibility behavior not yet accepted by the target
  controller.
- `UNKNOWN`: unresolved and not safe to expose as a supported capability.
- `BLOCKED_EXTERNAL`: requires credentials, controller state, or hardware not
  present in the current test.
