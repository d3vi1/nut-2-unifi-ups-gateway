# Contributing

Thank you for helping make NUT 2 UniFi UPS Gateway work with more UPS drivers,
CPU architectures, and UniFi Network releases. Small fixes, tests,
documentation improvements, and carefully redacted interoperability reports are
all welcome.

## Before opening an issue

1. Search existing issues and test the digest published by the latest GitHub
   Release.
2. Record the gateway version or image digest, CPU architecture, NUT version
   and driver, and UniFi Network version.
3. Reduce the problem to the smallest reproducible example.
4. Remove credentials, auth keys, private IPs, MAC addresses, serials,
   controller responses, and site/device names.
5. Never attach proprietary firmware, controller binaries, database exports,
   or packet captures.

Use the bug-report template for ordinary defects. Security problems must follow
[SECURITY.md](SECURITY.md) and must not be disclosed in a public issue.

Useful contributions include:

- fake-server tests for another standards-compliant NUT variable set;
- redacted outlet-topology cases covering groups, USB outlets, or per-outlet
  meters;
- reproduction of adoption or pairing behavior on another Network release;
- non-root container portability fixes for a supported architecture;
- clearer installation, troubleshooting, or safety documentation.

Do not post an unfiltered `upsc` dump: it may contain a serial number or other
device identity. Reduce it to the relevant variable names and anonymous sample
values.

## Development setup

Install Go 1.26 or newer as declared in [go.mod](go.mod). CI and release builds
currently use Go 1.27.1. Then clone your fork and create a focused branch:

```bash
git clone https://github.com/YOUR-ACCOUNT/nut-2-unifi-ups-gateway.git
cd nut-2-unifi-ups-gateway
git switch -c fix/short-description
```

The runtime intentionally uses only the Go standard library. Do not add a
runtime dependency, shell, package manager, or privileged container requirement
without a clear design and security justification.

## Make a change

1. Add or update a test that demonstrates the expected behavior.
2. Keep protocol parsing bounded and missing or malformed telemetry explicit.
3. Preserve the read-only boundary: no NUT command method and no
   controller-to-power execution path.
4. Update user documentation and the changelog when behavior changes.
5. Run the complete local gate:

```bash
make check
```

That command formats the Go source, runs tests with the race detector, runs
`go vet`, and verifies all four release targets:

- `linux/amd64`
- `linux/arm64`
- `linux/arm/v7`
- `linux/386`

Container or workflow changes must also build the non-root `scratch` image for
all four targets.

Toolchain and publishing changes must also follow the
[maintainer safeguards](docs/releasing.md#pinned-toolchains).

## Classify evidence

Use the repository vocabulary precisely:

- `PROVEN`: observed in the exact firmware/controller build or an executed
  test.
- `OBSERVED`: visible runtime or UI state without proof of the private
  mechanism that produced it.
- `CANDIDATE`: plausible compatibility behavior awaiting target acceptance.
- `UNKNOWN`: unresolved and not safe to advertise as supported.
- `BLOCKED_EXTERNAL`: requires unavailable hardware, credentials, or
  controller state.

Include enough non-sensitive provenance for another contributor to reproduce
the result. A passing unit test does not by itself prove live controller,
driver, pairing, or shutdown behavior.

## Open a pull request

- Keep the change focused and explain both the user-visible result and safety
  impact.
- Complete every applicable item in the pull-request template.
- Link the issue or evidence that motivated the change.
- Include the exact commands you ran and their result.
- Call out anything that remains `CANDIDATE`, `UNKNOWN`, or
  `BLOCKED_EXTERNAL`.

Every commit must carry a
[Developer Certificate of Origin](https://developercertificate.org/) sign-off.
The easiest method is:

```bash
git commit -s
```

The resulting commit message must contain:

```text
Signed-off-by: Your Name <you@example.com>
```

By contributing, you certify the DCO statement and license the contribution
under [GPL-2.0-only](LICENSE).
