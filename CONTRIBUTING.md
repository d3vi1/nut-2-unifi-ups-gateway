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
- rootless/container portability fixes for a supported architecture;
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

Container or workflow changes must also build the rootless `scratch` image for
all four targets.

The Buildx version and binary checksum and the BuildKit image digest in
`.github/actions/setup-pinned-buildx/action.yml` form one reviewed toolchain
unit. Update and verify all three together, then update the exact regression
constants in `internal/buildtest/buildx_test.go`; never substitute a moving tag
or a checksum downloaded at workflow runtime. The release SBOM generator is a
fourth content-addressed toolchain input enforced in the same test. Every
`push: true` build must remain explicitly cache-cold and must not import or
export a remote build cache; CI-only non-publishing builds may use their
separate cache.

The release attestation verifier is a separate pinned toolchain: its GitHub CLI
version/archive checksum and the Sigstore Public Good trusted-root source,
raw checksum, and compact-JSONL checksum must change together with their
regression constants. Never fall back to the runner's unpinned `gh`, fetch live
TUF metadata, or expose a GitHub token to the offline verification step.

## Maintainer release gate

Do not create the version tag or a GitHub Release by hand. Before dispatching
the release controller:

1. Make the repository and its GHCR package public.
2. Enable immutable GitHub Releases.
3. Protect `main`, then create one active tag ruleset named
   `N2U release tags`, targeting exactly `refs/tags/v*`, with only update and
   deletion restricted and an empty bypass list. Creation stays available so
   the workflow can use GitHub's atomic create-ref operation; once created, a
   version tag cannot be moved or removed. Emergency recovery requires an
   explicit, audited ruleset change rather than a standing bypass.
4. Require full commit-SHA pinning for Actions and keep the default
   `GITHUB_TOKEN` permission read-only.
5. Store a repository-scoped, read-only fine-grained token as
   `N2U_RELEASE_POLICY_TOKEN`. It needs Administration read and Contents read
   access so the controller can verify policy and inspect its private draft;
   it must have no write permission.
6. Archive and remove every still-rerunnable historical tagged workflow that
   had package-write authority but predates this controller.
7. Confirm the reviewed source is the live `main` tip and that the requested
   version has no tag, draft, or published Release. Also confirm that no
   unexpected collaborator, installed GitHub App, writable deploy key,
   workflow, or package ACL has release authority.

Run **Publish container** manually from `main` and provide the exact SemVer tag,
such as `v0.9.0`. The controller first reserves the version with a protected
tag, creates its owned draft, publishes a uniquely named permanent OCI
retention anchor, binds its digest and attestation to the numeric reservation,
uploads an exact asset set, and only then publishes the immutable Release. It
never publishes a `:0.9.0` image alias.

Never rerun all, failed, or individual jobs from a release run. Every release
job requires attempt one and matching upstream outputs. If anything fails after
reservation, inspect the monotonic external state and normally use a new
version; cleanup or manual continuation needs its own reviewed procedure. After
success, verify that the Git tag, source SHA, image digest, attestation,
retention anchor, release marker, bundle `.env`, assets, and checksums agree.

Keep `main` and all manual GitHub Release and GHCR writes frozen while the
controller is running. The controller requires the source to remain the live
`main` tip at every state transition. GitHub documents no conditional update
for the final draft-to-publish PATCH, so the controller cannot make that
boundary atomic against another authorized writer. It serializes its own
release runs, overwrites every expected mutable field during publication, and
validates the exact response and immutable readback; an independently
authorized concurrent writer remains part of the release trust boundary.

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
