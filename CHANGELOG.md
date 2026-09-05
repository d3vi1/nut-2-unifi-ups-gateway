# Changelog

All notable changes are documented here. The project follows
[Semantic Versioning](https://semver.org/) after its first tagged release.

## 0.9.0 - 2026-09-05

### Added

- Fixed, identity-free diagnostic reason codes for NUT, controller, startup and
  state failures. Underlying errors remain available to internal typed checks,
  but runtime logs never print their arbitrary text.
- A default-off, persistent mirror of the firmware version selected by an
  authenticated HTTP/GCM controller. Lower channel targets are accepted too;
  only reported version text changes. No firmware is fetched or installed, and
  source profiles, capabilities, adoption and power control remain unchanged.
  Manual target acceptance and configuration convergence were **OBSERVED** on
  Network 10.6.102; live target restart and downgrade remain **CANDIDATE**.
- A separate default-off multi-field configuration receipt policy, with memory
  and persistent modes. It handles the observed management envelope without
  granting command authority. A private, bounded receipt survives restart while
  keeping adoption state v1 unchanged. Network 10.6.102 marker convergence,
  memory-mode Online/pairings and persistent storage/reload were **OBSERVED**
  separately; this is not universal UI/rename/restart acceptance.
- Identity-free receipt-status and ignored-setting diagnostics, atomic-storage
  fault tests, and bounded transition-nonce replay protection across restart.

- Experimental projection of NUT-observed outlet counts and relay groups,
  including deterministic remapping of opaque `outlet.N.groupid` values and
  singleton groups when the native group identifier is absent.
- Conservative AC/USB outlet classification and `POWER_METER` mapping from
  direct outlet-scoped NUT facts, without treating voltage or power factor
  alone as proof of a power meter. NUT switchability is retained as descriptive
  topology but does not advertise a writable `HAS_RELAY` bit.
- Fail-closed W/VA alias resolution, same-snapshot power-factor derivation, and
  modern `battery.charger.status` reconciliation with legacy status tokens.
- A bounded partial native group table for `outlet.group.*` observations that
  have no `outlet.count`, without overlaying those groups on carrier outlets.
- Unit-preserving UPS-wide mapping and preservation of standard
  `ups.beeper.status` values without adding a buzzer write path.
- An experimental, default-off, credential-free advertisement for a separately
  verified NUT service at the emulated device IP.
- A default-off plain-HTTP GCM compatibility option that can mirror only a
  valid received `cfgversion` in memory after adoption when it is the only
  non-empty `mgmt_cfg` entry. It is intended to test whether that narrow mirror
  helps Network reconcile configuration-only changes without granting command
  authority; exact-build live efficacy remains **CANDIDATE**. Accompanying
  `system_cfg` remains observed and ignored.

### Changed

- A generic Linux Compose bundle replaces the Synology-named release bundle.
  Templates move to `deploy/compose`; the Compose project name and existing
  named state volume remain unchanged. Use a version-matched deployment set.
- A shorter, user-oriented README with a Mermaid overview, shared installation,
  troubleshooting and compatibility guides, plus separate Synology notes and
  maintainer release instructions.
- `USWDA26` and `USPDA2C` now act as controller-recognized wire carriers rather
  than templates for valid observed topology; absent NUT topology keeps only an
  AC-compatible structural fallback (`USWDA26` 4+4 or nine singleton
  `USPDA2C` rows), without invented relay, meter, auto-relay, or button bits.
- Historical Network 10.6.101 unknown-device results are distinguished from
  the gateway adoption and safe-shutdown pairing observed in the 2026-09-03 UI.
- Effective smart-power capabilities now use a fail-closed allowlist:
  safe-shutdown timing, plus NUT information access only when explicitly
  advertised. Power Cycle on AC Recovery, buzzer control, EPO, and unresolved
  high bits are not published.

### Safety

- Dynamic relay groups remain descriptive. Controller relay requests still do
  not execute NUT commands, and UPS/group electrical totals are never
  apportioned into fabricated per-outlet readings.
- Controller attempts to configure unsupported NUT-server, AC-recovery-cycle,
  buzzer, outlet-power, or EPO settings are categorized and logged without
  retaining values or issuing a NUT command.
- Authenticated GCM controller responses now use separate bounded recent and
  state-changing replay windows. State-changing nonces are persisted with the
  adoption transition so routine `noop` responses cannot evict rollback
  protection or force a state-file write on every inform.
- Controller-provided inform intervals are now observation-only; the local
  `N2U_INFORM_INTERVAL` is authoritative, so a captured cadence reply cannot
  regain an effect after restart and routine informs do not wear the state
  volume.
- After a controller key is installed, adopted replies over plain HTTP are
  acknowledgement-only by default, including authenticated GCM whose envelope
  cannot prove request freshness. State, reset, key, reboot, upgrade, and
  cadence effects require trusted HTTPS; a same-key one-way CBC-to-GCM upgrade
  remains allowed. The explicit volatile-`cfgversion` exception changes only
  the in-memory report marker: it applies no accompanying configuration and
  changes neither the state file nor persistent replay nonces.
- The identity-free health listener now has a shutdown-safe aggregate
  connection cap, disables connection reuse, and retains its time and header
  bounds.
- Tagged releases now publish an attested multi-platform digest and a
  checksum-verified Compose bundle whose generated `.env` uses that exact OCI
  digest. Compose fails closed if `N2U_IMAGE` is absent instead of pulling a
  mutable fallback tag.
- The Dockerfile frontend, Buildx client artifact, and BuildKit builder image
  are pinned to reviewed content digests or checksums so release tooling cannot
  drift behind mutable defaults.
- Publishing builds are explicitly cache-cold and the official BuildKit Syft
  SBOM generator is pinned to a reviewed version and OCI index digest.
- Image names are deliberately non-floating: `edge` belongs only to `main`.
  A release has no SemVer, `latest`, major, or minor OCI alias; its permanent
  run-scoped registry tag is only a retention anchor, while the immutable
  Release bundle uses the authoritative manifest digest.
- Fulcio certificate lifetime is evaluated at the authenticated Rekor
  integration time after the pinned GitHub verifier completes full Sigstore
  verification. A delayed verifier can no longer reject a valid historical
  signature merely because its short-lived leaf has since expired; malformed
  or out-of-lifetime log times still fail closed.
- The offline attestation verifier runs without GitHub, Actions-runtime, OIDC,
  or GHCR credentials after its pinned inputs are installed.
- The release controller runs only by explicit dispatch from the live default
  branch. It atomically reserves the version by creating its protected source
  tag, then creates an owned draft before touching GHCR. The tag created with
  the ephemeral `GITHUB_TOKEN` does not trigger historical tag-push workflows.
- Every release mutation addresses that draft by numeric ID and verifies its
  exact repository, source SHA, run ID, attempt, OCI anchor, digest,
  attestation, and asset set. Automatic reruns are rejected before mutation.
- Live release checks require a public repository and package, immutable
  Releases, SHA-pinned Actions, read-only default workflow permissions, and the
  exact active, no-bypass `N2U release tags` update/deletion ruleset plus a
  protected `main`. A checksum-pinned GitHub CLI verifies the exact local
  attestation offline against a review-pinned Sigstore root and the expected
  workflow/source identity; the local guard adds stricter provenance checks.
  The controller also validates the exact four-platform OCI index and the
  digest-pinned contents of the Compose archive before publication. Transport,
  schema, authentication, timeout, or partial-state uncertainty fails closed.
- Public protocol evidence labels site-derived compatibility observations as
  redacted and omits deployment identities and inventory. Its focused
  regression rejects dated or counted adoption inventory and any direct
  `ups.id` assignment in those redacted samples.

## 0.1.0-alpha.1 - 2026-09-02

### Added

- Read-only NUT telemetry client with no power-write API and a conservative UPS
  model.
- UniFi discovery and encrypted inform compatibility for eight-outlet
  `USWDA26` and nine-outlet `USPDA2C` profiles.
- Persistent adoption identity, rootless `scratch` container, Synology Compose
  deployment, multi-architecture GHCR workflow, SBOM, and provenance.
- Firmware-exact UPS26 profile GUID, cross-protocol opaque identities,
  anonymous-ID normalization, HTTP fingerprint, and deterministic discovery
  source binding on multi-homed hosts.
- Dedicated pending-inform observability that treats HTTP 404 as controller
  reachability without claiming adoption success.
- Live DSM/UDM validation and an explicit Network 10.6.101 unknown-device
  compatibility boundary.
