# Changelog

All notable changes are documented here. The project follows
[Semantic Versioning](https://semver.org/) after its first tagged release.

## 0.9.0 - 2026-09-03

### Added

- Experimental projection of NUT-observed outlet counts and relay groups,
  including deterministic remapping of opaque `outlet.N.groupid` values and
  singleton groups when the native group identifier is absent.
- Conservative AC/USB outlet classification and evidence-bound `HAS_RELAY`
  mapping from outlet, matched-group, or global switchability plus
  `POWER_METER` mapping from direct outlet-scoped NUT facts, without treating
  voltage or power factor alone as proof of a power meter.
- Unit-preserving UPS-wide mapping for `ups.realpower.nominal` and preservation
  of standard `ups.beeper.status` values without adding a buzzer write path.
- An experimental, default-off, credential-free advertisement for a separately
  verified NUT service at the emulated device IP.

### Changed

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
- Tagged releases now publish an attested multi-platform digest and a
  checksum-verified Synology bundle whose generated `.env` uses that exact OCI
  digest. Compose fails closed if `N2U_IMAGE` is absent instead of pulling a
  mutable fallback tag.

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
