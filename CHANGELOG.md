# Changelog

All notable changes are documented here. The project follows
[Semantic Versioning](https://semver.org/) after its first tagged release.

## Unreleased

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
