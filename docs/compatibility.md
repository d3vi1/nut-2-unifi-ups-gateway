# Compatibility and validation

The gateway follows standard NUT variables, not a particular NAS or UPS vendor.
A NUT driver determines which measurements and outlet details are available.
Missing values are omitted, never manufactured to make Network look complete.

## What has been observed

| Behavior | Evidence and boundary |
|---|---|
| NUT telemetry, adoption and Safe Shutdown Pairing | **OBSERVED** with the USWDA26 carrier on Network 10.6.102 / UniFi OS 5.1.31, using a Synology-hosted amd64 container |
| Multi-field configuration reconciliation | **OBSERVED** backend acceptance; an operator also observed Online and pairings after the corrected memory-mode parser |
| Configuration receipt across process restart and container recreation | **OBSERVED** private-file restoration and healthy informs; not proof of all subsequent UI operations |
| Manual reported-firmware update | **OBSERVED** Network transition from 1.6.1.413 to 1.6.4.432, matching persistent configuration receipt and no container restart |
| Reported-firmware restoration after restart; downgrade/channel reversal | **CANDIDATE** live interoperability; automated persistence and bidirectional tests pass |
| Other Network releases and the USPDA2C carrier | No general acceptance claim; older Network 10.6.101 tests reached an unknown-device 404 |
| Dynamic NUT outlet count, relay groups, USB and metering | **CANDIDATE**; automated projection coverage, not topology-capable live-source acceptance |
| Completed shutdown of paired UniFi consoles | **BLOCKED_EXTERNAL** until an operator-controlled end-to-end test |
| UPS outlet/buzzer/power commands | Intentionally unsupported; there is no NUT write API |

These are redacted interoperability observations, not endorsements or a minimum
supported-version promise. They do not include site identities or device inventory.
See [protocol evidence](protocol-evidence.md) for the detailed source boundaries.

## Platforms

The image is built for Linux amd64, arm64, arm/v7 and 386. Cross-build success
does not mean every architecture/host combination has been tested in the field.
The shared deployment targets Docker Engine with Linux host networking;
Synology is the current field-tested host.

A non-root process is not a rootless Docker engine. Docker Desktop, user-namespace
remapping, rootless engine networking, Kubernetes and non-host-network deployments
require their own validation; do not assume USB access or extra capabilities will
fix adoption. [Docker's platform limitations](https://docs.docker.com/engine/network/drivers/host/).

## Panel limitations

The default USWDA26 carrier routes the device into UniFi's UPS flow. Network's
catalog also draws surge jacks and a fixed battery/surge outlet illustration.
That illustration does not establish physical NUT topology.

Current and power depend on driver precision. Watts require actual watt values;
VA and load percentages are not relabeled as watts. Outlet groups are descriptive,
not writable controls. [Field mapping](configuration.md#outlet-topology-and-control).

## Operator-controlled checks

Before a release is accepted in a real deployment, agree a maintenance window
and record the exact gateway digest, Network version and enabled options.
The following are separate checks, not commands this document runs for you:

- Verify adoption, plausible readings, Online state and expected pairings.
- Rename and verify configuration convergence.
- Restart/recreate only the gateway with its original volume; confirm the saved
  configuration and reported firmware remain, with no new device identity.
- Request a lower firmware/channel target in Network and confirm the reported
  version changes without installation, restart or power effects.
- Check that unavailable NUT data stops fresh telemetry reporting and that
  recovery does not invent healthy battery data.
- Treat a real console shutdown as a separate supervised end-to-end test with
  console access, recovery procedures and normal NUT protection retained.

Do not simulate a low battery on production infrastructure without understanding
which paired devices could shut down. Local fake-server tests are not permission
for a live outage or power operation.
