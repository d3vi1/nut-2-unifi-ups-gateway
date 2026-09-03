# Local deployment notes

Copy this file to `AGENTS-local.md`. The copied file is ignored by Git.

- Record the Synology and controller hosts without passwords or private keys.
- Record the Container Manager project name and volume path.
- Record the selected NUT UPS name and whether its telemetry contains outlet
  count, `groupid`, type, switchability, and per-outlet electrical fields;
  never record credentials or add write commands.
- If advertising an existing NUT service in UniFi, record a read-only test from
  another LAN host proving the emulated device IP, served UPS name, and port.
  Keep the feature off when that evidence is absent.
- Record the generated emulator MAC and serial only in the private deployment
  store, not in issues or public logs.
- Record acceptance evidence and rollback steps for the local site.
