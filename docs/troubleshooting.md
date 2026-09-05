# Troubleshooting

Start with the real gateway version and a small, recent log sample:

```sh
docker compose --env-file .env -f compose.yaml exec -T gateway /nut-2-unifi-ups-gateway version
docker compose --env-file .env -f compose.yaml ps
docker compose --env-file .env -f compose.yaml logs --tail 30 gateway
curl -fsS http://127.0.0.1:9199/readyz
```

Add `-f compose.auth.yaml` to Compose commands if using NUT authentication.
Commands run on the gateway host. Never post `.env`, state files, passwords,
unfiltered `upsc`, controller replies or packet captures. Even when gateway log
messages are identity-free, Docker prefixes and host diagnostics may not be.
Review and redact anything you share.

## Understand the checks

- Container **healthy** and `/healthz`: the process answers, not proof of NUT or UniFi.
- `/readyz`: usable, fresh NUT data. A 503 means readiness failed; it is not
  evidence that the UPS has physically failed.
- Network **Online**: controller/UI acceptance, checked separately.
- **Paired**: a recorded relationship, not proof that a console shuts down safely.

Receipt statuses in `/readyz` are separate from NUT readiness. `stored` means a
marker was committed, not that Network accepted it. `rejected` means the response
was ineligible; `rate_limited` waits for a later eligible response. `storage_error`
requires private storage inspection and repair, then an operator-approved gateway
restart. Do not delete identity or receipt files to hide an error.

## Fixed diagnostic reasons

Warnings and startup failures use fixed `reason` codes. They intentionally omit
error text containing URLs, device identifiers, credentials or remote responses.
These codes identify a failure category, not the exact root cause.

| Reason | Check locally |
|---|---|
| `configuration_invalid` | Variable names, duration syntax, required pairs and mutually exclusive options in the [configuration reference](configuration.md). Validate Compose with `config --quiet`, not a printed configuration. |
| `state_read`, `state_permissions` | The original state volume is mounted; its files and directory have private ownership/permissions for UID/GID 65532. Never solve this with world-readable permissions. |
| `state_invalid`, `identity_mismatch` | Preserve the volume and private backup. Confirm the image/environment matches this instance; do not edit identity JSON or generate a replacement. |
| `state_write` | Free space, read-only mounts and storage health. Repair the existing volume; do not delete it. |
| `controller_dns`, `controller_route` | The configured console name resolves to IPv4 and the host can select the intended management interface. |
| `controller_transport`, `controller_timeout` | Inform destination/port, routing, connectivity, and trusted certificate when using HTTPS. Do not disable TLS verification. |
| `controller_http` | The controller returned an unexpected HTTP status. Check the inform endpoint and controller availability; raw bodies are never logged. |
| `controller_protocol` | Controller version/response compatibility, adopted identity and persisted configuration. Do not reset adoption as a first troubleshooting step. |
| `controller_replay` | A response nonce was already seen. Occasional retries can be harmless; persistent failures need a scoped interoperability investigation, not disabled replay checks. |
| `nut_dns`, `nut_connect`, `nut_timeout` | NUT name resolution, host/port, service availability, ACL and timeout. Do not broaden the server ACL to the internet. |
| `nut_auth` | Local username/password-file configuration and the NUT server's access policy. Never include the password in a report. |
| `nut_unknown_ups` | The served UPS name from `upsc -l HOST`; this is not the descriptive `ups.id`. |
| `nut_unavailable` | NUT reports stale data or a disconnected driver. Fix the upstream driver/connection. |
| `nut_protocol` | Malformed, duplicate, oversized or otherwise rejected NUT data. Record server/driver versions, not the raw response. |
| `nut_telemetry` | Missing, malformed, contradictory or stale required readings. The gateway does not invent healthy data. |
| `health_bind`, `discovery_bind` | A local bind/interface conflict. Check configured addresses and another gateway instance; do not change host networking blindly. |
| `internal_error` | A failure without a more specific safe classification. Report the gateway version, operation and redacted surrounding fixed messages. |

HTTP 404 is special: the inform endpoint was reached, but adoption may be pending
or the carrier unrecognized. It is counted separately and logged at debug level,
not as a generic connection failure. Increasing log verbosity never enables raw
controller-response logging.

## Common Network symptoms

**No device to adopt.** Check fresh NUT data first: the gateway suppresses inform
without it. Then check the console's final inform address, IPv4 route and local
discovery reachability. Network 10.6.101 returned unknown-device 404 in an older
test; a reachable endpoint alone does not establish model support.

**Getting Ready after a rename.** An observed cause was a configuration marker
that never converged. On a trusted management LAN, review the
[persistent receipt opt-in](installation.md#unifi-compatibility-options) and its
limitations. It is not permission to apply Network's power settings. The legacy
volatile single-field option is not the recommended path. A healthy container
does not prove this symptom is fixed.

**An update is offered again.** Network sees a reported compatibility version,
not the gateway release. The optional [reported-firmware mirror](configuration.md#controller-selected-reported-firmware)
records eligible controller targets without downloading or installing firmware.
Unknown response shapes remain rejected. Do not repeatedly trigger updates or
change channels unless deliberately conducting a controlled validation.

**The diagram or wattage looks wrong.** Static carrier artwork can show outlets
or surge jacks absent from NUT. Missing watts/current stay unknown; UPS-wide
values are never divided among outlets. See [compatibility](compatibility.md).

**A power setting does not work.** Outlet switching, buzzer control and Power
Cycle on Restore are unsupported. A displayed button is not an implemented action.

For help, open a [redacted bug report](https://github.com/d3vi1/nut-2-unifi-ups-gateway/issues/new?template=bug_report.yml)
with gateway version/digest, host type/architecture, NUT/driver version, Network
version, the symptom and fixed reason codes. Security reports follow
[SECURITY.md](../SECURITY.md), not public issues.
