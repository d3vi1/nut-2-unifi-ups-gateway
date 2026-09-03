# Configuration

Configuration is read once from environment variables. Unknown `N2U_`
variables should be treated as deployment mistakes. Durations use Go syntax,
for example `5s`, `2m`, or `500ms`.

## Upstream NUT

| Variable | Default | Validation |
|---|---|---|
| `N2U_NUT_ADDRESS` | `127.0.0.1:3493` | host and port required |
| `N2U_NUT_UPS` | `ups` | token characters only |
| `N2U_NUT_USERNAME` | empty | requires a password |
| `N2U_NUT_PASSWORD` | empty | mutually exclusive with `_FILE` |
| `N2U_NUT_PASSWORD_FILE` | empty | maximum 64 KiB |
| `N2U_NUT_TIMEOUT` | `5s` | 1 second–1 minute |
| `N2U_NUT_ALLOW_INSECURE_REMOTE` | `false` | explicit plaintext remote-NUT acknowledgement |
| `N2U_POLL_INTERVAL` | `5s` | 1 second–5 minutes |
| `N2U_STALE_AFTER` | `20s` | at least the poll interval |

Prefer `N2U_NUT_PASSWORD_FILE` to a secret in the environment. Poll-only NUT
servers commonly require no login; do not add one unless the server does.
Because the current client deliberately implements no STARTTLS, non-loopback
NUT endpoints are rejected unless `N2U_NUT_ALLOW_INSECURE_REMOTE=true` is set.
That opt-in acknowledges that telemetry and any credentials traverse the
network without transport encryption; it is not suitable for an untrusted LAN.

## UniFi identity and transport

| Variable | Default | Validation |
|---|---|---|
| `N2U_UNIFI_MODEL` | `USWDA26` | Controller-recognized UPS carrier: `USWDA26` or `USPDA2C` |
| `N2U_UNIFI_VERSION` | `1.6.1` | `1.6.1` or the exact selected build (`1.6.1.413`/`1.6.1.4933`) |
| `N2U_INFORM_URL` | `http://unifi:8080/inform` | HTTP(S), `/inform`, no credentials/query/fragment |
| `N2U_INFORM_INTERVAL` | `10s` | 1 second–10 minutes; sole runtime inform cadence |
| `N2U_INFORM_TIMEOUT` | `10s` | 1 second–1 minute |
| `N2U_DISCOVERY_INTERVAL` | `30s` | 5 seconds–10 minutes |
| `N2U_UNIFI_NUT_SERVER_ENABLED` | `false` | Explicit experimental advertisement only |
| `N2U_UNIFI_NUT_SERVER_ID` | `ups` | Served NUT UPS name, 1–31 token characters when enabled |
| `N2U_UNIFI_NUT_SERVER_PORT` | `3493` | 1–65535 |
| `N2U_DEVICE_MAC` | generated | six-byte unicast MAC |
| `N2U_DEVICE_SERIAL` | derived | stable non-empty identifier |
| `N2U_DEVICE_HOSTNAME` | `nut-2-unifi-ups-gateway` | 1–63 characters |
| `N2U_DEVICE_IP` | route-derived | IPv4 only |

Set the final controller origin before first startup. Adoption may update the
path/configuration at that exact origin, but hostname, address, scheme, and port
changes are rejected rather than accepted through a DNS-equivalence check.
Controller-provided intervals are parsed for protocol compatibility but never
change the runtime scheduler. `N2U_INFORM_INTERVAL` is the sole cadence source,
which makes captured cadence replies inert across process restarts without
rewriting the state volume on every ordinary inform.

Initial adoption uses firmware-compatible CBC and a public bootstrap key, so it
must occur on a trusted management LAN. Once a controller key is installed,
plain-HTTP CBC replies are acknowledgement-only: configuration, reset, key,
reboot, upgrade, and cadence effects are suppressed. A same-key one-way upgrade
to GCM remains available. Full controller response effects require authenticated
GCM or HTTPS with a certificate trusted by the container.

### Optional NUT Server advertisement

UniFi's **NUT Server** setting describes a downstream NUT service reachable at
the emulated device's own LAN IP. It is not another name for
`N2U_NUT_ADDRESS`, and the gateway does not start, stop, configure, or proxy an
NUT server.

The advertisement is therefore disabled by default and remains **CANDIDATE**.
Enable it only when a separate service is already reachable from another LAN
host at `N2U_DEVICE_IP:N2U_UNIFI_NUT_SERVER_PORT` and `LIST UPS` returns exactly
`N2U_UNIFI_NUT_SERVER_ID`. The ID is the served NUT UPS name used in
`upsc ID@HOST:PORT`; it is not the descriptive `ups.id` variable.

```dotenv
N2U_UNIFI_NUT_SERVER_ENABLED=true
N2U_UNIFI_NUT_SERVER_ID=ups
N2U_UNIFI_NUT_SERVER_PORT=3493
```

Only an unauthenticated, credential-free advertisement is representable. The
gateway never copies an upstream username or password into UniFi inform.
Changing this form in Network does not reconfigure the external NUT service;
controller-supplied `nutserver.*` settings are reported as ignored and produce
no NUT write.

Changing an explicit MAC or serial after the state volume is initialized fails
startup. Remove the gateway's own state volume only when intentionally creating
a new UniFi device identity.

Before adoption, changing `N2U_INFORM_URL` atomically repairs the pending state
(including after a failed DNS lookup on first startup). After any valid
controller response marks the device managed, the persisted negotiated URL
takes precedence and configuration no longer overwrites it.

## Runtime

| Variable | Default |
|---|---|
| `N2U_STATE_FILE` | `/var/lib/n2u/state.json` |
| `N2U_HEALTH_ADDRESS` | `127.0.0.1:9199` |
| `N2U_LOG_LEVEL` | `info` |

Health handlers contain no device identity, retain strict request timeouts and
header bounds, and share a fixed aggregate connection limit. Loopback remains
the safe default; expose this endpoint remotely only behind trusted network
policy.

## Outlet topology and control

`N2U_UNIFI_MODEL` selects a known Network-facing UPS identity, not the outlet
layout. `NUTUPS` is useful local terminology for the logical projection but is
not a supported wire model or configuration value: stock UniFi Network routes
unknown model names to its unknown-device path.

When NUT supplies a valid `outlet.count`, the gateway projects that many
outlets. The following native facts control each projected row:

| NUT fact | UniFi projection |
|---|---|
| `outlet.N.groupid` | Opaque equality key, remapped by first occurrence to dense positive `relay_group` values |
| missing `outlet.N.groupid` | A singleton relay group for that outlet |
| matching `outlet.group.G.id` | Associates group metadata/status by exact opaque ID when optional group count agrees; numeric IDs are not table indices |
| unambiguous USB `outlet.N.type` or `outlet.N.designator` | USB physical-class bit `0x20000` |
| any other or missing type/designator | AC-compatible physical-class bit `0x10000`; not a physical-type claim |
| affirmative outlet, exactly matched group, or global `switchable=yes` | `HAS_RELAY` bit `0x00001`; outlet fact has highest precedence |
| direct `outlet.N.current`, `outlet.N.realpower`, or `outlet.N.power` key | `POWER_METER` bit `0x00002` |

`AUTO_RELAY` (`0x00004`) and the unresolved low-order bit `0x00008` are never
inferred from NUT. `POWER_METER` requires a direct outlet-scoped current,
real-power, or apparent-power variable. Voltage or power factor alone does not
establish that capability. A malformed sample is omitted from telemetry, while
the presence of its direct variable still describes meter capability. UPS-wide
and group-wide measurements are not copied or apportioned to outlets. Dynamic
rows use no `button_group`, because NUT outlet topology supplies no evidence for
the genuine device's physical buttons. A malformed outlet/group switchability
fact remains unknown and does not inherit a broader group/global value.

If `outlet.count` is absent or invalid, the gateway uses a deterministic,
AC-compatible fallback. `USWDA26` uses eight rows with 1–4 in relay group 1 and
5–8 in relay group 2. `USPDA2C` uses nine singleton groups. These rows carry
only the AC physical-class bit: without NUT topology the gateway does not
invent relay, metering, automatic-relay, physical-button, or outlet-state
capabilities. The carrier affects only this fallback; valid observed NUT
topology remains carrier-independent. The dynamic projection is experimental
and remains **CANDIDATE** until accepted live with a topology-capable driver.

All relay groups are descriptive in gateway v1. The process has no NUT command
method; controller relay requests are ignored and cannot switch the upstream
UPS. Rows in a shared group report a consistent relay state. A directly matched
group status may supply it; otherwise conflicting or incomplete member evidence
makes that state unknown. Unknown `N2U_` variables,
including proposed control/command settings, are rejected.

## UPS-wide electrical and buzzer data

| NUT fact | UniFi projection |
|---|---|
| `output.current` | `device_output_current`, preserving the precision supplied by the NUT driver |
| `ups.realpower` | `device_total_power_output` in watts |
| `ups.realpower.nominal` | `device_total_power_budget` in watts |
| `ups.power` / `ups.power.nominal` | Not projected as watts; these values are apparent power in VA |
| `ups.load` | Retained as load percentage, never fabricated into W without direct real-power evidence |
| `ups.beeper.status=enabled/disabled` | Preserved as the matching boolean observation |
| `ups.beeper.status=muted` | Preserved internally but omitted from UniFi's lossy boolean field |

The effective gateway `smart_power_caps` is a fail-closed allowlist inside the
carrier mask. It advertises only safe-shutdown timing (`0x08`), plus NUT
information access when the explicit advertisement above is enabled (`0x09`).
Power Cycle on AC Recovery, buzzer control, EPO, and unresolved carrier bits
`0x40`/`0x80` stay off. The similarly numbered `outlet_caps.AUTO_RELAY` bit
belongs to a different bitmap and is not an implementation of Power Cycle on
Restore.
