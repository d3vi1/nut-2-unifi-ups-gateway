# Configuration

For first-time setup, use [Install and maintain](installation.md). This page is
the advanced reference; compatibility options do not grant power-control authority.

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
| `N2U_UNIFI_HTTP_GCM_VOLATILE_CFGVERSION_SYNC` | `false` | Boolean; explicit plain-HTTP compatibility opt-in |
| `N2U_UNIFI_HTTP_GCM_CONFIG_RECEIPT_MODE` | `off` | `off`, `memory`, or `persistent`; incompatible with the volatile option |
| `N2U_UNIFI_HTTP_GCM_REPORTED_FIRMWARE_SYNC` | `false` | Boolean; requires persistent receipts and trusted-LAN HTTP/GCM |
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
plain-HTTP replies are acknowledgement-only by default: configuration, reset,
key, reboot, upgrade, and cadence effects are suppressed. GCM authenticates
contents but does not prove that a response belongs to the current request. A
same-key one-way upgrade from CBC to GCM remains available; full post-adoption
response effects require HTTPS with a certificate trusted by the container.

### Plain-HTTP GCM cfgversion compatibility

This is the **legacy single-field experiment**, not the recommended onboarding
path. See [multi-field receipts](#multi-field-configuration-receipts) for the
controller response shape observed with Network 10.6.102.

`N2U_UNIFI_HTTP_GCM_VOLATILE_CFGVERSION_SYNC` is a narrow, default-off
interoperability experiment for rename-related configuration changes. Whether
it clears **Getting Ready** remains **CANDIDATE** until
exact-build live acceptance. Enable the option only when the configured inform
endpoint is plain HTTP on a trusted management LAN.

When enabled, the exception applies only after adoption, with a non-default
controller key, to an authenticated GCM `setparam` response. Its `mgmt_cfg`
must contain exactly one non-empty entry: a syntactically valid
`cfgversion=...`. Any additional or unknown `mgmt_cfg` entry—including
`authkey`, inform URL, encryption mode, or adoption-state changes—disables the
volatile acknowledgement. The accepted `cfgversion` may be mirrored into
subsequent inform payloads in memory for the lifetime of the process.

`system_cfg` may accompany that response, but it remains observation-only and
is ignored. The gateway also does not apply inform cadence, restart, upgrade,
relay, or other power-control requests from the response.

This marker is not saved to the state file, and its response nonce is not added
to the persistent state-changing replay window. Restarting therefore returns
to the last persisted `cfgversion`; if another eligible `setparam` later
arrives, the gateway may mirror that marker again. This behavior alone does
not establish any Network UI state transition. GCM does not provide
request-response correlation, so a delayed but authentic response can
temporarily replace the in-memory marker. Do not enable this option on an
untrusted or shared network.

### Multi-field configuration receipts

`N2U_UNIFI_HTTP_GCM_CONFIG_RECEIPT_MODE` handles the observed controller
response containing `cfgversion` plus ordinary management fields. It is a
separate opt-in: leave `N2U_UNIFI_HTTP_GCM_VOLATILE_CFGVERSION_SYNC=false`.
The sole-entry volatile experiment above cannot accept this response shape.
Marker convergence was **OBSERVED** with Network 10.6.102. The memory-mode UI
was reported Online with pairings; persistent receipt storage and reload were
also observed. This does not prove every rename/restart/UI sequence or acceptance
on another controller build; see [the evidence matrix](compatibility.md).

| Mode | Behavior |
|---|---|
| `off` | Default; no receipt processing or receipt-file access |
| `memory` | First interoperability test; report the accepted marker until restart |
| `persistent` | Commit the accepted marker before reporting it; restore it after restart |

For a controlled first test on a trusted management LAN:

```dotenv
N2U_UNIFI_HTTP_GCM_VOLATILE_CFGVERSION_SYNC=false
N2U_UNIFI_HTTP_GCM_CONFIG_RECEIPT_MODE=memory
```

Verify that Network leaves **Getting Ready** and pairings remain, then select
`persistent` and verify both restart and rename behavior. Runtime health alone
does not establish controller acceptance or successful device shutdown.

The parser requires adoption, a non-default key, authenticated GCM, the current
device MAC and HTTP controller origin, `_type=setparam`, and one valid
`cfgversion`. It accepts only these inert companion keys: `capability`,
`led_enabled`, `mgmt_url`, `report_crash`, `selfrun_guest_mode`, `stun_url`, and
`use_aes_gcm=true`. Unknown or duplicate keys, malformed values, new auth keys,
inform URL changes, mode downgrades, and effectful top-level fields reject the
receipt. Neither companion URL becomes a network destination.

The observed outer JSON may also contain `cfgversion` (which must exactly match
the management marker), `server_time_in_utc` (exactly 13 ASCII digits), and
`blocked_sta` (only an empty string). These fields are not retained. The timestamp
does not establish freshness, ordering, or cadence, and no client-blocking action
is implemented. Nonempty lists, mismatches, other types, and unknown fields reject
the receipt.

An optional `system_cfg` is observed and ignored. A receipt does not claim that
NUT-server, buzzer, relay, recovery-cycle, IP, or other settings were applied.
Network may stop retrying a revision whose unsupported settings remain unapplied;
check `ignored_controller_setting_categories` in `/readyz` and the corresponding
`n2u_ignored_controller_setting_categories` metric before interpreting UI settings.

Persistent mode uses a private `controller-receipt.json` beside `N2U_STATE_FILE`
in the existing state volume (normally `/var/lib/n2u`). Use a separate state
directory for each gateway instance. The adoption file keeps its v1 schema.
The receipt is limited to 16 KiB: a schema/context binding, marker, and at most
128 transition nonces. It contains no raw controller configuration or passwords.
Changing device identity, adoption key/mode, persisted adoption marker, inform
endpoint, carrier, or receipt policy invalidates the cached receipt.

New receipts use a private temporary file, file sync, atomic rename, and directory
sync before advancing the report. Stable markers and noops do not write. At most
one transition is written per 30 seconds per process; deferred transitions can
be accepted on a later response. A storage failure blocks further receipt writes
for that process. Repair storage, then restart; no adoption reset is required.
`configuration_receipt` in `/readyz` and `n2u_config_receipt_status` distinguish
pending, received, stored, rejected, rate-limited, and storage-error states.
NUT readiness remains independently measured.

Only marker-transition nonces are persisted; ordinary noops and same-marker
replies are remembered in process memory only. The persisted window rejects
those transition replays across restart, but does not establish freshness or
ordering. An unseen delayed reply, a same-marker reply no longer remembered,
an evicted nonce, or restoration of an old volume can restore an old marker and
mislead Network about convergence. Configuration versions are opaque; legitimate
A-to-B-to-A changes remain possible. Enable only on a trusted management LAN.

For rollback, use the previous version-matched image, Compose files, and `.env`
with the same named state volume. The old binary reads its original adoption
state and does not use the separate receipt. Do not retain new environment
variables in an older deployment: unknown `N2U_` variables are rejected.

### Controller-selected reported firmware

`N2U_UNIFI_HTTP_GCM_REPORTED_FIRMWARE_SYNC=false` is a separate default-off
compatibility experiment. Set it to `true` only with configuration receipt mode
`persistent`, on a trusted management LAN. It mirrors the version selected by an
authenticated, adopted, non-default-key HTTP/GCM controller `upgrade` response.
Targets may increase **or decrease**, for example when changing release channels.
No version ordering or invented maximum is used. Versions must have three or four
canonical decimal components; unknown formats fail closed.

This changes **reported compatibility text**, not installed software. The real
gateway release, source protocol profile, hardware identity, outlet/capability
masks and minimum required version remain unchanged. Inform `version` and the
short discovery version change together at the committed-state boundary. UPS26's
long embedded firmware build remains source provenance; the Pro carrier's two
short version fields both mirror the target. An in-flight packet built before a
transition can still finish with its previous snapshot.

Only exact `upgrade` fields `version`, optional `url`, `md5sum`, `sha256sum`, and
`server_time_in_utc` are accepted. Companion fields are bounded, type-checked and
discarded, not retained or logged. URLs are never parsed, resolved or fetched;
checksum text is not artifact verification, and server time is not freshness.
There is no firmware install, reboot, command, cadence or NUT-write action.

The independent `controller-firmware.json` beside `N2U_STATE_FILE` is private
(0600), bounded to 16 KiB and atomically committed before publication. It contains
only a schema, opaque authority/source-profile binding, target version and at most
128 transition nonces. Same-target replies do not write. New targets write at most
once per 30 seconds per process. Failed storage blocks further firmware changes
until repair and restart; configuration-receipt storage failure also blocks this
dependent feature. The two markers do not erase each other on normal transitions.
Identity, key, origin, GCM mode or source-profile changes invalidate the target.

`reported_firmware_receipt` in `/readyz` and
`n2u_reported_firmware_receipt_status` expose fixed status values, never the target
or companion metadata. Keep one state directory per instance. Disabling the flag
uses the source version and leaves the cache untouched; re-enabling can restore
that cache. Rollback preserves adoption state and leaves this separate file unused.

This feature materially influences Network's upgrade/configuration/UI decisions.
Authenticated GCM does not prove ordering: unseen, evicted, same-target responses
forgotten after restart, or restored old volumes can regress the reported target.
A legitimate A-to-B-to-A transition is allowed. Same-version channel changes have
no separate channel meaning. A user-triggered manual update from reported
`1.6.1.413` to `1.6.4.432`, followed by configuration convergence, was **OBSERVED**
with Network 10.6.102. Firmware-target restart/recreation and downgrade/channel
switching remain **CANDIDATE**, covered by automated tests but not that live test.
Do not generalize this observation to other builds, carriers or shutdown behavior.

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
| affirmative outlet, exactly matched group, or global `switchable=yes` | Retained as native descriptive topology; no writable `HAS_RELAY` bit is emitted in v1 |
| direct `outlet.N.current`, `outlet.N.realpower`, or `outlet.N.power` key | `POWER_METER` bit `0x00002` |

`HAS_RELAY` (`0x00001`), `AUTO_RELAY` (`0x00004`), and the unresolved low-order
bit `0x00008` are never emitted from NUT observations. `POWER_METER` requires a
direct outlet-scoped current,
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

NUT may publish a bounded `outlet.group.count` table while omitting
`outlet.count`. The gateway retains valid group IDs, names, types, optional
counts, status, and switchability as a separate partial native observation.
Because no membership is known, those rows are not overlaid on the carrier
fallback, do not set `TopologyObserved`, do not create a group-to-outlet map,
and cannot add relay state or capabilities to an inform payload. This is the
expected interpretation of a PowerNet group table that has no per-outlet
membership evidence.

All relay groups are descriptive in gateway v1. The process has no NUT command
method; controller relay requests are ignored and cannot switch the upstream
UPS. Rows in a shared group report a consistent relay state. A directly matched
group status may supply it; otherwise conflicting or incomplete member evidence
makes that state unknown. Switchability remains available internally for future
evidence work but is not converted into a writable UniFi capability. Unknown `N2U_` variables,
including proposed control/command settings, are rejected.

## UPS-wide electrical and buzzer data

| NUT fact | UniFi projection |
|---|---|
| `output.current` | `device_output_current`, preserving the precision supplied by the NUT driver |
| `ups.realpower`, then `output.realpower` | `device_total_power_output` in watts |
| `ups.realpower.nominal`, then `output.realpower.nominal` | `device_total_power_budget` in watts; nominal zero is invalid |
| `ups.power`, then `output.power` | Retained as apparent power in VA; never projected as watts |
| `ups.power.nominal`, then `output.power.nominal` | Retained as nominal apparent power in VA; never projected as watts; nominal zero is invalid |
| `output.powerfactor` | Direct power factor in the closed interval 0–1 |
| absent direct power factor plus valid same-snapshot W and VA | Derived `W / VA` only when `VA > 0` and `0 <= W <= VA` |
| `ups.load` | Retained as load percentage, never fabricated into W without direct real-power evidence |
| `battery.charger.status=charging` | Charging `true` |
| `battery.charger.status=discharging/floating/resting` | Charging `false` |
| absent modern charger status plus `CHRG` | Legacy charging `true` |
| absent modern charger status plus `DISCHRG` | Legacy charging `false` |
| no modern status, `CHRG`, or `DISCHRG` | Charging remains unknown and is omitted |
| `ups.beeper.status=enabled/disabled` | Preserved as the matching boolean observation |
| `ups.beeper.status=muted` | Preserved internally but omitted from UniFi's lossy boolean field |

Alias resolution is fail-closed. Equal numeric aliases are accepted with the
listed precedence; differing valid aliases, any present malformed alias,
malformed direct power factor, or contradictory modern/legacy charger evidence
leave the affected value unknown. The gateway does not derive watts from VA,
power factor, load, or voltage multiplied by current.

The effective gateway `smart_power_caps` is a fail-closed allowlist inside the
carrier mask. It advertises only safe-shutdown timing (`0x08`), plus NUT
information access when the explicit advertisement above is enabled (`0x09`).
Power Cycle on AC Recovery, buzzer control, EPO, and unresolved carrier bits
`0x40`/`0x80` stay off. The similarly numbered `outlet_caps.AUTO_RELAY` bit
belongs to a different bitmap and is not an implementation of Power Cycle on
Restore.
