# Protocol evidence

This document separates observations from compatibility assumptions. No
Ubiquiti firmware, extracted executable, controller database, packet capture,
credential, or device identity is distributed by this repository.

## Evidence labels

- **PROVEN**: observed in the exact firmware/controller build or an executed
  interoperability test.
- **OBSERVED**: visible runtime or UI state that establishes the displayed
  result, but not the private protocol mechanism that produced it.
- **CANDIDATE**: implemented from corroborated public protocol research but not
  yet accepted by the target controller.
- **UNKNOWN**: unresolved and not advertised as supported.
- **BLOCKED_EXTERNAL**: requires hardware, credentials, or controller state not
  available to the test.

## Exact firmware analyzed

| Product | Selector/sysid | Firmware | Image SHA-256 |
|---|---|---|---|
| UniFi UPS 2U EU | `USWDA26` / `0xDA26` | `1.6.1+413` | `23ef3227b207ab3afb80821c6e9a65cfb0863ca486698cdac46117acf94fdd74` |
| UniFi UPS 2U Pro EU | `USPDA2C` / `0xDA2C` | `1.6.1+4933` | `77036be0858115d40efc5f9984f1fdf6e9a90100d4b65df787cc5d45d3211de5` |

Static analysis used a segment-preserving ELF reconstruction and Ghidra's
Xtensa little-endian languages for ESP32 and ESP32-S3. The images and derived
analysis databases are not part of this repository.

## TNBU inform envelope

Both images use the same 40-byte header: `TNBU`, big-endian packet version `0`,
MAC, big-endian flags, 16-byte IV/nonce, big-endian payload version `1`, and
big-endian body length. Packet version `1` is rejected by the device parser.

The JSON is encrypted directly; there is no zlib layer:

- AES-CBC uses flags `0x0001`, a 16-byte IV, and PKCS#7 padding.
- AES-GCM uses flags `0x0009`, a 16-byte nonce, the full header as AAD, and an
  appended 16-byte tag.

The exact UPS HTTP client sends `POST` with
`Content-Type: application/x-binary`, its default
`User-Agent: ESP32 HTTP Client/1.0`, and no explicit `Accept` header. It accepts
only HTTP 200. HTTP 404 is a distinct retried rejection state, not proof that
the controller is unreachable.

The initial envelope key is a public protocol constant. Adoption through
`/inform` uses top-level `_type:"setparam"`; `mgmt_cfg` is a newline-delimited
`key=value` string carrying `cfgversion`, `inform_url`, `authkey`, and optional
`use_aes_gcm`. There is no HTTP-inform `set-adopt` command. The response is
decoded with the current key/mode and changes apply to the next request. GCM is
sticky until `setdefault`; a later `setparam` may rotate the key.

The gateway deliberately narrows those firmware semantics at its trust
boundary. Controller cadence never changes the local scheduler. After a
controller key is installed, every plain-HTTP reply is acknowledgement-only by
default: GCM proves envelope integrity but not association with the current
request. A same-key one-way CBC-to-GCM upgrade remains available; all other
effectful post-adoption replies require trusted HTTPS.

An explicit, default-off compatibility option can mirror a syntactically valid
`cfgversion` from an authenticated GCM `setparam` after adoption with a
non-default key. Eligibility requires `mgmt_cfg` to contain exactly one
non-empty entry, `cfgversion=...`; any additional or unknown `mgmt_cfg` entry
disables the acknowledgement. An accompanying `system_cfg` is still observed
and ignored. The value affects only subsequent inform payloads in the running
process. It does not apply key, URL, mode, cadence, adoption, restart, upgrade,
relay, or power-control requests; neither the state file nor the persistent
state-changing replay window is changed. A restart restores the persisted
marker; any later eligible controller response is evaluated again. This does
not establish a Network UI transition. Because GCM still does not correlate
the response to the current request, this exception is suitable only for a
trusted management LAN.

### Multi-field receipt evidence

The separate `N2U_UNIFI_HTTP_GCM_CONFIG_RECEIPT_MODE` experiment accepts a
strictly validated multi-field `setparam`. A redacted Network 10.6.102 sample
contained `cfgversion`, `capability`, `led_enabled`, `mgmt_url`, `report_crash`,
`selfrun_guest_mode`, `stun_url`, and `use_aes_gcm=true`. The legacy sole-entry
mirror rejects that shape. USWDA26 firmware assigns its marker before applying
`system_cfg`, which can subsequently fail; receipt is not proof of applied
settings. The new mode records only the marker and replay metadata, optionally
in a separate private receipt file. No controller settings become executable.
Online/rename/restart efficacy remains **CANDIDATE** pending live acceptance;
authenticated GCM alone does not establish ordering or freshness.

A subsequent scoped capture contained six top-level string fields: `_type`,
`mgmt_cfg`, `system_cfg`, `cfgversion`, `server_time_in_utc`, and `blocked_sta`.
Two authenticated responses were rejected by the initial three-field parser.
The revised parser accepts the matching outer marker, a 13-digit inert timestamp,
and an empty blocked-client string; all other top-level fields remain rejected.
Both captured replies passed the revised parser offline. This proves syntax
compatibility with that capture, not live Network convergence.

## Genuine firmware protocol inventory

| Direction | Endpoint | Purpose | Evidence | Gateway v1 |
|---|---|---|---|---|
| inbound | TCP/3493 | NUT `upsd` 2.8.0 | **PROVEN** | source only; not re-exported |
| inbound | TLS/TCP/22 | proprietary UniFi adopt/inform/private messages; not SSH | **PROVEN** | omitted |
| inbound | HTTPS/TCP/8080 | authenticated cmd/OTA/reboot/reset/log API | **PROVEN** | omitted |
| outbound | UDP/10001 broadcast | UniFi discovery announcement; no device-side listener | **PROVEN** | implemented send-only |
| outbound | HTTP(S) `/inform` | encrypted binary inform | **PROVEN** | implemented |
| outbound | UDP/3478 | STUN client | **PROVEN** | omitted unless proven necessary |
| outbound | configurable UDP | syslog client | **PROVEN** | omitted |
| outbound | HTTPS | firmware download | **PROVEN** | omitted |
| link layer | LLDP TX/RX | neighbor/uplink discovery code in USWDA26 1.6.1+413 | **PROVEN** static code; exact TLVs/runtime emission **UNKNOWN** | omitted; optional future investigation |

The firmware contains no supported evidence for SSH, Telnet, mDNS/DNS-SD,
SNMP, SSDP/UPnP, MQTT, or WebSocket listeners. Namespace and parser strings
alone were not promoted into protocol claims.

## UniFi Network controller observations

The compatibility target used during development was UniFi Network 10.6.101 on
UniFi OS 5.1.31. Its installed device database recognizes `USPDA2C` as
`UPS-2U-Pro-EU` with battery-management, smart-outlet, outlet-monitor, buzzer,
MCU, and pure-sine-wave capabilities.

Controller code proves:

- UDP/10001 discovery and TCP/8080 `/inform` listeners;
- per-device inform authentication, AES-CBC and AES-GCM;
- MAC consistency checks between inform header and JSON;
- UPS outlet overrides and shutdown-policy fields;
- L3-inform discovery without the SSH adoption path;
- pairing/unpairing and managed-console shutdown orchestration.

Historical live tests against this exact Network 10.6.101 target also establish
an important build-specific negative boundary. Network received and decrypted
TNBU v0/CBC requests, passed JSON, payload-version, and header/payload-MAC
validation, then returned HTTP 404 from its unknown-device dispatch. No
targeted `device` or `pending_device` record was created. The same result held
after all of these one-variable checks:

- the fixed firmware profile GUID and coherent `hash_id`/`anon_id`;
- the firmware HTTP header fingerprint;
- a collision-checked Ubiquiti OUI;
- a unique macvlan IPv4/MAC pair with verified UDP/10001 and TCP/8080 traffic.

That controller's catalogs contained the `USWDA26`/`0xDA26` definition and exact
`1.6.1.413` firmware. The result is retained as historical evidence about that
build, not a claim about every Network release.

A redacted interoperability observation on Network 10.6.102 with UniFi OS
5.1.31 showed the gateway-projected UPS as adopted and safe-shutdown pairing
with eligible managed consoles. This is **OBSERVED** UI evidence of registration
and pairing state. It does not by itself prove which private dispatch condition
changed, demonstrate a completed shutdown, or validate the new
dynamic-topology projection. Device counts, names, and site identity are
intentionally omitted.

A literal `model="NUTUPS"` is not emitted. No such model is present in the
examined stock registry, and the exact controller's unknown-device path rejects
unrecognized identities. The implementation retains `USWDA26` or `USPDA2C` as
a recognized carrier while allowing NUT, rather than that carrier, to describe
outlet topology.

Read-only inspection of that installed frontend and controller object also
established:

- `USWDA26` has static catalog categories `standard:[1,2,3,4]`,
  `surge:[5,6,7,8]`, plus RJ45 Surge Out/In entries. The battery/surge icons and
  blue network-surge jacks do not come from dynamic `outlet_caps`.
- The heading **Surge / Power Utilization** is hard-coded for this model. It
  consumes `device_total_power_output` and `device_total_power_budget`; missing
  budget becomes zero, and output below the model's 100 W display floor becomes
  the `<100` range seen in the UI.
- The details panel formats `device_output_current` to two decimals but does not
  create it. In a redacted APC/Synology interoperability sample,
  `output.current=1.00` was the exact precision exposed by the `snmp-ups`
  driver.
- Device `smart_power_caps` bit `0x2` gates **Power Cycle on Restore**, bit `0x4`
  gates **Power-Off Buzzer**, bit `0x8` gates safe-shutdown/cycle timing, and bit
  `0x10` gates EPO. This namespace is separate from `outlet_caps`, where
  `AUTO_RELAY` happens to be `0x4`.
- `nut_server` has the controller shape `enabled`, `id`, `port`,
  `credential_required`, `username`, and `password`. Its ID is the UPS name
  served by NUT protocol `LIST UPS`, not the opaque telemetry variable `ups.id`.

A redacted same-host Synology/Network sample provided additional **OBSERVED**
read-only evidence: the NUT service was reachable from the controller host at
the emulated device address on TCP/3493, and `LIST UPS` returned one served UPS
name. The separate opaque `ups.id` value differed from that served name. This
proves that one deployment can truthfully opt in to advertising its exact
served name on port 3493. Documentation and examples use the explicitly
synthetic served name `ups`; operators must replace it when `LIST UPS` reports a
different value. The observation does not prove that every local or remote NUT
source is reachable at the emulated device address, nor that Network accepts a
device-originated `nut_server` object without provisioning feedback.

## Dynamic NUT outlet topology

The dynamic mapping deliberately separates observed NUT facts from UniFi
compatibility choices:

| NUT input | Projected behavior | Evidence status |
|---|---|---|
| valid positive `outlet.count` | exact observed outlet count | **CANDIDATE** for live Network acceptance |
| equal `outlet.N.groupid` values | same deterministic positive `relay_group` | **CANDIDATE** |
| missing `outlet.N.groupid` | unique singleton `relay_group` | conservative **CANDIDATE** fallback |
| exact `outlet.group.G.id` match with consistent optional count | associates group metadata/status/switchability | evidence-bound **CANDIDATE** mapping |
| bounded `outlet.group.count` without `outlet.count` | retained as a separate partial native group table; never applied to carrier rows | evidence-bound observation, no projected topology |
| unambiguous USB `outlet.N.type` or `.designator` | `0x20000` physical-class bit | conservative **CANDIDATE** mapping |
| other or absent type/designator | `0x10000` AC-compatible bit | interoperability **CANDIDATE**, not a native-type assertion |
| affirmative outlet, matched-group, or global NUT `switchable=yes` | retained as native topology evidence; no `HAS_RELAY` bit in read-only v1 | evidence-bound **CANDIDATE** observation |
| direct outlet current, real-power, or apparent-power key | `POWER_METER` (`0x00002`) | evidence-bound **CANDIDATE** mapping |

NUT outlet type and designator are opaque; USB is recognized only from an
unambiguous value, not from a name, description, or guessed connector taxonomy.
`HAS_RELAY` (`0x00001`), `AUTO_RELAY` (`0x00004`), and the unresolved low-order
bit `0x00008` are never emitted from NUT observations, and no physical
`button_group` is invented. Voltage and power factor
alone do not establish `POWER_METER`. Device-level and outlet-group electrical
values are never spread across outlets, so a real UPS total cannot appear as
fabricated identical per-outlet amperage. Shared relay states are emitted
consistently across group members; conflicts make the state unknown.

UPS-wide real-power mapping is unit-preserving. Ordered W aliases are
`ups.realpower` then `output.realpower`, with the same ordering for nominal W;
ordered apparent-power aliases are `ups.power` then `output.power`, likewise
for nominal VA. VA is never sent in a field Network labels as watts. Conflicts
and malformed present aliases fail closed. Direct `output.powerfactor` has
priority; when absent, and only with valid same-snapshot real and apparent
power, `W/VA` supplies a value in 0–1. `ups.load`, voltage/current products,
nominal VA, and power factor are not used to invent real power. Modern
`battery.charger.status` is preferred over the legacy `CHRG`/`DISCHRG` tokens;
contradictions are omitted rather than resolved by precedence. When no charger
evidence exists, charging state remains unknown. Standard `ups.beeper.status`
values are preserved, but the `muted` state has no lossless UniFi boolean
representation.

When no valid `outlet.count` exists, the gateway reports a conservative
AC-compatible layout: eight outlets in two 4+4 groups for `USWDA26`, or nine
singleton groups for `USPDA2C`. It omits all relay, automatic-relay, metering,
button, and per-outlet-state capabilities because NUT did not establish them.
The former is the current path for the Synology APC driver, whose live NUT
snapshot contains no `outlet.*` variables. A topology-capable NUT driver and a
controlled Network acceptance test are still required to promote the dynamic
path beyond **CANDIDATE**.

## Exact eight-outlet firmware reference

`USWDA26` is a local selector. Its controller-facing inform identity is
`model="UPS26"`, `model_display="UPS26"`, version `1.6.1.413`, required version
`1.3.4`, profile GUID `317875ca-ad3e-47e9-9430-47e3e2e1ab3d`, and full build
`UPS2U.esp32.v1.6.1.g5457.260723.0556`. `hash_id` is the 16-character lowercase
hex rendering of the same eight bytes carried by discovery TLV `0x27`.
`anon_id` renders the same 16 post-normalization bytes carried by TLV `0x2a`;
the firmware uses the unusual UUID-shaped nibbles `text[14]='8'` and
`text[19]='4'`. Outlets 1–4 have capabilities `0x1000D` and relay group 1;
outlets 5–8 have capabilities `0x10005` and relay group 2. Only the first four
records serialize button fields in this firmware callback.

Its discovery message is version 2, command 6, with model/platform `UPS26`,
hardware `UPS 2U`, sysid `0xDA26`, full build in TLV `0x03`, `1.6.1.413` in TLV
`0x16`, profile UUID `317875ca-ad3e-47e9-9430-47e3e2e1ab3d`, and the observed
`0x2c=3`/`0x2d=2` fields.

These masks, button fields, and group assignments describe the genuine UPS26
firmware reference only. The runtime fallback retains the structural group
count but emits AC-compatible rows without those unsupported capabilities. The
`USPDA2C` firmware reference similarly remains separate from its conservative
nine-singleton runtime fallback. Neither fallback constrains topology that NUT
actually reports.

## Power-control evidence

Firmware `relayctl` entries contain a 1-based index plus delay-to-off and
delay-to-on in minutes, but the analyzed UPS26 handler does not use index,
group, or `relay_state` to select an outlet. Its delay path performs a global
UPS power cycle. `system_cfg` outlet relay keys change desired configuration
only and do not prove immediate actuation. The gateway therefore parses
`relayctl` but ships no NUT write API.

Firmware and controller analysis further prove that **Power Cycle on Restore**
is global `smart_power_caps=0x2`, independent of outlet `AUTO_RELAY`. The Pro
firmware persists an enable flag and 60–600 second recovery delay, arms selected
outlets during safe shutdown, and cycles currently-on armed outlets after AC
returns. NUT has no exact persistent setting: `ups.start.auto`,
`ups.delay.start`, `shutdown.return`, and `load.cycle` have distinct semantics
and the latter two are destructive one-shot commands. V0.9.0 therefore uses a
fail-closed allowlist: safe-shutdown timing only (`0x08`), plus NUT information
access for an explicit server advertisement (`0x09`). Genuine mask bits `0x40`
and `0x80` have no identified consumer in the examined controller corpus and
remain reference evidence rather than operational claims.

## Projection status

| Behavior | Status |
|---|---|
| Read NUT variables with bounded protocol handling | **PROVEN** by automated fake-server tests |
| Normalize standard UPS status/battery/load fields | **PROVEN** by unit tests |
| Map direct nominal real power and preserve standard beeper states | **PROVEN** by unit tests; current APC driver exposes neither value |
| Encode/decode uncompressed TNBU v0 CBC and GCM packets | **PROVEN** by exact-firmware analysis and codec tests; live controller acceptance tracked separately |
| Emit the exact `USWDA26` discovery shape | **PROVEN** on wire to the target UDM; registration evidence is build-specific and listed separately |
| Reach and pass TNBU/JSON/MAC parsing on Network 10.6.101 | **PROVEN**; controller returns unknown-device HTTP 404 |
| Adopt and pair through `/inform` | **OBSERVED** in a redacted Network 10.6.102 interoperability sample; the older 10.6.101 test remained a 404 |
| Volatile plain-HTTP GCM `cfgversion` synchronization | **CANDIDATE**; explicit default-off compatibility option with automated coverage, pending live rename-recovery acceptance |
| Multi-field configuration receipts, with optional persistence | **CANDIDATE**; automated parser/storage/restart coverage, pending exact-build Online/rename/restart acceptance |
| Project NUT-observed outlet count, groups, USB type, and meter capability | **CANDIDATE**; automated coverage only, no topology-capable live source acceptance yet |
| Advertise an independently verified NUT service at the emulated device IP | **CANDIDATE**, explicit opt-in only; default disabled |
| Trigger UniFi OS shutdown policy from NUT battery state | **BLOCKED_EXTERNAL** until a controlled outage simulation |
| Execute any controller-requested outlet/zone operation | deliberately unsupported in v1; no NUT write API |

## Public interoperability references

Wire-format behavior was independently compared against:

- [Network UPS Tools variable namespace](https://github.com/networkupstools/nut/blob/master/docs/nut-names.txt)
- [jamesbraid/unifi-emu](https://github.com/jamesbraid/unifi-emu) (MIT)
- [amd989/unifi-gateway](https://github.com/amd989/unifi-gateway) (MIT)
- [jeffreykog/unifi-inform-protocol](https://github.com/jeffreykog/unifi-inform-protocol)
- [fxkr/unifi-protocol-reverse-engineering](https://github.com/fxkr/unifi-protocol-reverse-engineering)

They are references, not runtime dependencies. This project ships a
standard-library-only implementation and does not incorporate AGPL code.
