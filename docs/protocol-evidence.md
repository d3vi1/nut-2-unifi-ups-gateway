# Protocol evidence

This document separates observations from compatibility assumptions. No
Ubiquiti firmware, extracted executable, controller database, packet capture,
credential, or device identity is distributed by this repository.

## Evidence labels

- **PROVEN**: observed in the exact firmware/controller build or an executed
  interoperability test.
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

The firmware contains no supported evidence for SSH, Telnet, LLDP, mDNS/DNS-SD,
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

Live tests against this exact target also establish an important negative
boundary. Network received and decrypted TNBU v0/CBC requests, passed JSON,
payload-version, and header/payload-MAC validation, then returned HTTP 404 from
its unknown-device dispatch. No targeted `device` or `pending_device` record
was created. The same result held after all of these one-variable checks:

- the fixed firmware profile GUID and coherent `hash_id`/`anon_id`;
- the firmware HTTP header fingerprint;
- a collision-checked Ubiquiti OUI;
- a unique macvlan IPv4/MAC pair with verified UDP/10001 and TCP/8080 traffic.

The active controller catalogs contain the `USWDA26`/`0xDA26` definition and
exact `1.6.1.413` firmware. The unresolved gate is therefore current
controller-private unknown-device/model dispatch, not TNBU decryption or the
known UPS identity fields. Further payload guessing is explicitly out of
scope; resolving it requires temporary controller DEBUG evidence or a real UPS
capture on the same Network release.

## Exact eight-outlet profile

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

## Power-control evidence

Firmware `relayctl` entries contain a 1-based index plus delay-to-off and
delay-to-on in minutes. Each entry schedules an independent OFF→ON cycle; an
array is processed sequentially without atomic prevalidation or rollback. It
does not read `relay_state`. `system_cfg` outlet relay keys change desired
configuration only and do not prove immediate actuation. The gateway therefore
parses `relayctl` but ships no NUT write API.

## Projection status

| Behavior | Status |
|---|---|
| Read NUT variables with bounded protocol handling | **PROVEN** by automated fake-server tests |
| Normalize standard UPS status/battery/load fields | **PROVEN** by unit tests |
| Encode/decode uncompressed TNBU v0 CBC and GCM packets | **PROVEN** by exact-firmware analysis and codec tests; live controller acceptance tracked separately |
| Emit the exact `USWDA26` discovery shape | **PROVEN** on wire to the target UDM; controller registration still unresolved |
| Reach and pass TNBU/JSON/MAC parsing on Network 10.6.101 | **PROVEN**; controller returns unknown-device HTTP 404 |
| Adopt and remain connected through `/inform` | **UNKNOWN** on Network 10.6.101; zero device/pending records after controlled A/B tests |
| Trigger UniFi OS shutdown policy from NUT battery state | **BLOCKED_EXTERNAL** until a controlled outage simulation |
| Execute any controller-requested outlet/zone operation | deliberately unsupported in v1; no NUT write API |

## Public interoperability references

Wire-format behavior was independently compared against:

- [jamesbraid/unifi-emu](https://github.com/jamesbraid/unifi-emu) (MIT)
- [amd989/unifi-gateway](https://github.com/amd989/unifi-gateway) (MIT)
- [jeffreykog/unifi-inform-protocol](https://github.com/jeffreykog/unifi-inform-protocol)
- [fxkr/unifi-protocol-reverse-engineering](https://github.com/fxkr/unifi-protocol-reverse-engineering)

They are references, not runtime dependencies. This project ships a
standard-library-only implementation and does not incorporate AGPL code.
