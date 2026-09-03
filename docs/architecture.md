# Architecture

## Scope

The gateway is an application-layer projection, not a virtual power device. It
reads one NUT UPS, retains a bounded normalized snapshot, and serializes that
snapshot with one of two controller-recognized carrier identities: `USWDA26` or
`USPDA2C`. The selected identity routes the report into UniFi Network's UPS
flow; it does not select or constrain the projected NUT outlet topology.

The runtime has five deliberately small components:

1. A bounded NUT line-protocol client.
2. A normalizer that makes missing and stale telemetry explicit.
3. A persistent UniFi identity/adoption state machine.
4. UniFi discovery and encrypted inform codecs.
5. An identity-free health/metrics endpoint.

Only the private state volume is writable. The process atomically replaces the
`0600` state file and may create temporary siblings in that directory; the file
contains the generated identity and UniFi inform key.

## Why host networking on Synology

Synology's local `upsd` may restrict client addresses. A bridge container has a
different source address even when it targets the NAS, while host networking can
use loopback exactly as a local client. UniFi discovery also uses UDP broadcast.

Host networking does not require root here: NUT uses TCP/3493, discovery uses
UDP/10001, and the health endpoint uses TCP/9199. The supplied Compose
deployment drops all capabilities, and the process never binds a privileged
port. The identity-free health server also limits aggregate accepted
connections in addition to per-request timeouts.

## Outlet-topology projection

The gateway treats NUT as the source of outlet topology when it supplies a
valid, bounded, positive `outlet.count`:

1. It creates exactly the observed number of outlet records.
2. It treats `outlet.N.groupid` as an opaque native identifier. Equal values
   form one group, and first occurrence assigns deterministic, dense, positive
   UniFi `relay_group` numbers. An outlet without `groupid` receives its own
   singleton group. `outlet.group.G.*` metadata or status is associated only
   when `outlet.group.G.id` exactly matches that opaque identifier and its
   optional count agrees with membership; a numeric identifier is never assumed
   to equal the group-table index. Every member row reports the same group relay
   state. A directly matched group status may supply it; otherwise conflicting
   or incomplete member facts make it unknown.
3. It recognizes an outlet as USB only when `outlet.N.type` or
   `outlet.N.designator` is unambiguously a USB form. Names and descriptions do
   not classify an outlet. Every other value receives an AC-compatible wire
   projection; this is an interoperability fallback, not proof of the physical
   receptacle type.
4. It adds `HAS_RELAY` only from an affirmative NUT `switchable=yes` fact on
   the outlet, its exactly matched group, or the global outlet collection. It
   adds `POWER_METER` only when that outlet directly exposes `current`,
   `realpower`, or apparent `power`. It never infers `AUTO_RELAY` or the
   unresolved low-order bit 3, and it does not invent a physical button group.
5. It projects only outlet-scoped voltage, current, real-power, and power-factor
   samples that parse successfully. Apparent power can establish meter
   capability but is not mislabeled as real watts. UPS-wide and outlet-group
   values are never divided, duplicated, or otherwise apportioned among member
   outlets.

If `outlet.count` is absent or invalid, the runtime uses a conservative carrier
fallback. `USWDA26` keeps eight AC-compatible rows in two 4+4 groups;
`USPDA2C` keeps nine AC-compatible singleton groups. It does not copy the real
device's relay, automatic-relay, metering, button, or per-outlet-state bits.
This preserves a deterministic UPS-flow shape for drivers such as the current
Synology APC driver, which publishes no `outlet.*` variables. The dynamic path
is **CANDIDATE**: it is unit-testable but has not yet been accepted live by
Network with a topology-capable NUT driver.

The logical project name may be described as `NUTUPS`, but the gateway does not
send `model="NUTUPS"`. The stock Network registry and dispatch path require a
known model identity; unknown names reach the unknown-device path. `USWDA26`
and `USPDA2C` are therefore wire carriers only and are not topology templates.

The carrier still owns Network's physical illustration. In the installed
Network 10.6.102 catalog, `USWDA26` statically labels outlets 1–4 as standard
battery-backed outlets, 5–8 as surge outlets, and two additional RJ45 jacks as
Surge In/Out. Those categories are not computed from `outlet_table` or
`outlet_caps`; a NUT projection cannot override them without a neutral
controller model.

UPS-wide electrical data follows units, not visual convenience. Direct
`ups.realpower` and `ups.realpower.nominal` become output and budget watts.
`output.current` is copied with the precision NUT supplied. Apparent VA, load
percentage, and voltage multiplied by current are not presented as real watts.

## Power-write boundary

The no-topology fallbacks expose these descriptive groups:

| Carrier | UniFi outlet | Relay group | Upstream action in v1 |
|---|---:|---:|---|
| `USWDA26` | 1–4 | 1 | none |
| `USWDA26` | 5–8 | 2 | none |
| `USPDA2C` | 1–9 | one group per outlet | none |

The firmware-proven `relayctl` message is not evidence of safe per-outlet or
per-group switching. In the analyzed UPS26 path, outlet index, relay group, and
requested relay state do not address an individual relay; the delay fields lead
to a global UPS power cycle. The analyzed `setparam` outlet keys update only
desired configuration; they do not prove immediate relay actuation.

The Synology APC driver exposes only UPS-wide power commands and no outlet
variables. Mapping either a single UniFi outlet or a four-outlet relay group to
a global NUT command could drop every attached load. Gateway v1 therefore has
no NUT command method, no control environment variable, and no controller path
that can write to the UPS. `relayctl` is decoded and logged only as an ignored
request count, without identities or command contents.

Observed NUT `groupid` values therefore describe topology only. UniFi relay
requests are decoded for protocol visibility and ignored; they never become a
NUT command, whether a group contains one outlet or many.

The device-level smart-power bitmap uses a fail-closed allowlist. Only
controller-owned safe-shutdown timing is advertised by default (`0x08`);
explicit external NUT-service metadata adds information access (`0x09`). Power
Cycle on AC Recovery, buzzer control, EPO, and unresolved genuine-firmware bits
`0x40`/`0x80` are omitted. Power Cycle on AC Recovery is a controller/firmware
policy bit, not the separate `outlet_caps.AUTO_RELAY` bit, and NUT exposes no
lossless persistent equivalent. Observed `ups.beeper.status` may be retained,
but status alone does not authorize `beeper.enable` or `beeper.disable`.

The genuine UPS can itself listen as a NUT server. This gateway is normally
only a NUT client, so NUT information-access capability is also omitted by
default. An experimental operator opt-in may advertise a separately running,
credential-free service already verified at the emulated device IP. The
gateway still does not own that service's listener, authentication, or
lifecycle, and ignores controller attempts to change them.

## Intentionally omitted services

The genuine firmware contains authenticated maintenance and adoption services.
They are not required for the L3 inform adoption path and would add privileges,
credentials, and remotely reachable code without improving the shutdown-policy
use case. The gateway therefore does not implement:

- the proprietary TLS service on TCP/22 (it is not SSH);
- the HTTPS maintenance API on TCP/8080;
- firmware update, reset, reboot, or log-download operations;
- a STUN listener (the real firmware is a STUN client);
- SNMP, LLDP, mDNS, SSDP, Telnet, MQTT, or WebSocket services.

It also does not open a downstream TCP/3493 listener. The optional NUT Server
object is metadata about an independently verified co-located service, not a
listener implemented by this process.

The genuine firmware sends discovery broadcasts but does not listen on
UDP/10001. The gateway follows that send-only behavior.

The outbound inform endpoint on controller TCP/8080 is unrelated to the real
UPS's inbound maintenance listener on the same numeric port.
