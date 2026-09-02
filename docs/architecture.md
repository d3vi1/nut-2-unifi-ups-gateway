# Architecture

## Scope

The gateway is an application-layer projection, not a virtual power device. It
reads one NUT UPS, retains a bounded normalized snapshot, and serializes that
snapshot into one of two explicit model profiles: eight-outlet `USWDA26` or
nine-outlet `USPDA2C`.

The runtime has five deliberately small components:

1. A bounded NUT line-protocol client.
2. A normalizer that makes missing and stale telemetry explicit.
3. A persistent UniFi identity/adoption state machine.
4. UniFi discovery and encrypted inform codecs.
5. An identity-free health/metrics endpoint.

Only the state file is writable. It contains the generated identity and UniFi
inform key, is written atomically with mode `0600`, and belongs on a private
persistent volume.

## Why host networking on Synology

Synology's local `upsd` may restrict client addresses. A bridge container has a
different source address even when it targets the NAS, while host networking can
use loopback exactly as a local client. UniFi discovery also uses UDP broadcast.

Host networking does not require root here: NUT uses TCP/3493, discovery uses
UDP/10001, and the health endpoint uses TCP/9199. The container drops all
capabilities and never binds a privileged port.

## Power-write boundary

The default `USWDA26` profile has eight UniFi outlets:

| UniFi outlet | Relay group | Upstream action in v1 |
|---:|---:|---|
| 1–4 | 1 | none |
| 5–8 | 2 | none |

The firmware-proven `relayctl` message is not an on/off setter. Every table
entry independently schedules an OFF→ON power cycle, and a multi-entry request
has no transaction or rollback. The analyzed `setparam` outlet keys update only
desired configuration; they do not prove immediate relay actuation.

The Synology APC driver exposes only UPS-wide power commands and no outlet
variables. Mapping either a single UniFi outlet or a four-outlet relay group to
a global NUT command could drop every attached load. Gateway v1 therefore has
no NUT command method, no control environment variable, and no controller path
that can write to the UPS. `relayctl` is decoded and logged only as an ignored
request count, without identities or command contents.

The optional `USPDA2C` profile exposes all nine outlets mandated by the
controller's model database. It is not a way to force an eight-outlet physical
layout into the Pro model.

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

The genuine firmware sends discovery broadcasts but does not listen on
UDP/10001. The gateway follows that send-only behavior.

The outbound inform endpoint on controller TCP/8080 is unrelated to the real
UPS's inbound maintenance listener on the same numeric port.
