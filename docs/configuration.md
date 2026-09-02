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
| `N2U_UNIFI_MODEL` | `USWDA26` | `USWDA26` or `USPDA2C` |
| `N2U_UNIFI_VERSION` | `1.6.1` | `1.6.1` or the exact selected build (`1.6.1.413`/`1.6.1.4933`) |
| `N2U_INFORM_URL` | `http://unifi:8080/inform` | HTTP(S), `/inform`, no credentials/query/fragment |
| `N2U_INFORM_INTERVAL` | `10s` | 1 second–10 minutes; local maximum even if the controller asks for longer |
| `N2U_INFORM_TIMEOUT` | `10s` | 1 second–1 minute |
| `N2U_DISCOVERY_INTERVAL` | `30s` | 5 seconds–10 minutes |
| `N2U_DEVICE_MAC` | generated | six-byte unicast MAC |
| `N2U_DEVICE_SERIAL` | derived | stable non-empty identifier |
| `N2U_DEVICE_HOSTNAME` | `nut-2-unifi-ups-gateway` | 1–63 characters |
| `N2U_DEVICE_IP` | route-derived | IPv4 only |

Set the final controller origin before first startup. Adoption may update the
path/configuration at that exact origin, but hostname, address, scheme, and port
changes are rejected rather than accepted through a DNS-equivalence check.
Positive controller intervals shorter than `N2U_INFORM_INTERVAL` are honored;
longer values are capped at this operator-controlled maximum.

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

## Outlet topology and control

`USWDA26` always reports the firmware-proven eight outlets in two relay groups
of four. It is a fixed UniFi topology, not evidence that the NUT source exposes
two controllable banks. Gateway v1 is telemetry-only and rejects unknown
`N2U_` variables, including proposed control/command settings.
