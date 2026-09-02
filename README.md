# NUT 2 UniFi UPS Gateway

`nut-2-unifi-ups-gateway` projects telemetry from an existing
[Network UPS Tools](https://networkupstools.org/) server into the narrow UniFi
discovery and inform surface used by UniFi UPS devices. The default profile is
**UniFi UPS 2U EU** (`USWDA26`), whose fixed eight-outlet layout presents two
relay groups of four outlets. An experimental **UPS 2U Pro EU** (`USPDA2C`)
profile preserves that model's nine-outlet topology. The purpose is
to let UniFi Network evaluate UPS-backed shutdown policies without replacing a
standards-compliant UPS integration.

> [!WARNING]
> This is an independent, experimental compatibility project. It is not made,
> supported, or endorsed by Ubiquiti. Never rely on it as the only protection
> for storage or safety-critical loads.

## Safety model

- Gateway v1 is telemetry-only.
- Gateway v1 contains no NUT write-command API. Controller power requests are
  parsed for protocol visibility and ignored without touching the upstream UPS.
- Stale or malformed NUT state becomes unavailable; it is never reported as a
  healthy battery.
- Secrets, full device identities, packet captures, and controller replies are
  not logged.

The default emulated layout contains eight outlets: indices 1–4 have relay
group 1 and indices 5–8 have relay group 2. This topology does not claim that
the upstream NUT driver can switch either group. See
[Power-write boundary](docs/architecture.md#power-write-boundary).

## Data path

```text
NUT upsd :3493          NUT 2 UniFi UPS Gateway          UniFi Network
LIST VAR ups  ───────▶  normalized UPS snapshot  ─────▶ UDP discovery :10001
                                                  └────▶ HTTP POST /inform :8080
                                                           │
                                                           ▼
                                                UniFi OS shutdown policy
```

The gateway does **not** proxy NUT to the network and does not emulate the real
UPS maintenance, OTA, log-download, or proprietary TLS adoption endpoints.

## Compatibility status

The NUT ingestion, eight-outlet projection, discovery datagrams, TNBU codec,
and controller reachability are live-validated on Synology DSM 7.3.2 and a UDM
running UniFi OS 5.1.31 / Network 10.6.101. That controller currently accepts
the request through TNBU/JSON/MAC parsing but returns its unknown-device HTTP
404 and creates no pending record. Adoption and shutdown-policy execution are
therefore **not yet demonstrated** on that release. See the exact negative
evidence and ruled-out hypotheses in
[Protocol evidence](docs/protocol-evidence.md#unifi-network-controller-observations).

## Container

The release image is a static Go binary in `scratch`, declares UID/GID `65532`,
and has no shell or package manager. The provided Compose deployment also drops
every Linux capability and makes the root filesystem read-only. Published
platforms are:

- `linux/amd64` (x86_64)
- `linux/arm64` (AArch64)
- `linux/arm/v7` (ARMv7)
- `linux/386` (i386)

Image visibility follows the GHCR package setting. A private initial release
requires `read:packages` authentication; no registry credential belongs in the
Compose file.

On Synology, host networking is intentional: it lets the unprivileged process
reach the NAS-local NUT server at `127.0.0.1:3493` and emit UniFi L2 discovery
without changing DSM's NUT ACL. No host port below 1024 is opened.

```bash
cp deploy/synology/.env.example deploy/synology/.env
docker compose --env-file deploy/synology/.env \
  -f deploy/synology/compose.yaml up -d
```

Set `N2U_INFORM_URL` to the controller's final explicit IPv4 `/inform` URL.
Adoption identity and the negotiated inform key persist in the `state` volume.

> [!IMPORTANT]
> Perform first adoption only on a trusted management LAN. Before adoption,
> firmware compatibility requires a public AES key and CBC, while the common
> controller endpoint is plain HTTP. A LAN attacker can read initial telemetry
> or forge a response that changes the next key. Configure the controller's
> exact origin in advance; the gateway refuses controller-directed origin
> changes. Prefer HTTPS only when its certificate chain is verifiable by the
> container.

## Configuration

| Variable | Default | Purpose |
|---|---:|---|
| `N2U_NUT_ADDRESS` | `127.0.0.1:3493` | NUT TCP endpoint |
| `N2U_NUT_UPS` | `ups` | NUT UPS name |
| `N2U_UNIFI_MODEL` | `USWDA26` | 8-outlet `USWDA26` or 9-outlet `USPDA2C` |
| `N2U_UNIFI_VERSION` | `1.6.1` | Selects the pinned firmware-proven 1.6.1 profile |
| `N2U_NUT_USERNAME` | empty | Optional NUT login |
| `N2U_NUT_PASSWORD_FILE` | empty | File containing the optional NUT password |
| `N2U_INFORM_URL` | `http://unifi:8080/inform` | Initial controller inform URL |
| `N2U_DEVICE_MAC` | generated once | Optional locally administered unicast MAC |
| `N2U_DEVICE_SERIAL` | derived once | Optional stable serial |
| `N2U_DEVICE_IP` | route-derived | Optional advertised IPv4 address |
| `N2U_POLL_INTERVAL` | `5s` | Upstream poll interval |
| `N2U_STALE_AFTER` | `20s` | Maximum telemetry age |
| `N2U_HEALTH_ADDRESS` | `127.0.0.1:9199` | Health and metrics listener |

Every supported variable and the fixed outlet-topology rules are documented in
[Configuration](docs/configuration.md).

## Health and observability

- `GET /healthz`: process liveness
- `GET /readyz`: readiness based on fresh NUT telemetry
- `GET /metrics`: identity-free Prometheus counters and gauges

An HTTP 404 from `/inform` establishes controller reachability but not a
successful inform or adoption. It increments `n2u_inform_pending_total`, not
`n2u_inform_errors_total`. Initial 404 responses are common while adoption is
pending; a persistent 404 can also indicate an unrecognized device profile and
must be checked in UniFi Network.

## Project status

Protocol behavior is tracked with four evidence labels: `PROVEN`, `CANDIDATE`,
`UNKNOWN`, and `BLOCKED_EXTERNAL`. See the
[protocol evidence matrix](docs/protocol-evidence.md) before using the gateway
with a different UPS or Network release.

## Development

The runtime uses only the Go standard library.

```bash
make check
```

CI tests with the race detector, vets the source, cross-compiles all four target
architectures, and builds the multi-platform container. Tagged releases publish
an SBOM and build-provenance attestations with the image.

Contributions are welcome; read [CONTRIBUTING.md](CONTRIBUTING.md) and
[SECURITY.md](SECURITY.md) first.

## License

Copyright (C) 2026 d3vi1. Licensed under [GPL-2.0-only](LICENSE).
