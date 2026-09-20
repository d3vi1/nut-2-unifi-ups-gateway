# Managed addressing: DHCP or static (candidate for 0.9.1)

This optional `separate` deployment lets the emulated UPS obtain its own LAN
address from your DHCP server. With a UniFi Gateway, reserve that address for
the UPS MAC in Network. You do not have to copy the resulting lease into Compose.

**Experimental, with one observed deployment:** a Synology amd64 installation
on Engine 24 / Compose 2.20.x completed DHCP migration and full two-service
recreation while retaining its adopted identity. The operator confirmed Online
state and both existing pairings. This is not general host compatibility or
proof of shutdown; keep the existing NUT protection and validate your own setup.

## What changes

The UPS gateway remains a static, non-root Go program with no capabilities and
no power-command path. A separate `netagent` container configures its LAN
interface using Go and Linux system calls. That helper runs as root with only
`NET_ADMIN`, `NET_RAW`, and `NET_BIND_SERVICE`. It receives no adoption-state
mount or NUT credential file/environment variable. However, the shared network
namespace lets it observe plaintext NUT traffic, including credentials if used.
The helper is trusted network infrastructure, not a confidentiality boundary
against the gateway. Neither container gets the Docker socket.

DHCP and ARP do not authenticate their peers. Use a trusted, controlled LAN:
transaction and MAC checks reject unrelated replies, not an on-link attacker
who observes them. A rogue DHCP server can redirect off-subnet traffic or deny
service. Static addressing avoids DHCP server selection but does not prevent
ARP spoofing. The gateway's plaintext-NUT opt-in remains required for remote NUT.

The helper supplies a short-lived address heartbeat. The gateway validates the
real interface and its saved MAC, then uses that address for discovery/INFORM.
It stops on heartbeat loss, address changes, or lease expiry. Linux also expires
the address within four seconds without refresh, even if the helper is killed.
An unchanged renewal does not restart the gateway. Adoption state stays in the
existing `state` volume. A DHCP lease is never treated as permanent saved state.

## Docker prerequisite — important

Docker's built-in macvlan IPAM does not acquire external DHCP leases. The
candidate deployment therefore requires a **dedicated existing internal macvlan
network with bootstrap subnet `169.254.254.0/24`**, IPv6 disabled, and the correct
physical LAN parent. The helper removes only that link-local bootstrap address
and configures the LAN address itself. It refuses arbitrary pre-existing global
addresses, non-macvlan interfaces, and unrelated default routes.

This is an explicit handoff away from Docker address management: **Docker
inspect continues to show the bootstrap address, not the DHCP lease.** Do not
use that address for monitoring, published ports, Docker DNS, or service
discovery. The controller sees the actual address. This nonstandard behavior,
including container recreation, is a release gate on the exact Docker version.

Some Engine 24 multi-network deployments also ignore the requested endpoint
MAC. If that MAC is absent, the helper accepts only one active macvlan with
exactly the dedicated bootstrap IPv4 address and no unexpected routes/addresses.
It applies the configured adopted MAC and verifies kernel readback **before**
removing bootstrap addressing or starting DHCP. Ambiguous links are rejected;
the host-NUT bridge is never a fallback candidate. Docker's recorded MAC can
therefore differ from the active MAC too; verify the kernel interface and the
identity reported to Network, not Docker inspection alone.

The application never creates the host network, changes its parent interface,
changes firewall rules, or edits DHCP server configuration. Network provisioning
is a separate operator-controlled step; never reuse the static template's LAN
network. Do not use host networking or `privileged: true`.

After checking the existing LAN parent and Docker subnets, an administrator can
provision the dedicated bootstrap network (replace `eth0` with the actual parent):

```sh
docker network create --driver macvlan --internal \
  --subnet 169.254.254.0/24 --opt parent=eth0 n2u-managed-lan
```

The bootstrap subnet is part of the helper's contract, not your production LAN
subnet. Do not enable IPv6 on this Docker network. Verify that the real LAN
permits multiple MACs and that DHCP serves the intended management network.

## Configuration

Use `compose.managed.yaml` **instead of** either existing base template. Keep
the project name, state volume, and existing adopted MAC unchanged during
migration. Stop the old instance before starting another with its identity.

Set these in your private Compose `.env`, alongside your image digest, NUT
settings and controller URL:

```dotenv
N2U_DEVICE_MAC=02:00:00:00:00:30
N2U_LAN_NETWORK=n2u-managed-lan
N2U_NET_MODE=dhcp
```

The MAC above is an example, not a fleet default. Do not set `N2U_DEVICE_IP` for
managed addressing. For static configuration instead:

```dotenv
N2U_NET_MODE=static
N2U_NET_STATIC_CIDR=192.0.2.30/24
N2U_NET_ROUTER=192.0.2.1
```

These addresses are documentation examples. Use a real, available address
outside the dynamic pool (or excluded/reserved in your DHCP configuration).
Static configuration lives in your private `.env` and survives recreation;
DHCP reacquires its lease after every helper restart.

For this first managed implementation, **NUT and controller targets must use
IPv4 literals**. DHCP DNS, domain search, classless routes and IPv6 are not
implemented. The DHCP client requires a contiguous /1–/30 subnet, one on-link
router and a finite lease of 30 seconds to seven days. Unsupported or ambiguous
options fail closed. It performs address-conflict probes before assignment;
conflicts during operation withdraw the address rather than defend it.

Network's UPS **IP Settings → Static** remains unsupported: acknowledging an
INFORM configuration marker does not apply its network settings. Configure
static addressing through `.env`, or use a DHCP reservation in Network.

## NUT on the same NAS

Macvlan cannot directly reach its host's parent LAN address. The optional
`compose.managed-nut-host.yaml` overlay attaches an **existing internal bridge**
to `netagent`; the gateway can then reach the host NUT service through the bridge
gateway IP. Set `N2U_NUT_HOST_NETWORK`, `N2U_NUT_HOST_IP`,
`N2U_NUT_HOST_GATEWAY`, and `N2U_NUT_ADDRESS`
explicitly. NUT must already listen there and permit that source. The helper
never readdresses the bridge interface. Do not use `127.0.0.1` for host NUT.

On the tested Engine 24 build, Docker still installs a default route through
this internal bridge. The overlay explicitly supplies its client IP and gateway
to the helper (`N2U_NET_AUX_ADDRESS` / `N2U_NET_AUX_ROUTER`). Only that exact
Docker route shape on the uniquely matching veth endpoint may be removed after
complete network validation. Other defaults remain fatal. The bridge MAC,
address and connected route are preserved; no host route or firewall is edited.
Do not omit the gateway value or infer it from the NUT server address.

Recreate the two services together when changing networks or the helper's
container identity. Compose startup ordering does not provide runtime health
coupling; the gateway's own heartbeat guard supplies fail-closed behavior.

## Start, update and recover

Use the verified version-matched release bundle and retain its image digest.
Keep the same base and overlays in every command. For same-host NUT:

```sh
docker compose --env-file .env -f compose.managed.yaml -f compose.managed-nut-host.yaml config --quiet
docker compose --env-file .env -f compose.managed.yaml -f compose.managed-nut-host.yaml pull
docker compose --env-file .env -f compose.managed.yaml -f compose.managed-nut-host.yaml up -d
docker compose --env-file .env -f compose.managed.yaml -f compose.managed-nut-host.yaml ps
docker compose --env-file .env -f compose.managed.yaml -f compose.managed-nut-host.yaml exec -T gateway /nut-2-unifi-ups-gateway healthcheck
```

For remote NUT, omit the host overlay. For authenticated NUT, add
`-f compose.auth.yaml`; the secret is mounted only into the gateway. See the
[password-file instructions](installation.md#authenticated-nut).

For a planned update that recreates the network owner, first back up the stopped
gateway's state and private configuration. Stop `gateway` and `netagent` using
the same file combination, then run `up -d --force-recreate` for both services.
Do not recreate only `netagent`: the old gateway container may retain its former
network namespace. Do not run the old and new deployments concurrently.
Preserve the project name and named state volume; never use `down --volumes`.

Allow time for startup, DHCP and conflict probes. Check process health, fresh
NUT telemetry, the actual LAN address in Network, separate host/UPS identities,
Online state and pairings. The healthcheck alone proves only process health.
If setup fails, stop both services and restore the complete prior private
deployment set with the same state volume; do not reset adoption. A rollback to
0.9.0 also restores its old shared-IP limitation, so it is recovery, not a fix
for that identity conflict.

## Required validation before promotion

The later production-code revision `486800c` added narrow Engine 24 MAC and
auxiliary-default compatibility handling. The target deployment subsequently
passed DHCP migration and full two-service recreation, and its operator
confirmed Online state and retained pairings. The `c68625b` test-only follow-up
passed CI including the isolated Linux network lab and four-platform builds.
The deployed local candidate is not a published, attested GHCR release image.
No controller DHCP reservation or physical shutdown test was performed by these
checks. Static mode, other hosts and broader failure scenarios remain separate
validation work.

At code revision `e24c5ea`, CI built all four architectures and the isolated
Synology lab passed acquisition, unicast renewal, broadcast rebinding, expiry,
static configuration, logical helper restart and frozen-helper address expiry.
The lab had no production LAN, upstream NUT or controller access. A logical
helper restart is **not** proof of Docker service recreation or retained pairings.
The exact-code adversarial review produced no confirmed vulnerabilities; that
is not a guarantee of production readiness.

- Synthetic DHCP: discover/offer/request/ACK, T1 renewal, T2 rebinding, NAK,
  loss of server, expiry, invalid options and conflicts; no production LAN.
- Helper kill/restart and complete stack recreation; no stale advertisement,
  accidental IP reuse, lost adoption state or changed MAC.
- Static addressing and optional host-NUT bridge preserve other interfaces.
- Your host's actual lease, identity, adoption, pairings and topology, including
  rollback with the same state. A DHCP reservation is optional and must be
  configured and checked separately by the network administrator.
- Exact-patch Daybreak/security review, documentation review, race/vet tests,
  four architecture builds, then the separately gated 0.9.1 publication.

Protocol references: [DHCP (RFC 2131)](https://www.rfc-editor.org/rfc/rfc2131),
[IPv4 conflict detection (RFC 5227)](https://www.rfc-editor.org/rfc/rfc5227).
