# Managed addressing: DHCP or static (candidate for 0.9.1)

This optional `separate` deployment lets the emulated UPS obtain its own LAN
address from your DHCP server. With a UniFi Gateway, reserve that address for
the UPS MAC in Network. You do not have to copy the resulting lease into Compose.

**CANDIDATE, not yet accepted for production:** isolated Linux tests and an
adversarial code review have completed, but exact Synology/Network migration
and full container-recreation validation remain release gates.
Do not migrate a working installation solely because this template exists.

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

The application never creates the host network, changes its parent interface,
changes firewall rules, or edits DHCP server configuration. Network provisioning
is a separate operator-controlled step; never reuse the static template's LAN
network. Do not use host networking or `privileged: true`.

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
gateway IP. Set `N2U_NUT_HOST_NETWORK`, `N2U_NUT_HOST_IP`, and `N2U_NUT_ADDRESS`
explicitly. NUT must already listen there and permit that source. The helper
never readdresses the bridge interface. Do not use `127.0.0.1` for host NUT.

Recreate the two services together when changing networks or the helper's
container identity. Compose startup ordering does not provide runtime health
coupling; the gateway's own heartbeat guard supplies fail-closed behavior.

## Required validation before promotion

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
- Actual Synology lease, UDM reservation, adoption, pairings and topology,
  including rollback to the previous image/configuration with the same state.
- Exact-patch Daybreak/security review, documentation review, race/vet tests,
  four architecture builds, then the separately gated 0.9.1 publication.

Protocol references: [DHCP (RFC 2131)](https://www.rfc-editor.org/rfc/rfc2131),
[IPv4 conflict detection (RFC 5227)](https://www.rfc-editor.org/rfc/rfc5227).
