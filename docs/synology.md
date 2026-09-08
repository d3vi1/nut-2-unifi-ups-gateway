# Synology Container Manager

A DiskStation is a NAS, not the UPS appliance itself. Use `separate` mode so
the NAS keeps its existing LAN identity and the gateway gets its own IP/MAC.
Do not use `shared` on DSM to work around container networking.

## Choose the compatible template

Check the versions supplied by Container Manager:

```sh
docker version --format '{{.Server.Version}}'
docker compose version --short
```

The executable may not be on a non-interactive SSH PATH; use the Docker executable
supplied by Container Manager. Do not install a second engine.

- Compose **2.23.2 or newer**: base `compose.yaml`.
- Compose **2.20.x with Engine 24**: alternate base `compose.legacy.yaml`.
  It puts the MAC at service level and gives the LAN attachment highest priority.
  It is not an overlay: never combine it with `compose.yaml`.
- Other older combinations need validation first; never fall back to the old
  host-network template or add privileges to make validation pass.

The alternate base differs only in version-specific MAC placement and attachment
priority. Priority does not select a default route or guarantee an `eth0` name.
Both bases have the same runtime, state volume and hardening. Per-network MACs
are preferred on newer engines; see
[Docker's Compose reference](https://docs.docker.com/reference/compose-file/services/#mac_address).

## Prepare and migrate

Follow [dedicated LAN preparation](installation.md#prepare-the-dedicated-lan-network)
and [migration from 0.9.0](installation.md#migrate-from-host-networking). Network
creation is an administrator action; the gateway does not alter the NAS network.
Choose the actual existing LAN parent interface, which may be an OVS or bond
interface on DSM rather than `eth0`. Do not create VLAN interfaces or change
bond/OVS settings merely to match an example.

Keep the existing Compose project name and original state volume. Preserve the
already-adopted UPS MAC, configure it as the real macvlan endpoint MAC, and reserve
a **different unused IP** from the NAS. Do not print adoption state or change the
NAS MAC. Stage the version-matched bundle separately from the active `.env`.

## Reading NUT on the same NAS

Macvlan cannot directly contact its host's LAN address. Add the optional
`compose.nut-host.yaml` overlay and follow the
[internal bridge instructions](installation.md#nut-on-the-same-host).
For example, after an administrator has provisioned and checked a non-overlapping
internal bridge (replace all synthetic values):

```dotenv
N2U_NUT_HOST_NETWORK=n2u-nut-host
N2U_NUT_HOST_IP=172.30.90.2
N2U_NUT_ADDRESS=172.30.90.1:3493
N2U_NUT_UPS=ups
N2U_NUT_ALLOW_INSECURE_REMOTE=true
N2U_UNIFI_NUT_SERVER_ENABLED=false
```

The upstream must already listen on the bridge gateway or a suitable wildcard
address, and its ACL plus DSM firewall must permit that bridge-side client IP.
The plaintext opt-in is required even on this private bridge. A loopback-only
server cannot be reached by this arrangement. Do not silently change DSM UPS
files, firewall rules or service bindings; stop and review an administrator-owned
NUT access plan if these prerequisites are absent.

For the older compatible base:

```sh
docker compose --env-file .env -f compose.legacy.yaml -f compose.nut-host.yaml config --quiet
docker compose --env-file .env -f compose.legacy.yaml -f compose.nut-host.yaml pull
docker compose --env-file .env -f compose.legacy.yaml -f compose.nut-host.yaml up -d
docker compose --env-file .env -f compose.legacy.yaml -f compose.nut-host.yaml exec -T gateway /nut-2-unifi-ups-gateway healthcheck
```

Use the same base and overlays for every command. Add `-f compose.auth.yaml` if
NUT requires a credential file. Select that exact file combination if managing
the project in DSM's UI; if the UI cannot select multiple files, administer this
project through its bundled Compose CLI rather than creating another project.

There is no shell, NUT proxy or downstream NUT server in the container. Health
loopback now belongs to the container, not the NAS. Network's **NUT Server**
advertisement must remain off unless a separate service is independently
verified at the gateway's new LAN IP.

## Validate before relying on it

The process runs as UID/GID `65532:65532` with dropped capabilities. Some DSM
kernels do not enforce the requested PIDs limit; this is not a reason to make the
container privileged. Keep the NAS's existing UPS shutdown protection.

Configuration parsing is only a schema check. Real MAC/IP assignment, host NUT
reachability, Online state, separate NAS visibility and expected pairings must
be checked in an agreed live maintenance window. Physical shutdown testing is
separate. See [compatibility](compatibility.md), [update](installation.md#update)
and [rollback](installation.md#roll-back). Never use `--volumes` or delete state
as a migration step.
