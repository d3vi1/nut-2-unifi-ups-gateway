# Install and maintain the gateway

This is the `separate` Docker Compose deployment for Linux, including Synology.
For a native daemon on a dedicated UPS appliance, use [shared mode](runtime-modes.md#shared-native-daemon).
It reads an existing NUT server; it does not replace that server or its shutdown
configuration. [Compatibility](compatibility.md) lists what has actually been tested.

These source-tree instructions target the **0.9.1 dedicated-network deployment**.
They are not evidence that the release is published or that migration has been
accepted live. Keep the immutable `v0.9.0` deployment set intact for reference
and rollback; its host-network instructions do not apply to the new templates.

## Before you start

Have rootful Docker Engine on Linux and Compose **2.23.2 or later** available
(or the [Engine 24 / Compose 2.20.x alternate template](synology.md)),
plus the NUT host/port, served UPS name
and UniFi Network console address. Use `upsc -l HOST` to find served names and
`upsc UPS@HOST` to check telemetry if NUT tools are installed on the host.
Do not post those raw results publicly.

The supplied deployment gives the gateway its own **macvlan LAN interface**,
IPv4 address and MAC. It requires a pre-created external Docker network; Compose
does not provision the host network. Docker Desktop and rootless engines are
unsupported by this deployment. The switch and physical interface must permit
multiple MAC addresses. See [Docker's macvlan requirements](https://docs.docker.com/engine/network/drivers/macvlan/)
and [per-network MAC support](https://docs.docker.com/reference/compose-file/services/#mac_address-1).

| Connection | Direction from gateway container | Purpose |
|---|---|---|
| NUT TCP/3493, or your configured port | outbound | Read UPS telemetry |
| Controller TCP/8080, or your configured inform port | outbound | UniFi inform |
| UDP/10001 broadcast | outbound only | Discovery on the management LAN |
| TCP/9199 on container loopback | inside container only | Health and diagnostics |

There is no discovery listener, SSH service or NUT listener to expose.
Do not expose NUT, inform or health to the internet. Keep initial adoption on a
trusted management LAN: its bootstrap key is public. Remote NUT has no STARTTLS;
credentials and telemetry are plaintext unless an independently secured network
carries them. [Security boundaries](../SECURITY.md).

## Prepare the dedicated LAN network

An administrator must select an existing physical LAN interface, its subnet and
gateway, and a **new confirmed-free IP** for the gateway. Keep the NAS/host's IP
and MAC assigned to the NAS/host. Exclude the gateway IP from DHCP allocation
or reserve it so no other device receives it. There is no DHCP client in the
container: a router reservation does not assign its address; Docker's static
`N2U_DEVICE_IP` does. Use a unique stable unicast `N2U_DEVICE_MAC`; for an adopted
gateway use its existing UPS MAC, read privately from Network's device panel.
Do not print state files to recover it.

The following is an **optional administrator provisioning example**, not an
installation script. All displayed addresses are documentation-only examples.
Replace the subnet, gateway, allocation range and existing parent interface
after reviewing the actual LAN and Docker networks. Reserve the complete Docker
allocation range against DHCP and other manual use:

```sh
docker network create --driver macvlan \
  --subnet 192.0.2.0/24 --gateway 192.0.2.1 \
  --ip-range 192.0.2.32/28 \
  --opt parent=eth0 n2u-lan
```

The selected static address below is outside that automatic Docker allocation
range but within the LAN subnet; reserve it separately. Use only an existing,
reviewed parent interface. Inspect the prepared network privately before use.
This is host administration: neither the gateway nor its Compose files changes
parent interfaces, host firewall policy or NUT configuration for you.

The runtime checks that the selected IP belongs to one active local Ethernet
interface with exactly the configured and saved device MAC. Conflicting or
ambiguous local identity stops startup before telemetry. Inform HTTP and
discovery use that IPv4 source. These checks cannot detect arbitrary NAT or
prove network-wide uniqueness: a dedicated direct-LAN interface, free address
and unique MAC remain the administrator's deployment contract.

## Download and verify

Use an empty project folder. Docker administration may require host privileges;
the process inside the container still runs as UID/GID `65532:65532`.

Download both files from the same published
[GitHub Release](https://github.com/d3vi1/nut-2-unifi-ups-gateway/releases).
Once the matching `v0.9.1` release is actually published:

```sh
release=v0.9.1
bundle="nut-2-unifi-ups-gateway-${release}-compose.tar.gz"
checksums="nut-2-unifi-ups-gateway-${release}-compose.SHA256SUMS"
release_url="https://github.com/d3vi1/nut-2-unifi-ups-gateway/releases/download/${release}"
curl -fL --proto '=https' --tlsv1.2 "$release_url/$bundle" -o "$bundle"
curl -fL --proto '=https' --tlsv1.2 "$release_url/$checksums" -o "$checksums"
sha256sum -c "$checksums"
tar -tzf "$bundle"
```

Stop on a failed download/checksum. The archive must contain exactly `.env`,
`compose.yaml`, `compose.legacy.yaml`, `compose.auth.yaml`, `compose.nut-host.yaml`,
`compose.managed.yaml`, `compose.managed-nut-host.yaml` and `RELEASE-METADATA.txt`
inside one versioned directory, plus that directory entry (eight files and one
directory entry). The managed templates remain candidates until their validation
gates pass. If that Release is absent, stop; do not
substitute development files or mix this contract with the `v0.9.0` bundle.

The checksum detects corruption, not compromise of the shared GitHub Release
trust root. The maintainer's [release safeguards](releasing.md) bind the image
and deployment files before publication. After verification, extract:

```sh
tar -xzf "$bundle" --strip-components=1
chmod 600 .env
```

Keep `N2U_IMAGE` unchanged: it pins the multi-platform manifest digest. Do not
replace it with `:edge`, `:latest` or a guessed version tag. The source-tree
`deploy/compose/.env.example` is deliberately a development example.

## Configure NUT and Network

Both base templates explicitly select `N2U_NETWORK_MODE=separate` inside the
container. They do not use the daemon's host identity or an automatic fallback.
With Compose 2.20.x and Engine 24, substitute `compose.legacy.yaml` for
`compose.yaml` in **every** command, adding the same optional overlays. Never
merge the two alternative base templates.

Edit `.env`:

```dotenv
N2U_LAN_NETWORK=n2u-lan
N2U_DEVICE_IP=192.0.2.30
N2U_DEVICE_MAC=02:00:00:00:00:30
N2U_NUT_ADDRESS=192.0.2.20:3493
N2U_NUT_UPS=ups
N2U_INFORM_URL=http://192.0.2.10:8080/inform
N2U_NUT_ALLOW_INSECURE_REMOTE=true
N2U_UNIFI_NUT_SERVER_ENABLED=false
```

Replace every synthetic address, the example MAC, network name and `ups`.
Remote access must be confined by the server's ACL to the gateway's dedicated
LAN IP, across a trusted LAN or VPN.
Fix the actual server/routing configuration rather than weakening host firewalls.

Set the final inform origin **before adoption**. Once adopted, changing the
environment cannot migrate the persisted controller origin. Never edit the
adoption JSON by hand; see [troubleshooting](troubleshooting.md).

### NUT on the same host

Macvlan cannot directly reach its host through the host's LAN IP, and
`127.0.0.1` now refers to the container. For NUT on the same NAS/Linux host,
the optional `compose.nut-host.yaml` attaches a second, pre-created **internal
bridge**. Address the host NUT service through that bridge's gateway IP.
[Docker documents host access through a bridge alongside macvlan](https://docs.docker.com/engine/network/drivers/macvlan/).

An administrator may prepare the bridge after checking that its private subnet
does not overlap the LAN, VPNs or other Docker networks. This example uses a
documentation-only subnet; replace it with a suitable unused private subnet:

```sh
docker network create --driver bridge --internal \
  --subnet 198.51.100.0/29 --gateway 198.51.100.1 n2u-nut-host
```

`--internal` is required. It permits appropriately configured host services at
the bridge gateway without adding a default route from this network; the LAN
interface remains the external path. Docker performs its own network setup
during this explicit administrator action.
[Docker internal-network behavior](https://docs.docker.com/reference/cli/docker/network/create/#network-internal-mode---internal).

Set matching values in the private `.env`:

```dotenv
N2U_NUT_HOST_NETWORK=n2u-nut-host
N2U_NUT_HOST_IP=198.51.100.2
N2U_NUT_ADDRESS=198.51.100.1:3493
N2U_NUT_ALLOW_INSECURE_REMOTE=true
N2U_UNIFI_NUT_SERVER_ENABLED=false
```

The static bridge-side `N2U_NUT_HOST_IP` makes a narrow server ACL possible.
The existing `upsd` listener, ACL and host firewall must already allow this
source to reach the bridge gateway's NUT port. The overlay cannot make a
loopback-only listener reachable. If host policy does not permit it, ask the
host administrator to arrange supported NUT access before starting the gateway.
There is no automatic firewall edit, host shim, proxy or NUT command path.

This connection is still non-loopback plaintext, so the explicit opt-in remains
`true` even though the bridge is internal. Add `-f compose.nut-host.yaml` to
every Compose command, alongside `-f compose.auth.yaml` if authentication is
also needed. Keep Network's NUT Server advertisement disabled: this overlay
does not create a service on the gateway's LAN IP.

### Authenticated NUT

Skip this if the server permits read-only queries without login. Do not place a
password in `.env`. Prepare a trusted password file in a private host folder;
use an absolute path owned/administered by you. For a normal rootful Docker
Engine, the file must be readable as container UID/GID 65532:

```sh
sudo install -d -m 700 /opt/nut-2-unifi-ups-gateway/secrets
sudo install -o 65532 -g 65532 -m 400 /trusted/source/nut_password /opt/nut-2-unifi-ups-gateway/secrets/nut_password
```

Replace the source path. User-namespace-remapped engines require their own host
UID mapping and are not covered by these ownership commands. Add only non-secret
references to `.env`:

```dotenv
N2U_NUT_USERNAME=monitor
N2U_NUT_PASSWORD_SECRET_FILE=/opt/nut-2-unifi-ups-gateway/secrets/nut_password
```

Use **both** files for every deployment command:

```sh
docker compose --env-file .env -f compose.yaml -f compose.auth.yaml config --quiet
docker compose --env-file .env -f compose.yaml -f compose.auth.yaml pull
docker compose --env-file .env -f compose.yaml -f compose.auth.yaml up -d
```

The secret is mounted read-only. Never print it or attach it to an issue.

### UniFi compatibility options

Low-level defaults stay off. On a trusted management LAN, operators who accept
the limitations below can select the configuration observed with Network 10.6.102:

```dotenv
N2U_UNIFI_HTTP_GCM_VOLATILE_CFGVERSION_SYNC=false
N2U_UNIFI_HTTP_GCM_CONFIG_RECEIPT_MODE=persistent
N2U_UNIFI_HTTP_GCM_REPORTED_FIRMWARE_SYNC=true
```

The first receipt remembers a received configuration marker, **not applied
settings**. The second remembers Network's requested version, including lower
targets; it never installs firmware. GCM authenticates replies but does not prove
request freshness or ordering. Old authentic replies or restored volumes can
regress reported state. Unknown response shapes fail closed. Only enable these
options when that trust boundary is acceptable.

[Exact option limits](configuration.md#multi-field-configuration-receipts) and
[observed versus untested behavior](compatibility.md) remain separate.
The older sole-field volatile experiment is not the recommended onboarding path.

### NUT Server advertisement

Keep `N2U_UNIFI_NUT_SERVER_ENABLED=false` in this deployment. Its container runs
only a NUT client; neither network attachment serves or proxies NUT at the
gateway's LAN IP. A reachable upstream, including the internal bridge gateway,
does not qualify as a downstream service. The separate advanced
[advertisement contract](configuration.md#optional-nut-server-advertisement)
does not change this deployment rule.

## Start and adopt

For unauthenticated NUT:

```sh
docker compose --env-file .env -f compose.yaml config --quiet
docker compose --env-file .env -f compose.yaml pull
docker compose --env-file .env -f compose.yaml up -d
docker compose --env-file .env -f compose.yaml ps
docker compose --env-file .env -f compose.yaml exec -T gateway /nut-2-unifi-ups-gateway healthcheck
```

For authenticated NUT, add `-f compose.auth.yaml` to every Compose command.
For same-host NUT, also add `-f compose.nut-host.yaml`. Health binds container
loopback; host `curl` to `127.0.0.1:9199` no longer reaches it. The built-in
healthcheck checks process health, not telemetry readiness or Network acceptance.
In Network, adopt **UPS 2U**, check plausible readings and pair eligible consoles.
A healthy process or successful pairing is not a successful shutdown test.

The deployment keeps a read-only root filesystem, drops all capabilities and
uses no-new-privileges, a 64 MiB memory limit and bounded logs. Its requested
64-process limit depends on host support. Do not rename the Compose project,
replace the state mount or start two instances against the same state directory.

## Back up identity

The existing named state volume contains the adopted identity, secret inform key,
configuration receipt and reported-version receipt. Stop **only this gateway**
before taking a file-level backup with a trusted host backup tool. Back up the
complete volume plus private deployment files; restart the same service afterward.
Never print or upload state files. The same volume retains the saved identity;
an IP/network migration still needs independent Network and pairing validation.

## Migrate from host networking

The 0.9.1 network change is not an unattended image-only update. Stage the
matching deployment files using [Update](#update), then:

1. Record the existing Compose project name and state volume privately. Back up
   the complete deployment and stopped gateway state as described above.
2. Read the adopted **UPS MAC** privately from Network's device panel. Set
   `N2U_DEVICE_MAC` to that exact MAC so it becomes the actual macvlan interface
   MAC. Preserve the NAS's own MAC and IP; do not assign either to the gateway.
3. Have the administrator confirm and reserve a **new free LAN IP**, prepare
   the external macvlan network, and configure `N2U_DEVICE_IP` and
   `N2U_LAN_NETWORK`. If the adopted MAC conflicts with a physical device, stop
   for an identity migration decision; do not edit state or silently replace it.
4. For NUT on the same host, prepare the internal bridge and confirm the
   listener/ACL path above. Replace the old loopback NUT address. Preserve the
   existing shutdown protection throughout.
5. Stop only the old gateway before starting the replacement. Keep the exact
   Compose project and named state volume; never run both identities at once.
   Validate the staged Compose configuration, then recreate only this gateway.
6. Check the gateway version and health, then verify in Network that the UPS
   uses the new IP and original MAC while the NAS retains its own identity.
   Recheck Online state, readings and every intended Safe Shutdown Pairing.

Keeping the volume and MAC avoids intentionally replacing the saved identity,
but **does not guarantee adoption or pairings survive an IP change**. Network
may require an operator-controlled pairing/adoption step. Do not reset adoption
or delete state merely to clear a UI symptom. Exact-build live migration remains
**CANDIDATE** until these checks pass; physical shutdown is a separate test.

## Update

Include `compose.legacy.yaml` and `compose.nut-host.yaml` from the same bundle in
the protected deployment set. Keep the same selected base and overlays for
validation, pull, startup and rollback.

Keep `compose.yaml`, `compose.auth.yaml`, `compose.nut-host.yaml`,
`compose.legacy.yaml`,
`RELEASE-METADATA.txt` and the
digest-pinned `N2U_IMAGE` from the **same verified versioned release bundle**.
Copy the active deployment and its site-owned `.env` to a protected backup
directory. Keep the existing named state volume in place.

Download/verify the new bundle into a separate versioned staging directory.
Use its generated `.env` as the base, copy corresponding site-owned values,
and leave its new image digest unchanged. Unknown `N2U_` variables are rejected:
do not blindly copy the old environment. Never pair a new image line with an
older `compose.yaml` or `compose.auth.yaml`.
The same version rule applies to `compose.nut-host.yaml`; do not bring a new
overlay into an older bundle. For a host-network installation, complete
[the migration procedure](#migrate-from-host-networking) before startup.

From the staged directory:

```sh
docker compose --env-file .env -f compose.yaml config --quiet
docker compose --env-file .env -f compose.yaml pull
docker compose --env-file .env -f compose.yaml up -d
docker compose --env-file .env -f compose.yaml ps
```

Include the authentication and same-host overlays when used. The unchanged Compose project name
reuses the existing named state volume even from a different deployment folder.
Verify health, actual gateway version and Network state before accepting the update.

## Roll back

Restore the complete protected prior deployment set: `compose.yaml`,
`compose.auth.yaml`, `compose.legacy.yaml` and `compose.nut-host.yaml` when that prior version included them,
metadata and digest-pinned `N2U_IMAGE` from the
same verified versioned release bundle, with its backed-up site-owned `.env`.
Preserve the existing named state volume. Never mix either previous Compose file
with a different release's image line.

Use the same validate/pull/up commands from the restored folder, including the
overlays belonging to that version when needed. A rollback to `v0.9.0` restores
its original host-network contract and NUT address; do not attach the new bridge
overlay to it. Recheck the resulting IP/MAC presentation and Network pairings.
Do not use `docker compose down` for normal
updates or rollback, and never pass `--volumes`. Do not delete, replace or rename
the volume. An older binary may ignore separate newer receipt files; rollback
does not authorize editing or resetting adoption state.

Existing pre-0.9.0 Synology deployments also need the explicit network migration
above. Preserve the exact Compose project name and state mount, retain the
original deployment set for rollback, and migrate only matching environment values.
