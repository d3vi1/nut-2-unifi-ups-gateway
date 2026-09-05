# Install and maintain the gateway

This is the shared Docker Compose deployment for Linux, including Synology.
It reads an existing NUT server; it does not replace that server or its shutdown
configuration. [Compatibility](compatibility.md) lists what has actually been tested.

## Before you start

Have Docker Engine and Compose available, plus the NUT host/port, served UPS name
and UniFi Network console address. Use `upsc -l HOST` to find served names and
`upsc UPS@HOST` to check telemetry if NUT tools are installed on the host.
Do not post those raw results publicly.

The supplied deployment uses **host networking**. Same-host NUT is therefore
reachable on `127.0.0.1`; a bridge container would have a different loopback.
The gateway uses the host's IPv4 route/interface for discovery. Do not add port
mappings or assume Docker Desktop/rootless-engine networking is equivalent.
[Docker's host-network limitations](https://docs.docker.com/engine/network/drivers/host/).

| Connection | Direction from gateway host | Purpose |
|---|---|---|
| NUT TCP/3493, or your configured port | outbound | Read UPS telemetry |
| Controller TCP/8080, or your configured inform port | outbound | UniFi inform |
| UDP/10001 broadcast | outbound only | Discovery on the management LAN |
| TCP/9199 on loopback | local operator only | Health and diagnostics |

There is no discovery listener, SSH service or NUT listener to expose.
Do not expose NUT, inform or health to the internet. Keep initial adoption on a
trusted management LAN: its bootstrap key is public. Remote NUT has no STARTTLS;
credentials and telemetry are plaintext unless an independently secured network
carries them. [Security boundaries](../SECURITY.md).

## Download and verify

Use an empty project folder. Docker administration may require host privileges;
the process inside the container still runs as UID/GID `65532:65532`.

Download both files from the same published
[GitHub Release](https://github.com/d3vi1/nut-2-unifi-ups-gateway/releases).
For `v0.9.0`:

```sh
release=v0.9.0
bundle="nut-2-unifi-ups-gateway-${release}-compose.tar.gz"
checksums="nut-2-unifi-ups-gateway-${release}-compose.SHA256SUMS"
release_url="https://github.com/d3vi1/nut-2-unifi-ups-gateway/releases/download/${release}"
curl -fL --proto '=https' --tlsv1.2 "$release_url/$bundle" -o "$bundle"
curl -fL --proto '=https' --tlsv1.2 "$release_url/$checksums" -o "$checksums"
sha256sum -c "$checksums"
tar -tzf "$bundle"
```

Stop on a failed download/checksum. The archive must contain exactly `.env`,
`compose.yaml`, `compose.auth.yaml` and `RELEASE-METADATA.txt` inside one
versioned directory, plus that directory entry. If no Release exists yet, these
commands cannot install a stable release; do not substitute development files.

The checksum detects corruption, not compromise of the shared GitHub Release
trust root. The maintainer's [release safeguards](releasing.md) bind the image
and deployment files before publication. After verification, extract:

```sh
tar -xzf "$bundle" --strip-components=1
chmod 600 .env
```

Keep `N2U_IMAGE` unchanged: it pins the multi-platform manifest digest. Do not
replace it with `:edge`, `:latest` or a guessed `:0.9.0` tag. The source-tree
`deploy/compose/.env.example` is deliberately a development example.

## Configure NUT and Network

Edit `.env`:

```dotenv
N2U_NUT_ADDRESS=192.0.2.20:3493
N2U_NUT_UPS=ups
N2U_INFORM_URL=http://192.0.2.10:8080/inform
N2U_NUT_ALLOW_INSECURE_REMOTE=true
```

Replace both example addresses and `ups`. For same-host NUT use
`127.0.0.1:3493` and `N2U_NUT_ALLOW_INSECURE_REMOTE=false`. Remote access must
be confined by the server's ACL to the gateway host, across a trusted LAN or VPN.
Fix the actual server/routing configuration rather than weakening host firewalls.

Set the final inform origin **before adoption**. Once adopted, changing the
environment cannot migrate the persisted controller origin. Never edit the
adoption JSON by hand; see [troubleshooting](troubleshooting.md).

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

### Optional NUT Server advertisement

Leave `N2U_UNIFI_NUT_SERVER_ENABLED=false` unless a separate, credential-free
NUT service is independently verified from another LAN machine at the gateway's
advertised IP, served name and port. A remote upstream does not qualify merely
because the gateway can read it. The gateway does not proxy NUT.
[Detailed checks](configuration.md#optional-nut-server-advertisement).

## Start and adopt

For unauthenticated NUT:

```sh
docker compose --env-file .env -f compose.yaml config --quiet
docker compose --env-file .env -f compose.yaml pull
docker compose --env-file .env -f compose.yaml up -d
docker compose --env-file .env -f compose.yaml ps
curl -fsS http://127.0.0.1:9199/readyz
```

For authenticated NUT, add `-f compose.auth.yaml` to every Compose command.
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
Never print or upload state files. Restore the same volume to preserve identity.

## Update

Keep `compose.yaml`, `compose.auth.yaml`, `RELEASE-METADATA.txt` and the
digest-pinned `N2U_IMAGE` from the **same verified versioned release bundle**.
Copy the active deployment and its site-owned `.env` to a protected backup
directory. Keep the existing named state volume in place.

Download/verify the new bundle into a separate versioned staging directory.
Use its generated `.env` as the base, copy corresponding site-owned values,
and leave its new image digest unchanged. Unknown `N2U_` variables are rejected:
do not blindly copy the old environment. Never pair a new image line with an
older `compose.yaml` or `compose.auth.yaml`.

From the staged directory:

```sh
docker compose --env-file .env -f compose.yaml config --quiet
docker compose --env-file .env -f compose.yaml pull
docker compose --env-file .env -f compose.yaml up -d
docker compose --env-file .env -f compose.yaml ps
```

Include the authentication overlay when used. The unchanged Compose project name
reuses the existing named state volume even from a different deployment folder.
Verify health, actual gateway version and Network state before accepting the update.

## Roll back

Restore the complete protected prior deployment set: `compose.yaml`,
`compose.auth.yaml`, metadata and digest-pinned `N2U_IMAGE` from the
same verified versioned release bundle, with its backed-up site-owned `.env`.
Preserve the existing named state volume. Never mix either previous Compose file
with a different release's image line.

Use the same validate/pull/up commands from the restored folder, including the
authentication overlay when needed. Do not use `docker compose down` for normal
updates or rollback, and never pass `--volumes`. Do not delete, replace or rename
the volume. An older binary may ignore separate newer receipt files; rollback
does not authorize editing or resetting adoption state.

Existing pre-0.9.0 Synology deployments can adopt this generic bundle without
moving the volume: preserve the exact Compose project name and state mount,
retain their original deployment set for rollback, and migrate only matching
environment values.
