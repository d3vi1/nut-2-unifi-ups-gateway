# Synology Container Manager

This guide installs v0.9.0 without changing DSM's NUT configuration, firewall,
Docker storage, or any existing Container Manager project.

> [!CAUTION]
> Use a trusted management LAN for first UniFi adoption. The common controller
> endpoint is plain HTTP/8080 and the pre-adoption protocol has a public
> bootstrap key. A machine on the same untrusted network could observe initial
> telemetry or forge a response. Remote NUT traffic is also plaintext because
> this gateway does not implement STARTTLS. Use remote NUT only over a trusted
> LAN or VPN; never expose TCP/3493 to the internet.

## Before you start

Collect these values:

- the NUT server address and port;
- the UPS name shown by `upsc -l HOST`;
- the IP address or resolvable name of the UniFi console running Network;
- a read-only NUT username only if your server requires one.

Container Manager must be installed and `docker compose version` must succeed.
The gateway uses host networking so it can reach DSM's loopback-only NUT server
and send UniFi discovery broadcasts. It still runs as the unprivileged numeric
user `65532:65532`.

## Install the verified release bundle

For a first install, use an empty project directory and run as a Synology
administrator over SSH. Do not extract a new bundle over an existing `.env`;
follow [Update](#update) instead.

```bash
sudo -i
mkdir -p /volume1/docker/nut-2-unifi-ups-gateway
cd /volume1/docker/nut-2-unifi-ups-gateway
release=v0.9.0
bundle="nut-2-unifi-ups-gateway-${release}-synology.tar.gz"
checksums="nut-2-unifi-ups-gateway-${release}-synology.SHA256SUMS"
release_url="https://github.com/d3vi1/nut-2-unifi-ups-gateway/releases/download/${release}"
curl -fL --proto '=https' --tlsv1.2 "$release_url/$bundle" -o "$bundle"
curl -fL --proto '=https' --tlsv1.2 "$release_url/$checksums" -o "$checksums"
sha256sum -c "$checksums"
tar -tzf "$bundle"
```

Stop if `sha256sum` does not report `OK`. Before extraction, the `tar -t` output
must contain only `.env`, `compose.yaml`, `compose.auth.yaml`, and
`RELEASE-METADATA.txt` inside one versioned directory.

The generated `.env` uses the authoritative multi-platform manifest digest
returned by the release build, in this form:

```dotenv
N2U_IMAGE=ghcr.io/d3vi1/nut-2-unifi-ups-gateway@sha256:<64-hex-digit-digest>
```

Do not change it to `:0.9.0`, `:latest`, or another tag. The source-tree
`.env.example` deliberately remains tag-based for local development; it is not
the official Synology install file.

Compose intentionally refuses to render if `.env` is missing or
`N2U_IMAGE` is empty. Restore the generated file from this verified bundle
instead of substituting a mutable tag.

The checksum detects transfer or storage corruption, but does not independently
authenticate a compromised GitHub Release because both files have the same
trust root. Every release requires a public repository and GHCR package,
GitHub immutable releases, a protected `main`, and a no-bypass ruleset that
blocks updates and deletion for `v*` tags. These service settings are a
mandatory external release gate: the workflow cannot safely substitute for
them. The controller runs only by explicit dispatch from live `main`,
atomically reserves the version tag and creates its owned draft before the
image, and rejects reruns and conflicting external state. No `:0.9.0` or other
human-readable release image alias is published.

After those checks succeed, extract the bundle:

```bash
tar -xzf "$bundle" --strip-components=1
chmod 600 .env
```

Open `.env` in a text editor. Set `N2U_INFORM_URL` to the final explicit address
of the UniFi console. For example, a console at `192.0.2.10` uses:

```dotenv
N2U_INFORM_URL=http://192.0.2.10:8080/inform
```

Replace the documentation address with your real address. Configure the final
origin before first startup; controller-directed hostname, scheme, address, or
port changes are rejected.

## NUT on the same Synology

Keep these defaults:

```dotenv
N2U_NUT_ADDRESS=127.0.0.1:3493
N2U_NUT_UPS=ups
N2U_NUT_ALLOW_INSECURE_REMOTE=false
```

Change `ups` only if the local server uses another name. Test it on DSM before
starting the container:

```bash
upsc ups@127.0.0.1
```

A local read-only `LIST VAR` commonly needs no login. Do not add credentials
unless the server requires them.

## NUT on another machine

Replace the example address, UPS name, and NUT ACL with values for your site:

```dotenv
N2U_NUT_ADDRESS=192.0.2.20:3493
N2U_NUT_UPS=ups
N2U_NUT_ALLOW_INSECURE_REMOTE=true
```

The opt-in is mandatory for a non-loopback address. It acknowledges that NUT
telemetry and credentials have no transport encryption. Restrict TCP/3493 to
the Synology's source address and use a trusted LAN or VPN.

Verify reachability from the Synology:

```bash
upsc ups@192.0.2.20
```

If this fails, fix routing, firewall, the NUT `LISTEN` setting, or the NUT ACL
on the server. Do not weaken DSM or internet-facing firewall rules.

## Optional NUT Server advertisement

Network's **NUT Server** switch is not the upstream connection used by the
gateway. It tells clients that an NUT service is reachable at the emulated
device's own IP. The gateway does not open or manage that listener.

Leave the feature disabled unless a separate NUT service is already reachable
from another machine on the management LAN. Verify the served name and port
from that other machine first:

```bash
upsc -l 192.0.2.21:3493
upsc ups@192.0.2.21:3493
```

Replace the documentation address and `ups`. The first command must list the
same UPS name used by the second. Do not substitute the `ups.id` telemetry
value; NUT protocol clients need the name returned by `LIST UPS`.

Only after that read-only test succeeds, opt in explicitly:

```dotenv
N2U_UNIFI_NUT_SERVER_ENABLED=true
N2U_UNIFI_NUT_SERVER_ID=ups
N2U_UNIFI_NUT_SERVER_PORT=3493
```

This advertisement is experimental and credential-free. It never copies the
upstream NUT username or password. Changes made to these fields in Network are
ignored by gateway v0.9.0 and do not start, stop, or reconfigure DSM's NUT
service. Use the environment variables as the source of truth. Leave the
feature off for a remote, loopback-only, authenticated, firewalled, or otherwise
unverified server.

## Authenticated NUT

Skip this section when `upsc` works without authentication.

Do not put a NUT password in `.env`. Store it in a project-private directory
and use the supplied Compose overlay:

```bash
mkdir -p /volume1/docker/nut-2-unifi-ups-gateway/secrets
chmod 700 /volume1/docker/nut-2-unifi-ups-gateway/secrets
cp /trusted/source/nut_password /volume1/docker/nut-2-unifi-ups-gateway/secrets/nut_password
chown 65532:65532 /volume1/docker/nut-2-unifi-ups-gateway/secrets/nut_password
chmod 400 /volume1/docker/nut-2-unifi-ups-gateway/secrets/nut_password
```

The root-only parent directory protects the host path, while UID 65532 can read
the file through the read-only bind mount. Add only these non-secret values to
`.env`:

```dotenv
N2U_NUT_USERNAME=monitor
N2U_NUT_PASSWORD_SECRET_FILE=/volume1/docker/nut-2-unifi-ups-gateway/secrets/nut_password
```

Use both Compose files for every pull, start, inspect, and stop command:

```bash
docker compose --env-file .env -f compose.yaml -f compose.auth.yaml config
docker compose --env-file .env -f compose.yaml -f compose.auth.yaml pull
docker compose --env-file .env -f compose.yaml -f compose.auth.yaml up -d
```

Never print the password or attach the secret file to an issue.

## Validate and start

For NUT without authentication:

```bash
docker compose --env-file .env -f compose.yaml config
docker compose --env-file .env -f compose.yaml pull
docker compose --env-file .env -f compose.yaml up -d
docker compose --env-file .env -f compose.yaml ps
```

Inspect the rendered `config` output before `up -d`. Confirm:

- an image reference ending in `@sha256:` plus exactly 64 hexadecimal digits;
- `network_mode: host`;
- user `65532:65532`;
- all capabilities dropped and `no-new-privileges`;
- read-only root filesystem;
- one project-owned state volume;
- no published Docker ports;
- the intended NUT address, UPS name, and inform URL.

The default file requests a 64 MiB memory limit and a 64-process cgroup limit.
Some DSM kernels do not expose the PIDs controller and may warn that the latter
is ignored. The image contains one static process, no shell, and no subprocess
execution path.

## Verify health

```bash
docker inspect --format '{{json .State.Health}}' nut-2-unifi-ups-gateway
docker logs --since 5m nut-2-unifi-ups-gateway
curl -fsS http://127.0.0.1:9199/healthz
curl -fsS http://127.0.0.1:9199/readyz
curl -fsS http://127.0.0.1:9199/metrics
```

`/healthz` proves that the process is alive. `/readyz` requires fresh NUT
telemetry and is independent of UniFi adoption. In metrics:

- `n2u_controller_reachable=1` means the controller answered;
- `n2u_adopted=1` means the gateway accepted adoption state;
- a growing `n2u_inform_pending_total` with `n2u_adopted=0` means inform is
  still pending or the controller is returning HTTP 404.

## Adopt and pair

1. Open **UniFi Network → Devices** and wait up to a minute for **UPS 2U**.
2. Select it, choose **Adopt**, and wait for **Connected**.
3. Open its device panel and expand **Safe Shutdown Pairing**.
4. Pair each eligible NVR, gateway, or other console.
5. Choose a conservative remaining-runtime trigger and verify that live UPS
   telemetry is plausible.

Do not delete or recreate the `state` volume after adoption. It contains the
stable device identity and secret inform key. A paired UI state is **OBSERVED**
evidence, not proof of a completed shutdown. Keep the normal NUT shutdown plan
enabled and perform any outage test only in a controlled maintenance window.

The Network UI may show remote power actions. They are intentionally inert:
the gateway parses and ignores relay requests and never sends a NUT command.
V0.9.0 also removes advertised Power Cycle on Restore, buzzer-control, and EPO
capabilities. The NUT Server form may still appear because Network 10.6.102
renders it for this carrier even when server access is not advertised.

## Troubleshooting

| Symptom | Resolution |
|---|---|
| Container exits immediately | Run `docker compose ... config`; check the explicit inform URL, NUT address, UPS token, and secret-file permissions. |
| `/healthz` works but `/readyz` fails | Confirm `upsc UPS@HOST` works, then check the NUT name, ACL, timeout, and stale interval. |
| Non-loopback NUT is rejected | Set `N2U_NUT_ALLOW_INSECURE_REMOTE=true` only after confining the connection to a trusted LAN or VPN. |
| UPS never appears in Network | Keep the Synology and console on the management LAN, allow UDP/10001 and TCP/8080, and use the console's explicit `/inform` URL. |
| Inform remains pending or returns 404 | Confirm `N2U_UNIFI_MODEL=USWDA26`, update Network, and compare the exact build with [protocol evidence](protocol-evidence.md). |
| Only eight 4+4 outlets appear | The NUT driver supplied no valid `outlet.count`; the default carrier fallback is working as designed. |
| Outlets 5–8 are marked Surge | Network's `USWDA26` catalog fixes this illustration; it is not derived from NUT or `outlet_caps`. |
| Power is `<100/0 W` or current is exactly `1.00 A` | Inspect direct NUT `ups.realpower`, `ups.realpower.nominal`, and `output.current`; missing precision and W values are never invented. |
| NUT Server stays unchecked | This is the safe default. Follow the external reachability test above before enabling the experimental advertisement. |
| Remote power actions do nothing | Expected and safe: gateway v1 is read-only and has no NUT command path. |
| Pulling from GHCR is denied | The official release package must be public. For a private development package only, log in with a token limited to `read:packages`; never store it in Compose or `.env`. |
| Compose says `N2U_IMAGE` must be set | Restore `.env` from the verified release bundle; do not bypass the check with an image tag. |

Do not edit DSM's `/etc/ups`, `/usr/syno/etc/ups`, firewall, or Docker engine
storage to make the gateway work. Diagnose the actual NUT or Network boundary.

## Back up identity

The named Docker volume contains the adopted identity and inform key. Back it
up with a trusted administrative process without printing its files or
attaching them to an issue. Stop the project before taking a file-level copy.
Restoring the same volume preserves the UniFi device identity.

## Update

Read the new release notes and download its versioned Synology bundle and
checksum into a separate temporary directory. Verify the checksum before
extracting it, exactly as in the installation procedure. Copy only the new
digest-pinned `N2U_IMAGE=...@sha256:...` line from the generated `.env` into
your existing `.env`; retain all site settings and the existing state volume.
Then inspect the rendered Compose configuration before applying it:

```bash
docker compose --env-file .env -f compose.yaml config
docker compose --env-file .env -f compose.yaml pull
docker compose --env-file .env -f compose.yaml up -d
docker compose --env-file .env -f compose.yaml ps
```

For authenticated NUT, include `-f compose.auth.yaml` in all four commands.
Never update by pulling `:latest`, re-pulling a previous tag, or downloading
deployment files from a Git tag. Each upgrade gets its image digest from its
own verified, immutable GitHub Release bundle.

## Roll back

Retrieve and verify the previous known-good release bundle, then restore its
exact digest-pinned `N2U_IMAGE` line and run `pull` plus `up -d`. Do not derive a
rollback reference from a mutable tag.
To stop the unauthenticated deployment without deleting identity:

```bash
docker compose --env-file .env -f compose.yaml down
```

For authenticated NUT:

```bash
docker compose --env-file .env -f compose.yaml -f compose.auth.yaml down
```

Do not add `--volumes`. A normal rollback changes neither the upstream NUT
server nor the controller. Unpair the gateway in Network only when deliberately
discarding that identity.
