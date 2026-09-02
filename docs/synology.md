# Synology Container Manager

This deployment keeps DSM's NUT configuration and every existing Container
Manager project untouched. Use a new project directory and inspect the rendered
Compose model before starting it.

## Prepare

```bash
mkdir -p /volume1/docker/nut-2-unifi-ups-gateway
cp deploy/synology/compose.yaml /volume1/docker/nut-2-unifi-ups-gateway/compose.yaml
cp deploy/synology/compose.auth.yaml /volume1/docker/nut-2-unifi-ups-gateway/compose.auth.yaml
cp deploy/synology/.env.example /volume1/docker/nut-2-unifi-ups-gateway/.env
cd /volume1/docker/nut-2-unifi-ups-gateway
chmod 600 .env
docker compose --env-file .env config
```

Set the controller's final explicit IPv4 `/inform` URL in `.env`; adoption
origin changes are intentionally rejected. Gateway v1 has no power-write API.
A local NUT instance normally needs no password for read-only `LIST VAR`.
`N2U_IMAGE` is pinned to the documented alpha release by default; change it
only when deliberately upgrading or rolling back to another published tag.

If authentication is required, keep the password in a root-administered secret
directory and use the provided override instead of putting it in `.env`.
Docker Compose implements a local file-backed secret as a read-only bind mount,
so the file itself must be readable by the container's numeric UID rather than
owned `0600` by root:

```bash
mkdir -p /volume1/docker/nut-2-unifi-ups-gateway/secrets
chmod 700 /volume1/docker/nut-2-unifi-ups-gateway/secrets
cp /trusted/source/nut_password /volume1/docker/nut-2-unifi-ups-gateway/secrets/nut_password
chown 65532:65532 /volume1/docker/nut-2-unifi-ups-gateway/secrets/nut_password
chmod 400 /volume1/docker/nut-2-unifi-ups-gateway/secrets/nut_password
```

The root-only parent directory protects the host path while UID 65532 can read
the bind-mounted file inside the container. Then render the overlay:

```bash
docker compose --env-file .env \
  -f compose.yaml -f compose.auth.yaml config
```

Set `N2U_NUT_USERNAME` and the absolute `N2U_NUT_PASSWORD_SECRET_FILE` path in
`.env`. The override mounts it read-only at `/run/secrets/nut_password`. Verify
the permissions with a disposable test secret before relying on authenticated
NUT in production; never print the real secret during that check.

## Start and verify

If the repository/package is still private, authenticate Container Manager's
Docker client to GHCR with a read-packages token before pulling. Never place the
token in Compose or `.env`. Keep the same Compose file set for every lifecycle
command. For a NUT server without authentication, use:

```bash
docker compose --env-file .env -f compose.yaml pull
docker compose --env-file .env -f compose.yaml up -d
docker compose --env-file .env -f compose.yaml ps
```

For authenticated NUT, always retain the secret overlay:

```bash
docker compose --env-file .env -f compose.yaml -f compose.auth.yaml pull
docker compose --env-file .env -f compose.yaml -f compose.auth.yaml up -d
docker compose --env-file .env -f compose.yaml -f compose.auth.yaml ps
```

The remaining inspection commands are identical:

```bash
docker inspect --format '{{json .State.Health}}' nut-2-unifi-ups-gateway
docker logs --since 5m nut-2-unifi-ups-gateway
```

`/readyz` becomes ready from fresh NUT telemetry independently of adoption.
Confirm `n2u_controller_reachable=1`, then inspect
`n2u_inform_pending_total` and `n2u_adopted`. A growing pending counter with
`n2u_adopted=0` means the controller is answering 404; it is not evidence that
the device is ready to adopt. Network 10.6.101 is a known live-negative target
for the current profile despite accepting TNBU/JSON/MAC parsing; see the
protocol evidence before creating shutdown-policy expectations.

Expected properties:

- `network_mode=host`;
- numeric user `65532:65532`;
- no capabilities and `no-new-privileges`;
- read-only root filesystem;
- 64 MiB memory limit and a requested 64-process cgroup limit;
- exactly one project-owned state volume;
- no published Docker ports;
- `json-file` logs rotated at 10 MiB with three files retained;
- NUT source `127.0.0.1:3493`;
- no NUT command/control configuration or write path.

The default file does not set a CPU quota because DSM kernels without the CPU
CFS controller reject Docker `NanoCPUs` and refuse to create the container.
Add a site-specific CPU limit only after confirming the host exposes that
controller. Some DSM kernels also warn that the PIDs cgroup is unavailable and
discard `pids_limit`; verify the rendered host configuration instead of
assuming enforcement. The single static process has no subprocess or shell
execution path, and the 64 MiB memory bound remains enforced independently.

Do not edit DSM's `/etc/ups`, `/usr/syno/etc/ups`, firewall, or Docker engine
storage to make the gateway work. Diagnose an access denial first.

## Back up identity

The state volume contains the adopted identity and secret inform key. Back it
up using a trusted administrative process without printing it to a terminal or
attaching it to an issue. Restoring this state preserves the controller's device
identity; starting with an empty volume deliberately creates a new device.

## Roll back

For the unauthenticated deployment:

```bash
docker compose --env-file .env -f compose.yaml down
```

For authenticated NUT, keep the overlay:

```bash
docker compose --env-file .env -f compose.yaml -f compose.auth.yaml down
```

This stops and removes only this project and leaves the named state volume for
recovery. Remove that volume only when intentionally discarding the emulated
device identity. No change to the upstream NUT server or controller should be
needed for a normal rollback; unpair the gateway device through UniFi Network
only if it was actually paired.
