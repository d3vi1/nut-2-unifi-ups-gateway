# Synology Container Manager

Synology is one deployment option, not a requirement of the gateway.
Use the shared [installation, authentication, backup and update guide](installation.md)
and the same Compose release bundle as any Linux host.

## Container Manager setup

1. Install Container Manager. Docker Compose must be available to the account
   administering the project. DSM may package the Compose executable separately;
   use the executable supplied by Container Manager rather than installing a
   second Docker engine.
2. Create a dedicated project folder, for example
   `/volume1/docker/nut-2-unifi-ups-gateway`.
3. Download and verify the published Compose bundle there using the
   [shared procedure](installation.md#download-and-verify).
4. Edit `.env`, then validate and start with Compose. Select the same folder if
   using Container Manager's project UI; do not create a second project over the
   same state volume.

Container administration may require `sudo -i` over SSH. The gateway process
itself runs as non-root UID/GID `65532:65532`.

## Reading DSM's NUT service

For the NUT server on the same NAS, start with:

```dotenv
N2U_NUT_ADDRESS=127.0.0.1:3493
N2U_NUT_UPS=ups
N2U_NUT_ALLOW_INSECURE_REMOTE=false
```

Use the actual served UPS name if it differs. Host networking preserves local
loopback access and avoids a bridge container's different source address.
If NUT runs elsewhere, follow [remote NUT configuration](installation.md#configure-nut-and-network).

Check telemetry read-only before adoption, if `upsc` is available:

```sh
upsc ups@127.0.0.1
```

Do not edit DSM's `/etc/ups`, `/usr/syno/etc/ups`, firewall or Docker engine
storage to make the gateway work. Keep the NAS's existing UPS shutdown protection.

For an authenticated server, use the shared secret-file overlay with a private
path under your project folder. Never store the password in `.env`.
For Network configuration/version reconciliation, use the explicit
[trusted-LAN compatibility options](installation.md#unifi-compatibility-options);
leave the obsolete volatile experiment disabled.

## Host-specific limitations

Some DSM kernels lack the PIDs cgroup controller. Docker may warn that the
requested process limit is ignored. The gateway remains a single static process
without a shell; this warning does not establish that the host enforces the limit.

Network's **NUT Server** setting is separate from reading DSM NUT. Only advertise
a service after verifying it from another LAN host at the gateway's advertised
IP and served name/port. Do not advertise a loopback-only service.
[Advertisement checks](configuration.md#optional-nut-server-advertisement).

## Existing installations

The source templates moved from `deploy/synology` to `deploy/compose` and the
first 0.9.0 bundle is named `-compose`. **Do not move or recreate the state volume.**
The Compose project name and state mount remain unchanged. Keep your private
site configuration and prior image/Compose set for rollback.

Use [Update](installation.md#update) and [Roll back](installation.md#roll-back).
Do not extract a new bundle over your active `.env`. Never use `--volumes`.
For other problems, start with [Troubleshooting](troubleshooting.md).
