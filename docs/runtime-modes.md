# Two ways to run the gateway

Choose the role of the Linux machine, not the brand of its NUT driver.

| Mode | Use it when | Identity in Network | NUT on the same machine |
|---|---|---|---|
| `shared` | Linux is the UPS appliance itself | The host's actual IP and MAC | Host loopback |
| `separate` | Linux is also a NAS, server or other appliance | The container's own LAN IP and MAC | Optional internal bridge to the host service |

The runtime defaults to `separate`. The operator makes the role decision: the
program cannot tell whether a machine is physically a UPS, or discover every
other device or NAT rule on the LAN. Neither mode edits interfaces, ARP, routing,
firewalls or NUT configuration. Both are read-only NUT clients, not NUT servers.

In either mode, set `N2U_DEVICE_IP` to an actual local IPv4 address. It must belong
to exactly one up, non-loopback Ethernet interface with a nonzero unicast MAC
and a valid broadcast subnet (/1 through /30). The observed MAC is used for
INFORM, discovery and persistent identity. There is no randomly invented gateway
MAC. A configured or persisted MAC that differs from the interface stops startup.

## Shared native daemon

Use this only when the host and the emulated UPS intentionally represent one
appliance. Do not select it on a NAS while expecting an independent NAS client
and UPS device in Network. Same-MAC roles are not independent topology identities.

Docker is not required. Build the static binary from the reviewed source on a
Linux machine with the Go version declared by `go.mod` (or cross-build for the
target architecture):

```sh
CGO_ENABLED=0 go build -trimpath -buildvcs=false -o nut-2-unifi-ups-gateway ./cmd/nut-2-unifi-ups-gateway
```

These are source-build instructions, not a claim that native binaries are
published as Release assets. A source build reports `dev` unless the standard
version/revision build variables are supplied. The container bundle is separate.

For a manual run, provide a private writable state directory owned by the
unprivileged service account and replace the example IPs:

```sh
N2U_NETWORK_MODE=shared \
N2U_DEVICE_IP=192.0.2.20 \
N2U_INFORM_URL=http://192.0.2.10:8080/inform \
N2U_NUT_ADDRESS=127.0.0.1:3493 \
N2U_STATE_FILE=/var/lib/n2u/state.json \
./nut-2-unifi-ups-gateway
```

Leave `N2U_DEVICE_MAC` unset: the daemon reads it from the interface owning the
selected IP. Supplying it is an additional equality assertion, never a request
to change the host's MAC. Keep one persistent state directory per instance.

For systemd, reviewed example files are in `deploy/systemd`. An administrator
can install the binary as `/usr/local/bin/nut-2-unifi-ups-gateway`, the edited
`n2u.env.example` as root-owned mode 0600 `/etc/n2u/gateway.env`, and the unit in
the normal system unit directory. Then validate the unit with
`systemd-analyze verify`, reload units and enable/start it in an agreed maintenance
window. The example requires systemd supporting `DynamicUser` and `StateDirectory`
(235 or newer); it creates a private state directory and drops all capabilities.
Unit execution on a physical UPS remains operator validation, not an executed
field test. Do not start a second instance against an existing active state file.

Never load Compose's `.env` into the daemon: variables such as `N2U_IMAGE` and
`N2U_LAN_NETWORK` belong to Compose, not the runtime, and are rejected there.
For authenticated NUT, supply the normal username and password-file variables;
the secret must be privately readable by the actual service identity. Do not
make it world-readable to accommodate a dynamic user. Service-credential mapping
requires separate administrator setup. Local NUT itself needs no plaintext opt-in;
non-loopback NUT still requires the explicit trusted-network opt-in in either mode.

## Separate container

Follow [the container installation](installation.md). The base templates select
`N2U_NETWORK_MODE=separate` and require a stable `N2U_DEVICE_MAC`, used both for
the Docker LAN endpoint and the gateway's identity. Reserve a distinct unused IP
and unique MAC. A Docker bridge with NAT, an IP alias, or merely changing the IP
inside INFORM is not the supplied direct-LAN deployment.

The normal base is `compose.yaml`. The Engine 24 / Compose 2.20.x alternative is
`compose.legacy.yaml`; choose **one**, never merge them. Add `compose.nut-host.yaml`
only for the documented internal-bridge path to same-host NUT. It does not enable
downstream NUT advertisement or proxy the server. No runtime shell, extra daemon,
Docker socket, raw-packet privilege or networking capability is introduced.

## Existing identity and mode changes

The adoption-state schema is unchanged. On a 0.9.0 NAS migration, keep the adopted
virtual UPS MAC and configure it as the container's real LAN MAC; keep the same
state volume and assign a new IP. Do not substitute the NAS physical MAC.
The new binary intentionally rejects the old mismatched host-network deployment.

Switching mode does not reset state or authorize a MAC change. A mode change
with the same real identity can reuse state; different hardware MACs require an
intentional, separately planned adoption migration. Never delete state as a
routine workaround. Preserving state avoids an automatic identity reset, but
does not itself prove Network accepts the new IP or preserves every pairing.

Both new deployment modes remain **CANDIDATE** for exact-host/controller
interoperability until the operator verifies Online state, telemetry, expected
NAS visibility, topology and pairings. Physical shutdown remains a separate test.
