# Security policy

## Supported versions

Until 1.0, only the latest tagged release receives security fixes. Reproduce a
problem with that release before reporting it when doing so is safe.

## Report a vulnerability privately

Do not disclose a vulnerability, exploit, credential, inform key, private IP,
device identifier, controller response, packet capture, or power-control
procedure in a public issue.

Use the repository's
[GitHub Security Advisories page](https://github.com/d3vi1/nut-2-unifi-ups-gateway/security/advisories)
first. If GitHub shows **Report a vulnerability**, submit the report there. The
button appears only when private vulnerability reporting is enabled, so this
policy does not claim that it is currently available. See
[GitHub's private-reporting instructions](https://docs.github.com/en/code-security/how-tos/report-and-fix-vulnerabilities/report-privately).

If the button is absent, use a private contact method published on the
[maintainer's GitHub profile](https://github.com/d3vi1). If no private contact
method is available, a public issue may ask only for a private reporting
channel; include no vulnerability details or sensitive data.

A useful private report contains:

- affected gateway version or image digest and CPU architecture;
- deployment mode, NUT version/driver, and UniFi Network version;
- impact and realistic attack prerequisites;
- minimal redacted reproduction steps;
- suggested mitigation, if known.

Do not probe equipment, networks, or power controls that you do not own or
administer. Coordinate any live power-path test with the operator.

## Security properties

- The gateway has no NUT write-command API.
- Firmware `relayctl` requests are decoded but never executed or translated.
- Writable AC-recovery-cycle, buzzer, and EPO capabilities are not advertised.
- NUT information access is advertised only by an explicit operator opt-in and
  never includes credentials; the gateway itself opens no NUT listener.
- Controller responses and NUT lines are bounded before parsing.
- Authenticated GCM response nonces are replay-checked within the active
  auth-key/mode epoch. Nonces that changed persistent adoption state are kept
  in a separate bounded window and saved atomically with that transition.
- Controller-supplied inform intervals never control the runtime scheduler;
  `N2U_INFORM_INTERVAL` remains the sole cadence source.
- Adopted CBC replies over plain HTTP cannot change state or cadence after a
  controller key is installed. Bootstrap completion and a same-key one-way GCM
  upgrade remain compatible; authenticated GCM and trusted HTTPS retain full
  response semantics.
- The health listener has per-connection request bounds and a fixed aggregate
  connection cap. Its supplied deployment remains loopback-only.
- Inform redirects are rejected.
- A controller response cannot change the configured inform origin; DNS aliases
  are not treated as equivalent.
- Persistent adoption state is owner-readable only and atomically replaced.
- The release image declares a non-root user; the supplied Compose deployment
  drops every capability and is read-only apart from its private state volume.
- Tagged releases provide an attested multi-platform OCI digest and a
  checksum-verified deployment bundle pinned to that digest. The supplied
  Compose file refuses to render without an explicit `N2U_IMAGE`.
- Container workflows install an exact Buildx artifact only after verifying its
  reviewed SHA-256 and bootstrap BuildKit from an OCI digest. Publishing builds
  are explicitly cache-cold and the SBOM generator is pinned by OCI digest.
  GitHub's hosted runner and its preinstalled operating-system tools remain the
  external build platform trust root.
- Secrets are accepted through files; the example deployment does not place a
  NUT password in Compose or `.env`.

These properties are intentional boundaries, not a claim that the software is
free of vulnerabilities.

## Network trust boundaries

The NUT client does not implement STARTTLS. Loopback is the safe default. A
non-loopback endpoint is rejected unless
`N2U_NUT_ALLOW_INSECURE_REMOTE=true` is set, and that opt-in is appropriate
only on a trusted LAN or VPN. Never expose NUT TCP/3493 to the internet or send
NUT credentials across an untrusted network.

The optional `N2U_UNIFI_NUT_SERVER_ENABLED` setting is metadata about a
separately running service at the emulated device IP. It does not create a
firewall rule, listener, proxy, or authentication boundary. Enable it only after
read-only verification from the intended client network, and never use it to
publish a NUT service to the internet.

Pre-adoption UniFi compatibility has a separate trust boundary. The initial
TNBU key is public, CBC has no integrity, and many controllers use plain
HTTP/8080. A passive LAN observer can read initial telemetry; an active observer
can forge a response or choose the next key. Perform first adoption only on a
trusted management network, configure the exact controller origin before
startup, and inspect the resulting device identity. HTTPS helps only when the
controller certificate chains to a CA trusted by the container.

After the public-key bootstrap, an adopted session that still uses CBC over
plain HTTP is treated as an acknowledgement channel, not an authorization
channel. Its response is parsed and may retain read-only ignored-command
observations, but state, reset, key, reboot, upgrade, and cadence effects are
discarded. The only exception is a same-key transition to authenticated GCM.
Controllers that require effectful post-adoption CBC must use trusted HTTPS.

The software is provided under the warranty disclaimer in
[GPL-2.0-only](LICENSE).
