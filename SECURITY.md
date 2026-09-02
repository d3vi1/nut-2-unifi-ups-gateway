# Security policy

## Supported versions

Until the first stable release, only the latest tagged release is supported.

## Reporting a vulnerability

Use GitHub's private vulnerability-reporting feature for this repository. Do
not open a public issue containing credentials, inform auth keys, private IP
addresses, device identifiers, controller responses, or power-control steps.

Include the affected version, architecture, deployment mode, impact, and a
minimal redacted reproducer. Do not test outlet-control findings on equipment
you do not own or administer.

## Security properties

- No NUT write-command API is present in gateway v1.
- Firmware `relayctl` requests are decoded but never executed or translated.
- Controller responses and NUT lines are bounded before parsing.
- Inform redirects are rejected.
- Controller-provided inform URLs cannot change the configured origin; DNS
  aliases are not treated as equivalent.
- Persistent adoption state is owner-readable only and atomically replaced.
- The release container is non-root, capability-free, and read-only apart from
  its state volume.

The current NUT client does not implement STARTTLS. Loopback is the secure
default; a non-loopback endpoint requires an explicit insecure-remote opt-in and
must be confined to a trusted network. Do not send NUT credentials over an
untrusted link.

Pre-adoption UniFi compatibility has a separate, unavoidable trust boundary:
the initial TNBU key is public, CBC has no integrity, and many controllers use
plain HTTP/8080. A passive LAN observer can read the initial telemetry; an
active observer can forge a response or choose the next key. Perform first
adoption only on a trusted management network, configure the exact controller
origin before startup, and inspect the resulting device identity. HTTPS helps
only when the controller certificate chains to a CA trusted by the container.

These are design requirements, not a warranty. The software is provided under
the warranty disclaimer in GPL-2.0-only.
