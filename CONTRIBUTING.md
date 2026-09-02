# Contributing

Contributions are welcome, especially reproducible observations from other UPS
models or Network versions.

Before opening a change:

1. Do not attach proprietary firmware, controller binaries, database exports,
   packet captures, credentials, MAC addresses, or serial numbers.
2. Label protocol claims `PROVEN`, `CANDIDATE`, `UNKNOWN`, or
   `BLOCKED_EXTERNAL` and include enough non-sensitive provenance to reproduce
   the result.
3. Preserve the v1 invariant that no NUT power-write API or execution path is
   present.
4. Keep runtime code within the Go standard library.
5. Add tests for malformed input, timeouts, and 32-bit builds where relevant.

Run:

```bash
make check
```

Commits should be focused and carry a Developer Certificate of Origin sign-off:

```text
Signed-off-by: Your Name <you@example.com>
```

By contributing, you license the contribution under GPL-2.0-only.
