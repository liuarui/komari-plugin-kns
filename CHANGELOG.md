# Changelog

This file records public releases. Private development history before the first public release is intentionally not included.

## [1.0.4] - 2026-11-10

- Allow resolved task failures and health incidents to be acknowledged without deleting their history; new incidents are shown again.
- Permit fresh initialization when only known empty KNS directories remain, while protecting existing files and services.

## [1.0.3] - 2026-11-10

- Isolate subscription, machine and settings drafts from unrelated background state updates.
- Validate current machine and task state when submitting new installs instead of rejecting unrelated revisions.
- Protect forms while saving, avoid duplicate batch scans, and mark interrupted installation responses as unknown.
- Move installation to a side drawer with a scrollable machine picker; improve offline-target handling, full UUID search and draft tracking.

## [1.0.2] - 2026-11-10

- Name newly claimed nodes consistently with subscription names, including NAT ports.
- Reuse an in-flight claim when the same idempotency key is retried and report dispatch failures accurately.
- Correct the legacy node takeover and batch operation documentation.

## [1.0.1] - 2026-11-10

- Remove machines and their managed nodes from KNS and subscriptions when they are deleted from Komari.
- Avoid revision conflicts between consecutive read-only machine scans and report common scan failure causes.
- Scan online managed machines and claim supported nodes in sequence; verify live presence before sending remote commands.
- Improve machine card borders in light and dark themes.
- Install verified KNS updates from the settings page through Komari's plugin manager.

## [1.0.0] - 2026-11-10

First public release.

- Manage Komari machines and OneBox proxy nodes from a single workspace.
- Install, inspect, reconfigure, restart, reinstall, and uninstall supported nodes.
- Discover and take over supported legacy OneBox inbounds while preserving their node settings.
- Create filtered subscription profiles for URI, Clash / Mihomo, sing-box, Loon, Surge / Surfboard, Quantumult X, Shadowrocket, Stash, Mellow, V2RayN / V2RayNG, Shadowsocks, SSD, and protocol-specific URI lists.
- Choose simple Clash rule templates through an optional external SubConverter; native client formats do not require it.
- Use advanced protocol settings for ALPN, certificate verification, VLESS Reality flow / fingerprint / SpiderX / handshake, Hysteria2 bandwidth / obfs, VMess alterId / cipher, TUIC congestion control / UDP relay, and Shadowsocks methods.
- Follow the Komari light / dark theme automatically, with a page-only preview control and compact embedded navigation.
- Select machines with distinct selection cards, batch selection, clear selected state, and a structured install review with task dispatch status.
- Track remote task status and resolve stale attention items after successful follow-up operations.
- Store state and subscription snapshots as private `0600` files; encrypted offline export remains available with an independent passphrase.
- Pin the reviewed OneBox adapter `1.8.0` at commit `66c18c352dc591e58075b6c10468ff7bc3bba233`.
