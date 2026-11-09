# Changelog

This file records public releases. Private development history before the first public release is intentionally not included.

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
