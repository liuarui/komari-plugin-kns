# Changelog

This file records public releases. Private development history before the first public release is intentionally not included.

## [1.3.1] - 2026-11-14

- Pin OneBox script `1.0.8` by its immutable `v1.0.8` release URL and SHA-256.
- Include corrected regional SNI labels and strict region-first candidate ranking from OneBox `1.0.8`.
- Keep adapter schema 1 and version `1.8.0`.

## [1.3.0] - 2026-11-14

- Pin OneBox script `1.0.6` by its immutable `v1.0.6` release URL and SHA-256.
- Keep the adapter at schema 1, version `1.8.0`; callbacks still require the exact adapter and script versions.
- Replace static version badges with a live release badge and clarify the Komari manifest compatibility requirement.
- Add quick-start navigation, a deployment diagram, responsive illustration sizing, and links to the detailed documentation.

## [1.0.15] - 2026-11-11

- Standardize existing KNS node names once on upgrade and use those names in subscription output.
- Apply the same standard name format to single-node installs.

## [1.0.14] - 2026-11-11

- Add localized country and region names beside flags in machine filters and pickers.

## [1.0.13] - 2026-11-11

- Add a quick machine filter for Komari-reported regions.
- Display and filter Komari-reported virtualization types, including KVM and LXC, and mark missing reports as unrecognized.

## [1.0.12] - 2026-11-11

- Bundle OneBox script 1.0.5, which removes fixed memory preflight thresholds and reports actual command failures.
- Keep PID headroom protection and RAM-based SNI concurrency adjustment; use the preset when automatic SNI scanning cannot run.
- Clarify likely OOM termination when a remote task exits with code 137.

## [1.0.11] - 2026-11-11

- Bundle OneBox script 1.0.4, which includes available swap in maintenance preflight while honoring visible cgroup limits.
- Clarify effective RAM+swap headroom in resource errors.

## [1.0.10] - 2026-11-11

- Bundle OneBox script 1.0.3 with lower memory gates for routine node operations and a separate gate for kernel upgrades.
- Show measured available memory and the per-operation minimum in resource failure messages.
- Pin the managed OneBox script to its immutable v1.0.3 release tag.

## [1.0.9] - 2026-11-11

- Bundle OneBox script 1.0.2, which automatically detects the server egress region and prioritizes matching Reality SNI candidates while preserving global fallback.
- Keep KNS script update verification aligned with the pinned OneBox script version and checksum.

## [1.0.8] - 2026-11-11

- Generate consistent default node names as country flag, country, Komari machine name, protocol, and port for installs, automatic provisioning, and legacy-node takeover.
- Look up country from the machine's public IP on demand; manual names bypass lookup and lookup failures do not block remote tasks.
- Preserve names of nodes already registered before this release; the new format applies to newly created or taken-over nodes.
- Explain the naming rule and IP geolocation lookup in the installation flow.

## [1.0.7] - 2026-11-10

- Block new remote changes after unresolved or timed-out tasks, including tasks carried over from earlier releases; allow them again after the alert is acknowledged.
- Show the actual blocking reason when an install target is skipped.

## [1.0.6] - 2026-11-10

- Correct Loon node syntax and include VLESS Reality, Hysteria2 obfuscation, bandwidth, ALPN, and AnyTLS settings.
- Include Quantumult X Reality public key, short ID, and VLESS flow; bracket IPv6 endpoints and report unsupported node types as skipped.
- Include documented Hysteria2 ALPN, bandwidth, and Salamander settings in Surge subscriptions.
- Apply protocol and tag filters to legacy subscription nodes and include their matching fields in snapshot invalidation.
- Mark ambiguous Komari dispatch responses for reconciliation and block further remote mutations until the machine has been checked and the alert handled.
- Explain blocked machine install targets and uncertain remote tasks in the workspace.

## [1.0.5] - 2026-11-10

- Show every supported native client format in existing subscription link dialogs, including Loon and Quantumult X.
- Keep the profile's configured pre-generated formats and token unchanged; generate other formats on demand.

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
