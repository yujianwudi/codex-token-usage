# Changelog

This file records user-visible changes and explicitly documents tags that were not published as GitHub Releases.

## 0.1.37 - 2026-07-16

- Enforces account-protection concurrency as a true hard limit and returns an HTTP 503 scheduler rejection without creating excess reservations.
- Preserves Codex session affinity when the plugin takes over scheduling, moving a session only when its bound credential reaches the configured hard limit.
- Serves the expensive protection usage index with bounded stale-while-refresh behavior so normal scheduler picks do not queue behind SQLite aggregation.
- Adds a pinned real dynamic-loader compatibility gate for CLIProxyAPI `b6ce0beecd31dff389d3190f7db6d7a1d4ce0e7e`, covering ABI/schema 1, registration, reconfiguration, scheduler callbacks, usage, management resources, host auth callbacks, affinity, and hard-limit rejection behavior.
- Uses `host.auth.list` as the authoritative Codex credential source, including runtime-only accounts, with non-authoritative filesystem fallback that cannot clear host-only restriction state.
- Closes scheduler snapshot race windows around Codex and xAI restriction writes.
- Hardens credential privacy, auth-file scanning, redirect handling, diagnostic path and URL redaction, browser secret cleanup, and database-scoped fingerprint health reporting.
- Adds Go, shell, and workflow formatting gates, complete third-party license notices, a security policy, release-note ancestry checks, and stronger checksum and provenance documentation.

## 0.1.36 - 2026-07-16

This release includes both the unpublished `0.1.35` changes and the `0.1.36` release-network hardening.

- Removed scheduler startup scans and unnecessary snapshot invalidation from the request path.
- Added generation-safe protection-state refresh, stricter reservation transitions, cancellable lifecycle operations, and schema v5 migration handling.
- Strengthened credential redaction, API-key privacy migration, private-file permissions, release asset allowlists, SBOM validation, and provenance coverage.
- Added bounded APT retries, strict update error handling, IPv4 selection, and network timeouts for Linux release builds.

See [PR #4](https://github.com/yujianwudi/codex-token-usage/pull/4) and [PR #5](https://github.com/yujianwudi/codex-token-usage/pull/5).

## 0.1.35 - Unpublished

The `v0.1.35` tag is retained for audit history, but its Linux arm64 build repeatedly failed before source compilation because `ports.ubuntu.com` timed out. No GitHub Release or supported release assets were published for this tag. Its changes were superseded and published in `0.1.36`.

Consumers should use `0.1.36` or later and must not treat the `v0.1.35` source tag as a complete binary release.

[0.1.36]: https://github.com/yujianwudi/codex-token-usage/releases/tag/v0.1.36
[0.1.37]: https://github.com/yujianwudi/codex-token-usage/releases/tag/v0.1.37
