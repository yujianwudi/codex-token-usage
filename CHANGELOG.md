# Changelog

This file records user-visible changes and explicitly documents tags that were not published as GitHub Releases.

## 0.1.39 - Release notes

This entry documents the source changes for `0.1.39`. Publication status is determined only by GitHub Releases; this changelog entry never authorizes tag or Release creation.

- Upgrades SQLite atomically to schema v6 with canonical, non-empty Provider constraints; Provider-scoped keys for Codex invalid/autoban state, xAI state, reservations, usage, and quota-trigger data; deterministic whole-row duplicate selection; inert preservation and diagnostics for foreign historical rows; v0-v5 fixtures, fault rollback, and concurrent-process migration coverage.
- Makes mixed scheduling partially available: quarantined, restricted, inactive, and saturated candidates are removed without rejecting healthy Providers; Host priority, rotation, affinity re-selection, third Providers, same-tier fallback, and lower-priority protected-Codex fallback remain enforced.
- Moves account-protection capacity decisions into a Provider-scoped SQLite `BEGIN IMMEDIATE` critical section with bounded lock waits, fail-closed busy handling, transactional terminal release, TTL/crash recovery, and 2/4/8-process stress gates.
- Adds durable Codex, xAI, and privacy revisions so another plugin process observes committed restrictions, releases, and quarantine changes before its next pick without cross-Provider invalidation.
- Adds presence-aware `Usage.Generate`: omitted defaults to true; false remains in audit/recent/export data and attempts to release at most one matching reservation, but is excluded from generation request, token, cost, latency, throughput, Provider, model, account, and protection-window totals.
- Adds top-level panic boundaries for all four C ABI exports, best-effort shutdown isolation, a test-only panic shared library exercised by both a native repeated-loop harness and the real CPA loader, and release-asset checks proving panic controls are absent.
- Hardens public errors and diagnostics so SQLite paths, SQL errors, auth paths, secrets, and raw xAI metadata values do not reach management responses, Summary, or the summary cache.
- Adds bounded fuzz gates for Provider/alias canonicalization, mixed filtering, and historical migration plus lifecycle, privacy-snapshot, and reservation-cleanup race stress.
- Enforces repeatable scheduler performance budgets from three benchmark samples in both CI and candidate builds, retaining the raw benchmark output as review evidence.
- Builds and uploads one verified candidate bundle from an unmerged fast-forward branch before the publish job enters the `independent-release` Environment; after second-machine acceptance, requires exact-SHA promotion to `main` plus the `tag@commit@bundle-digest` authorization; then creates or safely resumes an annotated tag and publishes the same files without rebuilding.
- Fixes the CLIProxyAPI compatibility gate for CRLF worktrees created on Windows and executed under WSL or Unix CI by forcing lock files to LF, parsing the lock as validated data instead of shell code, and accepting existing CRLF worktrees safely.
- Verifies online that the audited CLIProxyAPI tag and commit are still GitHub's latest published release before CI, candidate packaging, and final tag creation proceeds, and updates the audited ABI/RPC dynamic-loader target to `v7.2.80` (`09da52ad509e2c18e7b9540db3b98c2214c280aa`). The gate uses the real Host registration/reconfiguration/pick/management/shutdown lifecycle, in-process usage adapter, and a synchronized two-CPA-process shared-SQLite hard-limit check; a real CPA executor routed only to a controlled local mock upstream remains a separate independent acceptance item.
- Downloads immutable CPA source archives with bounded network timeouts and adds CRLF/unknown/duplicate lock tests plus a scheduled compatibility watch for the latest published CPA release and unreleased `main`.

## 0.1.38 - 2026-07-16

This release includes all `0.1.37` changes and fixes the final GitHub Release publication step.

- Checks out complete Git history in the publish job so the previous published release can be verified as an ancestor without a shallow-clone false negative.

## 0.1.37 - Unpublished

The immutable `v0.1.37` tag is retained for audit history. All source-security checks, five platform builds, binary scans, SBOM generation, and the complete 11-asset bundle verification passed, but GitHub Release publication stopped before attestation because the publish job's depth-1 checkout could not prove the real `v0.1.36` parent relationship. The same code and verified release contents are superseded by `0.1.38`.

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
[0.1.37]: https://github.com/yujianwudi/codex-token-usage/tree/v0.1.37
[0.1.38]: https://github.com/yujianwudi/codex-token-usage/releases/tag/v0.1.38
