# CPA Token Usage

CPA Token Usage is a CLIProxyAPI plugin for Codex account operation dashboards and AI provider usage analytics.

Current version: `0.1.39`

Release status: published binaries are listed on GitHub Releases. A source version, changelog entry, candidate artifact, or workflow run is not by itself authorization to create a tag or Release.

See the [changelog](CHANGELOG.md) for version history, the [release candidate acceptance runbook](docs/release-candidate-acceptance.md) for the independent handoff, and [SECURITY.md](SECURITY.md) for private vulnerability reporting.

## Features

- Codex account pool dashboard with pagination, saved sorting, quota bars, 7d/month quota estimates, cost estimates, and light/dark compatible UI.
- AI provider pages grouped by CPA endpoint name, separated from Codex OAuth account-pool pricing and quota calculations.
- Codex 429 auto-ban support with `reset_at` based recovery.
- 401 invalid-auth protection until the auth JSON file is replaced or removed.
- Suspicious external quota consumption detection for shared or resold accounts.
- Optional Codex quota trigger that sends a tiny real Codex request to refresh/start the 5h quota window.
- Runtime diagnostics and local alerts are exposed in summary JSON for troubleshooting and plugin-store validation.
- CSV / JSON export support; the dashboard exposes account export buttons and the backend can export accounts, providers, models, and recent requests.
- Built-in price fallbacks plus automatic LiteLLM model price updates.
- Manual Chinese / English language switch saved in the browser.
- xAI account-pool dashboard for xAI OAuth JSON credentials, with xAI-specific 401/403/429 and free-usage-exhausted states.
- xAI accounts are read through CPA `host.auth.list/get/get_runtime` when available, with filesystem fallback for older CPA versions; account rows classify Free, Super, and Heavy tiers from auth metadata.
- Non-standard Codex credential import converts ChatGPT Session, sub2api/account-product, 9router, Codex auth.json, AxonHub, Codex-Manager, and generic nested token JSON through CPA `host.auth.save`, with preview, conflict detection, and no-refresh-token warnings.
- Optional account-protection scheduling for Codex OAuth accounts: per-plan concurrency hard limits and rolling-window Token soft demotion.
- Account-protection and error filtering preserve CPA round-robin rotation within the highest-priority candidate tier.
- Provider-scoped state keys prevent Codex, xAI, and unsupported historical Provider rows with the same identity from changing one another's scheduler state.
- Mixed routes remove only quarantined, restricted, inactive, or saturated candidates; a lower-priority healthy Provider remains available and the request is rejected only when no safe candidate remains.
- Scheduler restriction snapshots use durable Provider revisions to detect committed state changes from another plugin process without restoring the historical full-table maintenance work on every pick.

## Install Manually

Official releases support Linux on amd64 and arm64. Download the matching release zip, then place the dynamic library under the CLIProxyAPI plugin directory:

```text
plugins/linux/amd64/codex-token-usage.so
plugins/linux/arm64/codex-token-usage.so
```

Restart CLIProxyAPI after replacing the file.

## Configuration

The plugin is configured under:

```yaml
plugins:
  enabled: true
  configs:
    codex-token-usage:
      enabled: true
      priority: 120

      开启定时额度触发: false
      触发间隔分钟: 10
      触发模式: probe # quota=只读额度 GET；probe=最小真实请求
      最大并发账号数: 1
      单账号超时秒数: 20
      单账号最小冷却分钟: 10

      开启账号保护调度: false
      Free 并发上限: 2
      Plus 并发上限: 5
      K12 并发上限: 5
      Team 并发上限: 5
      Pro 并发上限: 10
      Free 5 分钟 Token 上限: 2000000
      Plus 5 分钟 Token 上限: 8000000
      K12 5 分钟 Token 上限: 8000000
      Team 5 分钟 Token 上限: 8000000
      Pro 5 分钟 Token 上限: 12000000
      账号保护 Token 窗口秒数: 300
      账号保护预约超时秒数: 900

      自动更新模型价格表: true
      模型价格更新间隔小时: 6
      模型价格表地址: https://raw.githubusercontent.com/BerriAI/litellm/main/model_prices_and_context_window.json
      模型价格更新超时秒数: 20

      用量保留天数: 90
      额度触发记录保留天数: 30
      请求明细保留天数: 30
```

English config keys are also accepted:

```yaml
quota_trigger_enabled: false
quota_trigger_interval_minutes: 10
quota_trigger_mode: probe # quota = read-only quota GET; probe = minimal model request
quota_trigger_max_concurrency: 1
quota_trigger_timeout_seconds: 20
quota_trigger_min_account_cooldown_minutes: 10
account_protection_enabled: false
account_protection_free_concurrency: 2
account_protection_plus_concurrency: 5
account_protection_k12_concurrency: 5
account_protection_team_concurrency: 5
account_protection_pro_concurrency: 10
account_protection_free_token_limit: 2000000
account_protection_plus_token_limit: 8000000
account_protection_k12_token_limit: 8000000
account_protection_team_token_limit: 8000000
account_protection_pro_token_limit: 12000000
account_protection_token_window_seconds: 300
account_protection_reservation_ttl_seconds: 900
model_price_auto_update_enabled: true
model_price_update_interval_hours: 6
model_price_update_url: https://raw.githubusercontent.com/BerriAI/litellm/main/model_prices_and_context_window.json
model_price_update_timeout_seconds: 20
usage_retention_days: 90
quota_trigger_retention_days: 30
request_detail_retention_days: 30
```

Quota trigger defaults to off. `quota` mode performs a read-only GET against the Codex usage endpoint and does not send a model probe request. `probe` mode sends a real minimal Codex model request, so it can consume a small amount of tokens and may affect quota.

`request_detail_retention_days` remains accepted for configuration compatibility. Request-detail data currently lives with `usage_events`, so its effective retention follows `usage_retention_days` until a separate detail store is introduced.

## Scheduler and Usage Semantics

Account protection reserves capacity in an SQLite `BEGIN IMMEDIATE` transaction. Capacity read, candidate selection, reservation insertion, and commit form one cross-process critical section. A confirmed full account returns `account_protection_saturated` with HTTP 503; a busy, unavailable, or failed database transaction returns `scheduler_unavailable` with HTTP 503 and never dispatches fail-open. This guarantee applies to supported local SQLite filesystems, not NFS, SMB, cloud-synchronized folders, or other network shares.

Every terminal usage callback attempts to release at most one reservation for the same canonical Provider and strict credential/file identity. CLIProxyAPI v7.2.80 has no reservation token and no dispatch-failed/cancelled callback, so callbacks that never arrive are recovered only by the configured reservation TTL. Duplicate or out-of-order callbacks are therefore reported as `legacy_uncorrelated_release`; exactly-once release is not claimed. See [Reservation lifecycle and CPA ABI limits](docs/reservation-lifecycle-abi.md).

`Usage.Generate` is presence-aware: omitted values remain compatible with older Hosts and are normalized to `true`. `Generate=true` contributes to request, token, cost, latency, throughput, model, Provider, account, and protection-window metrics. `Generate=false` remains in recent/audit data and exports and still attempts to release at most one matching terminal reservation, but does not count as a model generation or add token/cost totals. A non-generation 401 remains an explicit credential signal; ordinary non-generation 4xx/5xx and 429 responses without quota evidence do not create restrictions.

Opening a v0-v5 database upgrades it atomically to schema v6. Back up active SQLite databases with the SQLite backup API, `.backup`, `VACUUM INTO`, or a stopped-writer copy that includes WAL/SHM sidecars; never copy only an active main `.db` file. See [SQLite schema v6 migration and rollback](docs/sqlite-v6-migration.md).

## Data Directory and Path Overrides

The plugin stores its SQLite database, API-key fingerprint secret, and downloaded model price table under a private Linux data directory:

| Platform | Default data directory |
| --- | --- |
| Linux | `~/.cli-proxy-api/plugins/codex-token-usage` |

Set `CPA_TOKEN_USAGE_DIR` to override the complete plugin data directory. The following related path settings are also supported:

- `CPA_MODEL_PRICE_FILE`: downloaded model price table file.
- `CPA_AUTH_DIR`: CLIProxyAPI credential directory.
- `CPA_CONFIG_PATH` or `CPA_CONFIG_FILE`: CLIProxyAPI configuration file.

The process account must be able to create and update the selected directory. On Linux, the plugin creates its private directory with mode `0700` and sensitive files with mode `0600`.

## Model Price Table

The plugin includes a small built-in fallback price table. By default it also downloads and refreshes the full LiteLLM-style model price table from:

```text
https://raw.githubusercontent.com/BerriAI/litellm/main/model_prices_and_context_window.json
```

The downloaded file is stored as `model_prices.json` in the data directory described above. To override only this file, set:

```bash
CPA_MODEL_PRICE_FILE=/path/to/model_prices.json
```

The file is about 1.5 MB and is not bundled into release zips, so plugin binaries stay smaller and prices can be refreshed without rebuilding the plugin.

## Data Safety

- Access tokens, refresh tokens, and id tokens are not written to summary JSON, UI, alert output, or exports.
- Starting with `0.1.33`, API keys are persisted only as a keyed HMAC fingerprint plus a non-sensitive last-four display suffix. Version `0.1.34` extends that protection to derived scheduler/auth-state identities and locally re-keys legacy unkeyed fingerprints.
- The standard `usage.db` fingerprint key remains `.api-key-hmac` for upgrade compatibility; non-standard databases receive database-scoped sidecars so two databases in one directory cannot share an identity namespace. The key identifier is also bound inside its database. Keep the database and sidecar together when backing up or moving an installation. A missing, corrupt, or mismatched bound secret fails closed instead of silently creating a new namespace.
- During the v3 privacy migration, legacy `keyfp:v0` identities are forward-mapped to normal v1 HMAC fingerprints when the corresponding API key is still configured. Unmatched historical rows are locally re-keyed and reported as `legacy_unlinkable_rows`. If an unmatched v0 identity is the sole identity of an active restriction, only that provider enters a fail-closed privacy quarantine: its scheduler requests return 503 while Dashboard/summary management remains available. Restore the corresponding configured API key and restart to recover and re-key automatically, or explicitly release the legacy restriction and restart to clear the quarantine.
- Exported account labels and API-key fields are masked, and CSV cells that could be interpreted as spreadsheet formulas are neutralized.
- Dashboard-provided text is escaped before insertion into HTML. Inline JavaScript is authorized by an exact SHA-256 CSP hash, and the plugin no longer copies the transient management key into browser Web Storage.
- Local alert data is generated inside summary/export responses only; this version does not send webhooks.
- Auth JSON files are read only for account identity, provider classification, quota trigger access, and replacement detection. Tokens are used in memory for trigger requests and are not written to summary/export data.
- xAI tier classification stores only the normalized tier and an allowlisted metadata-field label; raw note, label, tag, name, and nested metadata values are not copied into Summary or the SQLite summary cache.

## Build

Release builds use Go `1.26.5` with CGO enabled. A Linux C compiler, `zip`, and Python 3 are required for the full packaging and ABI smoke workflow.

```bash
go test ./...
./build.sh
./package-release.sh dist
```

`package-release.sh` validates that `PLUGIN_VERSION` matches `pluginVersion` in `main.go`. The Release workflow additionally requires the requested `vX.Y.Z`, injected binary version, source version, and asset filenames to agree.

The normal Release workflow is dispatched from an unmerged candidate branch whose commit is a fast-forward descendant of the current `main`. It builds one candidate bundle before its publish job enters the `independent-release` Environment. The verified bundle is uploaded once, and its identity is the lowercase SHA-256 digest of `checksums.txt`. After independent acceptance, that exact commit must be promoted to `main` without merge, squash, or rebase SHA changes. Publication then requires the exact `vX.Y.Z@40-character-commit@64-character-bundle-digest` triple in the Environment's `CPA_INDEPENDENT_ACCEPTED_RELEASES` variable plus Environment approval. The publish job rechecks that `origin/main` is the accepted commit and that the CPA compatibility lock still names the latest published CPA release; only then does the same run attest the downloaded candidate, create or safely resume its annotated tag, and publish those exact files without rebuilding. An emergency repository-owner waiver is also available but defaults off: the exact candidate SHA must already equal `origin/main`, the actor must be the repository owner, and `waiver_confirmation` must equal `WAIVE_SECOND_MACHINE_vX.Y.Z`. Waived tags and Release notes explicitly record that independent acceptance did not occur; automated source, CPA, build, asset, and provenance gates remain mandatory. See the [independent acceptance runbook](docs/release-candidate-acceptance.md).

CI and the Release workflow both run the scheduler benchmark suite three times, enforce the checked-in performance budgets, and retain the raw benchmark output as an Actions artifact for review.

CI first confirms that `scripts/cpa-compat.lock` still points to GitHub's latest published CLIProxyAPI release, then builds and dynamically loads the plugin against that exact commit. External CPA init/test code runs in a digest-pinned Go container with no network, no capabilities, a read-only root filesystem, and only the task-local work directory mounted; it cannot modify the runner workspace, Actions post hooks, Docker socket, or shared Go caches. This ABI/RPC gate exercises the real CPA Host registration, `ApplyConfig`/reconfiguration, guarded client, `PickAuth`, in-process usage adapter (including omitted/true/false `Generate`), management resources, host-auth callbacks, Provider pollution, mixed partial availability, hard-limit behavior, and shutdown/re-init. It also starts two independent CPA Host processes against one SQLite database with a reservation limit of one and a synchronized barrier, requiring exactly one success and one saturated result; the internal stress gate retains the fuller 2/4/8-process and crash/lock-recovery coverage. The same real CPA loader also loads a build-tagged test library and injects init/call/free/shutdown panics; exported test controls and panic markers are rejected from the release-compatible library. The gate injects usage through the Host adapter; it does not run a Provider network executor or prove that a real request emitted its terminal usage callback. That Provider-executor end-to-end lifecycle remains a separate independent acceptance item and must not be replaced by direct usage RPC calls. To run the ABI/RPC gate locally on Linux:

```bash
bash scripts/check-cpa-compat.sh
```

Set `CPA_SOURCE_DIR` to an existing CLIProxyAPI checkout containing the resolved commit to avoid downloading its source archive. Set `CPA_COMPAT_CHANNEL=locked` for a reproducible local check of the audited lock (it still downloads that exact source archive unless `CPA_SOURCE_DIR` is set), or `CPA_COMPAT_CHANNEL=latest-main` to probe unreleased upstream changes. Local runs default to host execution; set `CPA_COMPAT_EXECUTION_MODE=docker` to use the same restricted container when Docker is available. GitHub Actions refuses host execution. Main CI and the Release workflow both resolve GitHub's latest published CPA release, require the lock tag and commit to match it, and dynamically test that exact source; a stale lock blocks release publication. A scheduled GitHub Actions watch tests both the latest published release and latest `main`.

Official Linux archives are built in an Ubuntu 20.04 container and gated to require no newer than glibc `2.31`. They support glibc-based distributions such as Ubuntu 20.04+ and Debian 11+. Alpine Linux uses musl and is not supported by these CGO release binaries.

Each Linux zip contains the dynamic library, `LICENSE`, and `THIRD_PARTY_NOTICES.md`. Releases always publish per-architecture SPDX JSON SBOMs and SHA-256 checksums. Public repositories also publish GitHub build provenance attestations; the workflow skips only that attestation step for repositories where GitHub attestations are unavailable, without blocking the remaining release assets.

Release assets are named in the CLIProxyAPI plugin store format:

```text
codex-token-usage_0.1.39_linux_amd64.zip
codex-token-usage_0.1.39_linux_arm64.zip
codex-token-usage_0.1.39_linux_amd64.spdx.json
codex-token-usage_0.1.39_linux_arm64.spdx.json
checksums.txt
```

### Verify a Release

Download `checksums.txt` together with both Linux archives and both SPDX JSON files into the same directory. The checksum manifest intentionally covers all four assets, so verify the complete set before installing the plugin:

```bash
sha256sum -c checksums.txt
```

Public releases also carry GitHub build provenance. Set `SOURCE_DIGEST` to the 40-character commit reached by the release tag, as shown on the GitHub Release page, then verify each downloaded asset against the expected repository, workflow, commit, and GitHub-hosted runner:

```bash
VERSION=0.1.39
ASSET="codex-token-usage_${VERSION}_linux_amd64.zip"
SOURCE_DIGEST="<40-character release commit SHA>"

gh attestation verify "${ASSET}" \
  --repo yujianwudi/codex-token-usage \
  --signer-workflow yujianwudi/codex-token-usage/.github/workflows/release.yml \
  --source-digest "${SOURCE_DIGEST}" \
  --deny-self-hosted-runners
```

Repeat the attestation command for the SPDX JSON file and `checksums.txt`. The workflow is dispatched from the independently tested candidate branch and attests the accepted files before creating the annotated release tag. Verification therefore binds the repository, workflow, source digest, and hosted runner without claiming a tag-ref attestation. The source digest is the commit referenced by the final tag, not the annotated tag-object SHA.

## Plugin Store Checklist

- Build and upload both supported Linux architecture zip files.
- Include `checksums.txt`, per-architecture SPDX SBOMs, and license notices. Public repositories must also publish GitHub provenance attestations; where attestations are unavailable, only that attestation step may be skipped.
- Add screenshots for the Codex account pool, AI provider overview, and a selected AI endpoint page.
- Document both quota-trigger modes: read-only `quota` GET behavior and the real-probe token cost risk of `probe`.
- Confirm `go test ./...` passes before publishing.

## Common Issues

- Auth import uses the host's synchronous `host.auth.*` callback ABI. Cancellation is checked before and between callbacks, but a callback that is already running cannot be interrupted by the plugin; shutdown therefore waits for the host callback to return.

- `未注册 / 未生效`: confirm the file is under the correct plugin directory and restart CLIProxyAPI.
- `401`: the auth JSON is invalid and will not be used until replaced or removed.
- `429`: the account is temporarily auto-banned until the observed reset time.
- Provider not visible: confirm the endpoint still exists in CPA config and refresh the dashboard.
- Price missing: check `model_prices.json` status in the summary JSON and the model price update error if present.

## License

MIT
