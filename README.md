# CPA Token Usage

CPA Token Usage is a CLIProxyAPI plugin for Codex account operation dashboards and AI provider usage analytics.

Current version: `0.1.33`

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

## Install Manually

Download the matching release zip, then place the dynamic library under the CLIProxyAPI plugin directory:

```text
plugins/linux/amd64/codex-token-usage.so
plugins/windows/amd64/codex-token-usage.dll
plugins/darwin/arm64/codex-token-usage.dylib
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
      触发模式: probe
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
quota_trigger_mode: probe
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

Quota trigger defaults to off. `probe` mode sends a real minimal Codex model request, so it can consume a small amount of tokens and may affect quota. The legacy `quota` value is accepted for compatibility and normalized to `probe`; scheduled triggers no longer only read cached quota state.

## Data Directory and Path Overrides

The plugin stores its SQLite database, API-key fingerprint secret, and downloaded model price table under an OS-specific private data directory:

| Platform | Default data directory |
| --- | --- |
| Linux | `~/.cli-proxy-api/plugins/codex-token-usage` |
| macOS | `~/Library/Application Support/CLIProxyAPI/plugins/codex-token-usage` |
| Windows | `%LOCALAPPDATA%\CLIProxyAPI\plugins\codex-token-usage` |

Set `CPA_TOKEN_USAGE_DIR` to override the complete plugin data directory. The following related path settings are also supported:

- `CPA_MODEL_PRICE_FILE`: downloaded model price table file.
- `CPA_AUTH_DIR`: CLIProxyAPI credential directory.
- `CPA_CONFIG_PATH` or `CPA_CONFIG_FILE`: CLIProxyAPI configuration file.

The process account must be able to create and update the selected directory. On Unix-like systems, the plugin creates its private directory with mode `0700` and sensitive files with mode `0600`.

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
- Starting with `0.1.33`, API keys are persisted only as a keyed HMAC fingerprint plus a non-sensitive last-four display suffix. Existing plaintext API-key rows are migrated on first startup; back up `usage.db` before upgrading if the historical database is operationally important.
- The local fingerprint key is stored as `.api-key-hmac` in the private plugin data directory. Keep this file together with `usage.db` when moving an installation.
- Exported account labels and API-key fields are masked, and CSV cells that could be interpreted as spreadsheet formulas are neutralized.
- Dashboard-provided text is escaped before insertion into HTML.
- Local alert data is generated inside summary/export responses only; this version does not send webhooks.
- Auth JSON files are read only for account identity, provider classification, quota trigger access, and replacement detection. Tokens are used in memory for trigger requests and are not written to summary/export data.

## Build

Release builds use Go `1.26.5` with CGO enabled. A platform C compiler, `zip`, and Python 3 are required for the full packaging and Linux ABI smoke workflow.

```bash
go test ./...
./build.sh
./package-release.sh dist
```

`package-release.sh` validates that `PLUGIN_VERSION` matches `pluginVersion` in `main.go`. Tagged releases additionally require the `vX.Y.Z` tag, injected binary version, source version, and asset filenames to agree.

Official Linux archives are built in an Ubuntu 20.04 container and gated to require no newer than glibc `2.31`. They support glibc-based distributions such as Ubuntu 20.04+ and Debian 11+. Alpine Linux uses musl and is not supported by these CGO release binaries.

Each platform zip contains the dynamic library, `LICENSE`, and `THIRD_PARTY_NOTICES.md`. Releases always publish per-platform SPDX JSON SBOMs and SHA-256 checksums. Public repositories also publish GitHub build provenance attestations; the workflow skips only that attestation step for repositories where GitHub attestations are unavailable, without blocking the remaining release assets.

Release assets are named in the CLIProxyAPI plugin store format:

```text
codex-token-usage_0.1.33_linux_amd64.zip
codex-token-usage_0.1.33_linux_arm64.zip
codex-token-usage_0.1.33_windows_amd64.zip
codex-token-usage_0.1.33_darwin_amd64.zip
codex-token-usage_0.1.33_darwin_arm64.zip
checksums.txt
```

## Plugin Store Checklist

- Build and upload all required OS / architecture zip files.
- Include `checksums.txt`, per-platform SPDX SBOMs, and license notices. Public repositories must also publish GitHub provenance attestations; where attestations are unavailable, only that attestation step may be skipped.
- Add screenshots for the Codex account pool, AI provider overview, and a selected AI endpoint page.
- Document default-off quota trigger behavior and real-probe token cost risk.
- Confirm `go test ./...` passes before publishing.

## Common Issues

- `未注册 / 未生效`: confirm the file is under the correct plugin directory and restart CLIProxyAPI.
- `401`: the auth JSON is invalid and will not be used until replaced or removed.
- `429`: the account is temporarily auto-banned until the observed reset time.
- Provider not visible: confirm the endpoint still exists in CPA config and refresh the dashboard.
- Price missing: check `model_prices.json` status in the summary JSON and the model price update error if present.

## License

MIT
