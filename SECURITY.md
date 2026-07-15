# Security Policy

## Supported versions

Security fixes are applied to the latest GitHub Release and the `main` branch. Older releases should be upgraded before reporting behavior that is already fixed in the latest version.

## Reporting a vulnerability

Do not disclose credential, privacy, authentication, scheduler-bypass, or remote-code-execution details in a public issue.

When the repository's **Report a vulnerability** button is available, use GitHub Private Vulnerability Reporting:

https://github.com/yujianwudi/codex-token-usage/security/advisories/new

If private reporting is unavailable, open a public issue containing only a request for a private contact channel. Do not include secrets, proof-of-concept payloads, vulnerable account data, or reproduction details in that issue.

Please include, when available:

- The affected plugin and CLIProxyAPI versions and operating system.
- The security impact and the minimum steps needed to reproduce it.
- Whether real OAuth credentials, API keys, or account data were involved.
- Suggested mitigations or patches.

Remove or replace all live access tokens, refresh tokens, ID tokens, API keys, cookies, and identifying account data before sharing diagnostics.

We aim to acknowledge a complete report within 3 business days, provide an initial assessment within 7 business days, and coordinate disclosure after a fix is available. Complex host-ABI or upstream-provider issues may require additional time.

## Scope

Security-sensitive areas include credential import and storage, privacy migrations, management API authorization, dashboard output escaping, scheduler restrictions, release artifacts, dependency provenance, and filesystem permissions.

Denial-of-service reports should demonstrate a practical impact beyond expected local resource limits. Reports that require an attacker to already control the plugin process or replace its installed binary are generally outside scope unless they expose credentials or bypass an existing trust boundary.
