# SQLite schema v6 migration and rollback

Schema v6 separates scheduler state by canonical Provider and adds the
`usage_events.generate` flag. The plugin performs the upgrade automatically on
the first open of a v0-v5 database.

## Upgrade guarantees

- The migration obtains a dedicated SQLite `BEGIN IMMEDIATE` writer lock and
  re-reads `PRAGMA user_version` after the lock is held. Concurrent plugin
  processes therefore do not run the upgrade twice.
- Table creation, row copying, deterministic duplicate selection, index
  replacement, and the `user_version=6` update are committed as one
  transaction. A failed migration leaves the previous schema and rows intact.
- Empty legacy Provider values in `invalid_auths` and `autoban_bans` become
  `codex`; empty values in `xai_account_states` become `xai`. Non-empty values
  are trimmed and lowercased. Unsupported Providers are retained as inert
  historical rows and are reported by diagnostics; schedulers do not consume
  them.
- Empty legacy Provider values in `usage_events`, `quota_trigger_runs`, and
  `account_protection_reservations` become `codex`. Explicit non-empty values
  are trimmed, lowercased, and retained; they are never silently reassigned to
  another Provider.
- Duplicate legacy rows are merged only within the same canonical
  Provider/identity group. The complete winning row is copied; fields from
  different rows are never combined. The deterministic order is:
  - `invalid_auths`: active first, then `invalidated_at`, status, auth-file
    mtime/name, reason, auth index, source, and original rowid, all descending;
  - `autoban_bans`: newest effective event first, where a later explicit
    release uses `released_at` and otherwise the ban uses `banned_at`; an
    inactive release wins an active row at the same effective time, followed
    by reset/ban/release time, status, release reason, reason, window, auth
    index, source, and original rowid;
  - `xai_account_states`: active first, then observed/reset time, status,
    auth-file mtime, state, reason, auth file/id/index/source, and original
    rowid, all descending.
- Usage events, quota-trigger runs, and reservations preserve their complete
  rows and original IDs; they are not merged by account alias.
- Existing usage rows receive `generate=1`, preserving pre-v6 accounting.
- A v0.1.38 or older plugin is not a supported reader or downgrade tool for a
  v6 database. Its legacy initializer performs idempotent schema/column probes
  before it notices the newer `user_version`, so do not point it at the live v6
  file or rely on it as a no-write verifier. Restore the complete v5 backup
  before starting an older plugin.

The cross-process guarantees apply to SQLite on a supported local filesystem.
They are not claimed for NFS, SMB, cloud-synchronized folders, or other network
filesystems.

## Safe backup before upgrade

Do not copy only an active `usage.db`; committed pages may still be in the WAL.
Use one of these methods:

1. Stop every writer, then copy `usage.db` together with any `usage.db-wal` and
   `usage.db-shm` sidecars.
2. Use the SQLite backup API or the CLI `.backup` command while the database is
   live.
3. Use `VACUUM INTO` to create a consistent standalone copy.

Example with the SQLite CLI:

```sql
.open usage.db
.backup usage-v5-backup.db
PRAGMA quick_check;
PRAGMA user_version;
```

Record a cryptographic checksum for the backup and keep it outside the plugin
data directory.

## Verification

Run these checks on both the backup and the upgraded database:

```sql
PRAGMA quick_check;
PRAGMA user_version;

SELECT COUNT(*) FROM usage_events;
SELECT COUNT(*), SUM(active) FROM invalid_auths;
SELECT COUNT(*), SUM(active) FROM autoban_bans;
SELECT COUNT(*), SUM(active) FROM xai_account_states;

SELECT provider, COUNT(*), SUM(active)
FROM invalid_auths
GROUP BY provider
ORDER BY provider;

SELECT provider, COUNT(*), SUM(active)
FROM autoban_bans
GROUP BY provider
ORDER BY provider;

SELECT provider, COUNT(*), SUM(active)
FROM xai_account_states
GROUP BY provider
ORDER BY provider;
```

`PRAGMA user_version` must be `6` after upgrade, `quick_check` must return `ok`,
and the recorded totals and Provider distribution must match the expected
migration rules.

## Rollback

There is no in-place downgrade. To return to v0.1.38:

1. Stop every plugin/CPA process that can write the database.
2. Move the complete v6 database and sidecars aside for investigation.
3. Restore the complete v5 backup made with one of the safe methods above.
4. Verify its checksum, run `PRAGMA user_version;` and confirm that it returns
   `5`, then verify `PRAGMA quick_check`, row totals, active totals, and Provider
   distribution. Do not assign `user_version` during rollback verification.
5. Only then start the older plugin.
