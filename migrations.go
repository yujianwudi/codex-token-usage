package main

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
	"strings"
)

const currentSQLiteSchemaVersion = 6

var sqliteMigrationV6FaultHook func(context.Context, *sql.Tx, string) error

func sqliteMigrationV6Checkpoint(ctx context.Context, tx *sql.Tx, stage string) error {
	if sqliteMigrationV6FaultHook == nil {
		return nil
	}
	return sqliteMigrationV6FaultHook(ctx, tx, stage)
}

func migrateSQLiteStore(ctx context.Context, db *sql.DB, dbPath string) error {
	var version int
	if err := db.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&version); err != nil {
		return err
	}
	if version > currentSQLiteSchemaVersion {
		return fmt.Errorf("usage database schema %d is newer than supported schema %d", version, currentSQLiteSchemaVersion)
	}
	if version == currentSQLiteSchemaVersion {
		return verifySQLiteV6Schema(ctx, db)
	}

	// Use a one-connection handle whose driver-level transaction lock is
	// IMMEDIATE. Two plugin processes may race during an upgrade; the second one
	// waits for the first writer, then re-reads user_version inside the lock.
	migrationDB, err := sql.Open("sqlite3", sqliteMigrationDSN(dbPath))
	if err != nil {
		return err
	}
	migrationDB.SetMaxOpenConns(1)
	migrationDB.SetMaxIdleConns(1)
	defer migrationDB.Close()
	conn, err := migrationDB.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if err := tx.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&version); err != nil {
		return err
	}
	if version > currentSQLiteSchemaVersion {
		return fmt.Errorf("usage database schema %d is newer than supported schema %d", version, currentSQLiteSchemaVersion)
	}
	if version == currentSQLiteSchemaVersion {
		if err := tx.Commit(); err != nil {
			return err
		}
		return verifySQLiteV6Schema(ctx, db)
	}

	// Bootstrap only CREATE TABLE statements first. Running schemaSQL as a
	// whole against an old table can fail on a new index before the table has
	// received its additive columns. Both bootstrap and all ALTER/DDL below are
	// protected by the same IMMEDIATE transaction.
	if err := createSQLiteSchemaTables(ctx, tx); err != nil {
		return err
	}
	if err := sqliteMigrationV6Checkpoint(ctx, tx, "bootstrap-create"); err != nil {
		return err
	}
	// Keep every additive prerequisite in the same transaction as the privacy
	// and provider-key rewrites. In particular, v3 identity migration requires
	// reservation auth_file, while v6 adds generate for historical usage rows.
	if err := ensureSQLiteMigrationColumns(ctx, tx); err != nil {
		return err
	}
	if err := sqliteMigrationV6Checkpoint(ctx, tx, "additive-columns"); err != nil {
		return err
	}
	if version < 3 {
		if err := bindAPIKeyFingerprintSecret(ctx, tx, dbPath); err != nil {
			return err
		}
		if err := sqliteMigrationV6Checkpoint(ctx, tx, "secret-binding"); err != nil {
			return err
		}
	}
	if version < 4 {
		// Millisecond reset timestamps were accepted by early releases. Normalize
		// them once during the schema upgrade instead of scanning the potentially
		// large usage_events table on every process start.
		if err := normalizeStoredResetColumns(ctx, tx); err != nil {
			return err
		}
		if err := sqliteMigrationV6Checkpoint(ctx, tx, "reset-normalization"); err != nil {
			return err
		}
	}
	if version < 5 {
		// Reservations belong to in-flight calls from the previous plugin
		// process. They cannot be assigned safely to the new file-scoped identity,
		// and no such calls survive the plugin upgrade, so discard them instead of
		// temporarily under-counting duplicate credentials until their TTLs expire.
		if _, err := tx.ExecContext(ctx, `DELETE FROM account_protection_reservations`); err != nil {
			return err
		}
		if err := sqliteMigrationV6Checkpoint(ctx, tx, "reservation-cleanup"); err != nil {
			return err
		}
	}
	if version < 2 {
		if _, err := tx.ExecContext(ctx, `
DELETE FROM summary_cache
WHERE lower(trim(window)) NOT IN ('today','24h','7d','30d','all')
   OR limit_count NOT IN (50,100,500,2000,5000)`); err != nil {
			return err
		}
		if err := sqliteMigrationV6Checkpoint(ctx, tx, "summary-cache-v2-cleanup"); err != nil {
			return err
		}
	}
	if version < 6 {
		// Rebuild the Provider-scoped keys before the v3 privacy rewrite. Legacy
		// global auth_id/state_key primary keys cannot represent two Providers
		// whose raw or v0 aliases converge on the same protected v1 identity.
		// Moving to the composite keys first makes those cross-Provider identities
		// independent while the later privacy pass still merges same-Provider
		// collisions with the documented deterministic whole-row order.
		if err := migrateProviderKeysV6(ctx, tx); err != nil {
			return err
		}
	}
	if version < 3 {
		// v0 fingerprints were deterministic across installations and cannot be
		// mapped back to the original credential. Re-key them with this
		// installation's secret so historical rows remain grouped locally without
		// retaining a cross-installation identifier. This intentionally fails the
		// migration when the secret is unavailable instead of committing a partial
		// privacy upgrade.
		// Earlier releases passed unsanitized identities to usage and state writers.
		// Rewrite every persistent identity column in bounded rowid batches. Known
		// v0 fingerprints are forward-mapped from configured raw keys. If an unknown
		// v0 is the sole identity of an active restriction, keep that provider in a
		// fail-closed privacy quarantine until the key is restored or the restriction
		// is explicitly released; management endpoints remain available for recovery.
		legacyUnlinkableRows, err := migrateStoredIdentitiesV3(ctx, tx, dbPath)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO store_state(key,value) VALUES('api_key_legacy_unlinkable_rows', ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, fmt.Sprint(legacyUnlinkableRows)); err != nil {
			return err
		}
		if err := sqliteMigrationV6Checkpoint(ctx, tx, "privacy-unlinkable-state"); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM summary_cache`); err != nil {
			return err
		}
		if err := sqliteMigrationV6Checkpoint(ctx, tx, "summary-cache-v3-cleanup"); err != nil {
			return err
		}
	}
	if version < 6 {
		if err := rebuildProviderIndexesV6(ctx, tx); err != nil {
			return err
		}
		if err := sqliteMigrationV6Checkpoint(ctx, tx, "provider-indexes"); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, fmt.Sprintf(`PRAGMA user_version=%d`, currentSQLiteSchemaVersion)); err != nil {
		return err
	}
	if err := sqliteMigrationV6Checkpoint(ctx, tx, "version"); err != nil {
		return err
	}
	// With every table now on its final shape, create any missing indexes and
	// verify the complete schema and data invariants before committing.
	if _, err := tx.ExecContext(ctx, schemaSQL); err != nil {
		return err
	}
	if err := sqliteMigrationV6Checkpoint(ctx, tx, "schema-indexes"); err != nil {
		return err
	}
	if err := verifySQLiteV6Store(ctx, tx); err != nil {
		return err
	}
	if err := sqliteMigrationV6Checkpoint(ctx, tx, "verify"); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return verifySQLiteV6Store(ctx, db)
}

func createSQLiteSchemaTables(ctx context.Context, tx *sql.Tx) error {
	for _, raw := range strings.Split(schemaSQL, ";") {
		statement := strings.TrimSpace(raw)
		if !strings.HasPrefix(strings.ToUpper(statement), "CREATE TABLE") {
			continue
		}
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return err
		}
	}
	return nil
}

func sqliteMigrationDSN(dbPath string) string {
	separator := "?"
	if strings.Contains(dbPath, "?") {
		separator = "&"
	}
	return dbPath + separator + "_busy_timeout=5000&_txlock=immediate"
}

type sqliteMigrationColumn struct {
	table string
	name  string
	def   string
}

func ensureSQLiteMigrationColumns(ctx context.Context, tx *sql.Tx) error {
	columns := []sqliteMigrationColumn{
		{table: "usage_events", name: "provider", def: "TEXT NOT NULL DEFAULT ''"},
		{table: "usage_events", name: "executor_type", def: "TEXT NOT NULL DEFAULT ''"},
		{table: "usage_events", name: "model", def: "TEXT NOT NULL DEFAULT ''"},
		{table: "usage_events", name: "alias", def: "TEXT NOT NULL DEFAULT ''"},
		{table: "usage_events", name: "api_key", def: "TEXT NOT NULL DEFAULT ''"},
		{table: "usage_events", name: "auth_id", def: "TEXT NOT NULL DEFAULT ''"},
		{table: "usage_events", name: "auth_index", def: "TEXT NOT NULL DEFAULT ''"},
		{table: "usage_events", name: "auth_type", def: "TEXT NOT NULL DEFAULT ''"},
		{table: "usage_events", name: "source", def: "TEXT NOT NULL DEFAULT ''"},
		{table: "usage_events", name: "reasoning_effort", def: "TEXT NOT NULL DEFAULT ''"},
		{table: "usage_events", name: "service_tier", def: "TEXT NOT NULL DEFAULT ''"},
		{table: "summary_cache", name: "window", def: "TEXT NOT NULL DEFAULT ''"},
		{table: "summary_cache", name: "limit_count", def: "INTEGER NOT NULL DEFAULT 0"},
		{table: "summary_cache", name: "cached_at", def: "INTEGER NOT NULL DEFAULT 0"},
		{table: "summary_cache", name: "duration_ms", def: "INTEGER NOT NULL DEFAULT 0"},
		{table: "summary_cache", name: "revision", def: "TEXT NOT NULL DEFAULT ''"},
		{table: "summary_cache", name: "last_error", def: "TEXT NOT NULL DEFAULT ''"},
		{table: "summary_cache", name: "data_json", def: "TEXT NOT NULL DEFAULT ''"},
		{table: "usage_events", name: "latency_ms", def: "INTEGER NOT NULL DEFAULT 0"},
		{table: "usage_events", name: "ttft_ms", def: "INTEGER NOT NULL DEFAULT 0"},
		{table: "usage_events", name: "generate", def: "INTEGER NOT NULL DEFAULT 1"},
		{table: "usage_events", name: "failed", def: "INTEGER NOT NULL DEFAULT 0"},
		{table: "usage_events", name: "status_code", def: "INTEGER NOT NULL DEFAULT 0"},
		{table: "usage_events", name: "input_tokens", def: "INTEGER NOT NULL DEFAULT 0"},
		{table: "usage_events", name: "output_tokens", def: "INTEGER NOT NULL DEFAULT 0"},
		{table: "usage_events", name: "reasoning_tokens", def: "INTEGER NOT NULL DEFAULT 0"},
		{table: "usage_events", name: "cached_tokens", def: "INTEGER NOT NULL DEFAULT 0"},
		{table: "usage_events", name: "cache_read_tokens", def: "INTEGER NOT NULL DEFAULT 0"},
		{table: "usage_events", name: "cache_creation_tokens", def: "INTEGER NOT NULL DEFAULT 0"},
		{table: "usage_events", name: "total_tokens", def: "INTEGER NOT NULL DEFAULT 0"},
		{table: "usage_events", name: "primary_used_percent", def: "REAL"},
		{table: "usage_events", name: "primary_reset_at", def: "INTEGER"},
		{table: "usage_events", name: "secondary_used_percent", def: "REAL"},
		{table: "usage_events", name: "secondary_reset_at", def: "INTEGER"},
		{table: "usage_events", name: "primary_used_tokens", def: "INTEGER"},
		{table: "usage_events", name: "primary_remaining_tokens", def: "INTEGER"},
		{table: "usage_events", name: "primary_limit_tokens", def: "INTEGER"},
		{table: "usage_events", name: "secondary_used_tokens", def: "INTEGER"},
		{table: "usage_events", name: "secondary_remaining_tokens", def: "INTEGER"},
		{table: "usage_events", name: "secondary_limit_tokens", def: "INTEGER"},
		{table: "account_protection_reservations", name: "provider", def: "TEXT NOT NULL DEFAULT 'codex'"},
		{table: "account_protection_reservations", name: "auth_id", def: "TEXT NOT NULL DEFAULT ''"},
		{table: "account_protection_reservations", name: "auth_index", def: "TEXT NOT NULL DEFAULT ''"},
		{table: "account_protection_reservations", name: "source", def: "TEXT NOT NULL DEFAULT ''"},
		{table: "account_protection_reservations", name: "auth_file", def: "TEXT NOT NULL DEFAULT ''"},
		{table: "account_protection_reservations", name: "plan_type", def: "TEXT NOT NULL DEFAULT ''"},
		{table: "account_protection_reservations", name: "created_at", def: "INTEGER NOT NULL DEFAULT 0"},
		{table: "account_protection_reservations", name: "expires_at", def: "INTEGER NOT NULL DEFAULT 0"},
		{table: "invalid_auths", name: "auth_id", def: "TEXT NOT NULL DEFAULT ''"},
		{table: "invalid_auths", name: "auth_index", def: "TEXT NOT NULL DEFAULT ''"},
		{table: "invalid_auths", name: "source", def: "TEXT NOT NULL DEFAULT ''"},
		{table: "invalid_auths", name: "provider", def: "TEXT NOT NULL DEFAULT ''"},
		{table: "invalid_auths", name: "reason", def: "TEXT NOT NULL DEFAULT ''"},
		{table: "invalid_auths", name: "invalidated_at", def: "INTEGER NOT NULL DEFAULT 0"},
		{table: "invalid_auths", name: "active", def: "INTEGER NOT NULL DEFAULT 1"},
		{table: "invalid_auths", name: "last_status_code", def: "INTEGER NOT NULL DEFAULT 401"},
		{table: "invalid_auths", name: "auth_file", def: "TEXT NOT NULL DEFAULT ''"},
		{table: "invalid_auths", name: "auth_file_mtime", def: "INTEGER NOT NULL DEFAULT 0"},
		{table: "autoban_bans", name: "auth_id", def: "TEXT NOT NULL DEFAULT ''"},
		{table: "autoban_bans", name: "auth_index", def: "TEXT NOT NULL DEFAULT ''"},
		{table: "autoban_bans", name: "source", def: "TEXT NOT NULL DEFAULT ''"},
		{table: "autoban_bans", name: "provider", def: "TEXT NOT NULL DEFAULT ''"},
		{table: "autoban_bans", name: "window", def: "TEXT NOT NULL DEFAULT ''"},
		{table: "autoban_bans", name: "reason", def: "TEXT NOT NULL DEFAULT ''"},
		{table: "autoban_bans", name: "banned_at", def: "INTEGER NOT NULL DEFAULT 0"},
		{table: "autoban_bans", name: "reset_at", def: "INTEGER NOT NULL DEFAULT 0"},
		{table: "autoban_bans", name: "active", def: "INTEGER NOT NULL DEFAULT 1"},
		{table: "autoban_bans", name: "last_status_code", def: "INTEGER NOT NULL DEFAULT 429"},
		{table: "autoban_bans", name: "primary_used_percent", def: "REAL"},
		{table: "autoban_bans", name: "primary_reset_at", def: "INTEGER"},
		{table: "autoban_bans", name: "secondary_used_percent", def: "REAL"},
		{table: "autoban_bans", name: "secondary_reset_at", def: "INTEGER"},
		{table: "autoban_bans", name: "released_at", def: "INTEGER NOT NULL DEFAULT 0"},
		{table: "autoban_bans", name: "release_reason", def: "TEXT NOT NULL DEFAULT ''"},
		{table: "xai_account_states", name: "state_key", def: "TEXT NOT NULL DEFAULT ''"},
		{table: "xai_account_states", name: "auth_id", def: "TEXT NOT NULL DEFAULT ''"},
		{table: "xai_account_states", name: "auth_index", def: "TEXT NOT NULL DEFAULT ''"},
		{table: "xai_account_states", name: "source", def: "TEXT NOT NULL DEFAULT ''"},
		{table: "xai_account_states", name: "provider", def: "TEXT NOT NULL DEFAULT 'xai'"},
		{table: "xai_account_states", name: "state", def: "TEXT NOT NULL DEFAULT ''"},
		{table: "xai_account_states", name: "reason", def: "TEXT NOT NULL DEFAULT ''"},
		{table: "xai_account_states", name: "observed_at", def: "INTEGER NOT NULL DEFAULT 0"},
		{table: "xai_account_states", name: "reset_at", def: "INTEGER NOT NULL DEFAULT 0"},
		{table: "xai_account_states", name: "active", def: "INTEGER NOT NULL DEFAULT 1"},
		{table: "xai_account_states", name: "last_status_code", def: "INTEGER NOT NULL DEFAULT 0"},
		{table: "xai_account_states", name: "auth_file", def: "TEXT NOT NULL DEFAULT ''"},
		{table: "xai_account_states", name: "auth_file_mtime", def: "INTEGER NOT NULL DEFAULT 0"},
		{table: "quota_trigger_runs", name: "auth_id", def: "TEXT NOT NULL DEFAULT ''"},
		{table: "quota_trigger_runs", name: "auth_index", def: "TEXT NOT NULL DEFAULT ''"},
		{table: "quota_trigger_runs", name: "source", def: "TEXT NOT NULL DEFAULT ''"},
		{table: "quota_trigger_runs", name: "provider", def: "TEXT NOT NULL DEFAULT 'codex'"},
		{table: "quota_trigger_runs", name: "auth_file", def: "TEXT NOT NULL DEFAULT ''"},
		{table: "quota_trigger_runs", name: "mode", def: "TEXT NOT NULL DEFAULT ''"},
		{table: "quota_trigger_runs", name: "status", def: "TEXT NOT NULL DEFAULT ''"},
		{table: "quota_trigger_runs", name: "http_status", def: "INTEGER NOT NULL DEFAULT 0"},
		{table: "quota_trigger_runs", name: "error", def: "TEXT NOT NULL DEFAULT ''"},
		{table: "quota_trigger_runs", name: "started_at", def: "INTEGER NOT NULL DEFAULT 0"},
		{table: "quota_trigger_runs", name: "finished_at", def: "INTEGER NOT NULL DEFAULT 0"},
		{table: "quota_trigger_runs", name: "primary_used_percent", def: "REAL"},
		{table: "quota_trigger_runs", name: "primary_reset_at", def: "INTEGER"},
		{table: "quota_trigger_runs", name: "secondary_used_percent", def: "REAL"},
		{table: "quota_trigger_runs", name: "secondary_reset_at", def: "INTEGER"},
		{table: "quota_trigger_runs", name: "primary_used_tokens", def: "INTEGER"},
		{table: "quota_trigger_runs", name: "primary_remaining_tokens", def: "INTEGER"},
		{table: "quota_trigger_runs", name: "primary_limit_tokens", def: "INTEGER"},
		{table: "quota_trigger_runs", name: "secondary_used_tokens", def: "INTEGER"},
		{table: "quota_trigger_runs", name: "secondary_remaining_tokens", def: "INTEGER"},
		{table: "quota_trigger_runs", name: "secondary_limit_tokens", def: "INTEGER"},
	}
	for _, column := range columns {
		if err := ensureSQLiteMigrationColumn(ctx, tx, column); err != nil {
			return err
		}
	}
	return nil
}

func ensureSQLiteMigrationColumn(ctx context.Context, tx *sql.Tx, column sqliteMigrationColumn) error {
	exists, err := sqliteMigrationTableExists(ctx, tx, column.table)
	if err != nil || !exists {
		return err
	}
	rows, err := tx.QueryContext(ctx, `PRAGMA table_info(`+quoteSQLiteIdentifier(column.table)+`)`)
	if err != nil {
		return err
	}
	found := false
	for rows.Next() {
		var cid int
		var name, typ string
		var notNull int
		var defaultValue any
		var pk int
		if err := rows.Scan(&cid, &name, &typ, &notNull, &defaultValue, &pk); err != nil {
			_ = rows.Close()
			return err
		}
		found = found || name == column.name
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if found {
		return nil
	}
	_, err = tx.ExecContext(ctx, `ALTER TABLE `+quoteSQLiteIdentifier(column.table)+` ADD COLUMN `+quoteSQLiteIdentifier(column.name)+` `+column.def)
	return err
}

func sqliteMigrationTableExists(ctx context.Context, tx *sql.Tx, table string) (bool, error) {
	var count int
	err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, table).Scan(&count)
	return count != 0, err
}

func quoteSQLiteIdentifier(value string) string {
	return `"` + strings.ReplaceAll(value, `"`, `""`) + `"`
}

func migrateProviderKeysV6(ctx context.Context, tx *sql.Tx) error {
	for _, statement := range []string{
		`UPDATE usage_events SET provider=CASE WHEN trim(COALESCE(provider,''))='' THEN 'codex' ELSE lower(trim(provider)) END WHERE provider<>lower(trim(provider)) OR trim(COALESCE(provider,''))=''`,
		`UPDATE quota_trigger_runs SET provider=CASE WHEN trim(COALESCE(provider,''))='' THEN 'codex' ELSE lower(trim(provider)) END WHERE provider<>lower(trim(provider)) OR trim(COALESCE(provider,''))=''`,
	} {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return err
		}
	}
	if err := sqliteMigrationV6Checkpoint(ctx, tx, "provider-canonicalization"); err != nil {
		return err
	}
	for _, migrate := range []func(context.Context, *sql.Tx) error{
		migrateUsageEventsV6,
		migrateQuotaTriggerRunsV6,
		migrateInvalidAuthsV6,
		migrateAutobanBansV6,
		migrateXAIAccountStatesV6,
		migrateAccountProtectionReservationsV6,
	} {
		if err := migrate(ctx, tx); err != nil {
			return err
		}
	}
	return nil
}

func migrateUsageEventsV6(ctx context.Context, tx *sql.Tx) error {
	exists, err := sqliteMigrationTableExists(ctx, tx, "usage_events")
	if err != nil || !exists {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DROP TABLE IF EXISTS usage_events_v6_new`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
CREATE TABLE usage_events_v6_new (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  requested_at INTEGER NOT NULL,
  provider TEXT NOT NULL CHECK (provider <> '' AND provider = trim(provider) AND provider = lower(provider)),
  executor_type TEXT NOT NULL DEFAULT '',
  model TEXT NOT NULL DEFAULT '',
  alias TEXT NOT NULL DEFAULT '',
  api_key TEXT NOT NULL DEFAULT '',
  auth_id TEXT NOT NULL DEFAULT '',
  auth_index TEXT NOT NULL DEFAULT '',
  auth_type TEXT NOT NULL DEFAULT '',
  source TEXT NOT NULL DEFAULT '',
  reasoning_effort TEXT NOT NULL DEFAULT '',
  service_tier TEXT NOT NULL DEFAULT '',
  generate INTEGER NOT NULL DEFAULT 1,
  latency_ms INTEGER NOT NULL DEFAULT 0,
  ttft_ms INTEGER NOT NULL DEFAULT 0,
  failed INTEGER NOT NULL DEFAULT 0,
  status_code INTEGER NOT NULL DEFAULT 0,
  input_tokens INTEGER NOT NULL DEFAULT 0,
  output_tokens INTEGER NOT NULL DEFAULT 0,
  reasoning_tokens INTEGER NOT NULL DEFAULT 0,
  cached_tokens INTEGER NOT NULL DEFAULT 0,
  cache_read_tokens INTEGER NOT NULL DEFAULT 0,
  cache_creation_tokens INTEGER NOT NULL DEFAULT 0,
  total_tokens INTEGER NOT NULL DEFAULT 0,
  primary_used_percent REAL,
  primary_reset_at INTEGER,
  secondary_used_percent REAL,
  secondary_reset_at INTEGER,
  primary_used_tokens INTEGER,
  primary_remaining_tokens INTEGER,
  primary_limit_tokens INTEGER,
  secondary_used_tokens INTEGER,
  secondary_remaining_tokens INTEGER,
  secondary_limit_tokens INTEGER
)`); err != nil {
		return err
	}
	if err := sqliteMigrationV6Checkpoint(ctx, tx, "usage-events-create"); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO usage_events_v6_new (
  id, requested_at, provider, executor_type, model, alias, api_key, auth_id,
  auth_index, auth_type, source, reasoning_effort, service_tier, generate,
  latency_ms, ttft_ms, failed, status_code, input_tokens, output_tokens,
  reasoning_tokens, cached_tokens, cache_read_tokens, cache_creation_tokens,
  total_tokens, primary_used_percent, primary_reset_at, secondary_used_percent,
  secondary_reset_at, primary_used_tokens, primary_remaining_tokens,
  primary_limit_tokens, secondary_used_tokens, secondary_remaining_tokens,
  secondary_limit_tokens
)
SELECT id, requested_at,
       CASE WHEN trim(COALESCE(provider, '')) = '' THEN 'codex' ELSE lower(trim(provider)) END,
       COALESCE(executor_type, ''), COALESCE(model, ''), COALESCE(alias, ''),
       COALESCE(api_key, ''), COALESCE(auth_id, ''), COALESCE(auth_index, ''),
       COALESCE(auth_type, ''), COALESCE(source, ''), COALESCE(reasoning_effort, ''),
       COALESCE(service_tier, ''), COALESCE(generate, 1), COALESCE(latency_ms, 0),
       COALESCE(ttft_ms, 0), COALESCE(failed, 0), COALESCE(status_code, 0),
       COALESCE(input_tokens, 0), COALESCE(output_tokens, 0),
       COALESCE(reasoning_tokens, 0), COALESCE(cached_tokens, 0),
       COALESCE(cache_read_tokens, 0), COALESCE(cache_creation_tokens, 0),
       COALESCE(total_tokens, 0), primary_used_percent, primary_reset_at,
       secondary_used_percent, secondary_reset_at, primary_used_tokens,
       primary_remaining_tokens, primary_limit_tokens, secondary_used_tokens,
       secondary_remaining_tokens, secondary_limit_tokens
FROM usage_events`); err != nil {
		return err
	}
	if err := sqliteMigrationV6Checkpoint(ctx, tx, "usage-events-copy"); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DROP TABLE usage_events`); err != nil {
		return err
	}
	if err := sqliteMigrationV6Checkpoint(ctx, tx, "usage-events-drop"); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `ALTER TABLE usage_events_v6_new RENAME TO usage_events`); err != nil {
		return err
	}
	if err := sqliteMigrationV6Checkpoint(ctx, tx, "usage-events-rename"); err != nil {
		return err
	}
	for _, statement := range []string{
		`CREATE INDEX idx_usage_events_requested_at ON usage_events(requested_at)`,
		`CREATE INDEX idx_usage_events_auth ON usage_events(auth_index, auth_id, requested_at)`,
		`CREATE INDEX idx_usage_events_model ON usage_events(model, alias, requested_at)`,
		`CREATE INDEX idx_usage_events_requested_auth_id ON usage_events(requested_at, auth_id)`,
		`CREATE INDEX idx_usage_events_requested_source ON usage_events(requested_at, source)`,
		`CREATE INDEX idx_usage_events_quota_scan ON usage_events(requested_at, failed, status_code)`,
		`CREATE INDEX idx_usage_events_api_key_requested ON usage_events(api_key, requested_at)`,
		`CREATE INDEX idx_usage_events_provider_requested ON usage_events(provider, requested_at)`,
		`CREATE INDEX idx_usage_events_status_requested ON usage_events(status_code, requested_at)`,
		`CREATE INDEX idx_usage_events_requested_id_desc ON usage_events(requested_at DESC, id DESC)`,
		`CREATE INDEX idx_usage_events_lower_auth_index_requested ON usage_events(lower(auth_index), requested_at)`,
		`CREATE INDEX idx_usage_events_lower_auth_id_requested ON usage_events(lower(auth_id), requested_at)`,
		`CREATE INDEX idx_usage_events_lower_source_requested ON usage_events(lower(source), requested_at)`,
		`CREATE INDEX idx_usage_events_provider_model_requested ON usage_events(provider, model, alias, requested_at)`,
		`CREATE INDEX idx_usage_events_api_key_provider_requested ON usage_events(api_key, provider, requested_at)`,
	} {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return err
		}
	}
	return sqliteMigrationV6Checkpoint(ctx, tx, "usage-events-index")
}

func migrateQuotaTriggerRunsV6(ctx context.Context, tx *sql.Tx) error {
	exists, err := sqliteMigrationTableExists(ctx, tx, "quota_trigger_runs")
	if err != nil || !exists {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DROP TABLE IF EXISTS quota_trigger_runs_v6_new`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
CREATE TABLE quota_trigger_runs_v6_new (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  auth_id TEXT NOT NULL DEFAULT '',
  auth_index TEXT NOT NULL DEFAULT '',
  source TEXT NOT NULL DEFAULT '',
  provider TEXT NOT NULL DEFAULT 'codex' CHECK (provider <> '' AND provider = trim(provider) AND provider = lower(provider)),
  auth_file TEXT NOT NULL DEFAULT '',
  mode TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT '',
  http_status INTEGER NOT NULL DEFAULT 0,
  error TEXT NOT NULL DEFAULT '',
  started_at INTEGER NOT NULL,
  finished_at INTEGER NOT NULL,
  primary_used_percent REAL,
  primary_reset_at INTEGER,
  secondary_used_percent REAL,
  secondary_reset_at INTEGER,
  primary_used_tokens INTEGER,
  primary_remaining_tokens INTEGER,
  primary_limit_tokens INTEGER,
  secondary_used_tokens INTEGER,
  secondary_remaining_tokens INTEGER,
  secondary_limit_tokens INTEGER
)`); err != nil {
		return err
	}
	if err := sqliteMigrationV6Checkpoint(ctx, tx, "quota-trigger-runs-create"); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO quota_trigger_runs_v6_new (
  id, auth_id, auth_index, source, provider, auth_file, mode, status,
  http_status, error, started_at, finished_at, primary_used_percent,
  primary_reset_at, secondary_used_percent, secondary_reset_at,
  primary_used_tokens, primary_remaining_tokens, primary_limit_tokens,
  secondary_used_tokens, secondary_remaining_tokens, secondary_limit_tokens
)
SELECT id, COALESCE(auth_id, ''), COALESCE(auth_index, ''), COALESCE(source, ''),
       CASE WHEN trim(COALESCE(provider, '')) = '' THEN 'codex' ELSE lower(trim(provider)) END,
       COALESCE(auth_file, ''), COALESCE(mode, ''), COALESCE(status, ''),
       COALESCE(http_status, 0), COALESCE(error, ''), COALESCE(started_at, 0),
       COALESCE(finished_at, 0), primary_used_percent, primary_reset_at,
       secondary_used_percent, secondary_reset_at, primary_used_tokens,
       primary_remaining_tokens, primary_limit_tokens, secondary_used_tokens,
       secondary_remaining_tokens, secondary_limit_tokens
FROM quota_trigger_runs`); err != nil {
		return err
	}
	if err := sqliteMigrationV6Checkpoint(ctx, tx, "quota-trigger-runs-copy"); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DROP TABLE quota_trigger_runs`); err != nil {
		return err
	}
	if err := sqliteMigrationV6Checkpoint(ctx, tx, "quota-trigger-runs-drop"); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `ALTER TABLE quota_trigger_runs_v6_new RENAME TO quota_trigger_runs`); err != nil {
		return err
	}
	if err := sqliteMigrationV6Checkpoint(ctx, tx, "quota-trigger-runs-rename"); err != nil {
		return err
	}
	for _, statement := range []string{
		`CREATE INDEX idx_quota_trigger_runs_account ON quota_trigger_runs(provider, auth_index, auth_id, source, auth_file, finished_at)`,
		`CREATE INDEX idx_quota_trigger_runs_finished_at ON quota_trigger_runs(finished_at)`,
		`CREATE INDEX idx_quota_trigger_runs_status_finished ON quota_trigger_runs(status, finished_at)`,
		`CREATE INDEX idx_quota_trigger_runs_auth_file_finished ON quota_trigger_runs(auth_file, finished_at)`,
	} {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return err
		}
	}
	return sqliteMigrationV6Checkpoint(ctx, tx, "quota-trigger-runs-index")
}

func migrateInvalidAuthsV6(ctx context.Context, tx *sql.Tx) error {
	exists, err := sqliteMigrationTableExists(ctx, tx, "invalid_auths")
	if err != nil || !exists {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DROP TABLE IF EXISTS invalid_auths_v6_new`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
CREATE TABLE invalid_auths_v6_new (
  auth_id TEXT NOT NULL,
  auth_index TEXT NOT NULL DEFAULT '',
  source TEXT NOT NULL DEFAULT '',
  provider TEXT NOT NULL DEFAULT 'codex' CHECK (provider <> '' AND provider = trim(provider) AND provider = lower(provider)),
  reason TEXT NOT NULL DEFAULT '',
  invalidated_at INTEGER NOT NULL,
  active INTEGER NOT NULL DEFAULT 1,
  last_status_code INTEGER NOT NULL DEFAULT 401,
  auth_file TEXT NOT NULL DEFAULT '',
  auth_file_mtime INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (provider, auth_id)
)`); err != nil {
		return err
	}
	if err := sqliteMigrationV6Checkpoint(ctx, tx, "invalid-auths-create"); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
WITH canonical AS (
  SELECT
    rowid AS legacy_rowid,
    COALESCE(auth_id, '') AS auth_id,
    COALESCE(auth_index, '') AS auth_index,
    COALESCE(source, '') AS source,
    CASE WHEN trim(COALESCE(provider, '')) = '' THEN 'codex' ELSE lower(trim(provider)) END AS provider,
    COALESCE(reason, '') AS reason,
    COALESCE(invalidated_at, 0) AS invalidated_at,
    COALESCE(active, 1) AS active,
    COALESCE(last_status_code, 401) AS last_status_code,
    COALESCE(auth_file, '') AS auth_file,
    COALESCE(auth_file_mtime, 0) AS auth_file_mtime
  FROM invalid_auths
), ranked AS (
  SELECT *, ROW_NUMBER() OVER (
    PARTITION BY provider, auth_id
    ORDER BY active DESC, invalidated_at DESC, last_status_code DESC,
             auth_file_mtime DESC, auth_file DESC, reason DESC,
             auth_index DESC, source DESC, legacy_rowid DESC
  ) AS winner_rank
  FROM canonical
)
INSERT INTO invalid_auths_v6_new (
  auth_id, auth_index, source, provider, reason, invalidated_at, active,
  last_status_code, auth_file, auth_file_mtime
)
SELECT auth_id, auth_index, source, provider, reason, invalidated_at, active,
       last_status_code, auth_file, auth_file_mtime
FROM ranked
WHERE winner_rank = 1`); err != nil {
		return err
	}
	if err := sqliteMigrationV6Checkpoint(ctx, tx, "invalid-auths-copy"); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DROP TABLE invalid_auths`); err != nil {
		return err
	}
	if err := sqliteMigrationV6Checkpoint(ctx, tx, "invalid-auths-drop"); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `ALTER TABLE invalid_auths_v6_new RENAME TO invalid_auths`); err != nil {
		return err
	}
	if err := sqliteMigrationV6Checkpoint(ctx, tx, "invalid-auths-rename"); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `CREATE INDEX idx_invalid_auths_active ON invalid_auths(provider, active)`); err != nil {
		return err
	}
	return sqliteMigrationV6Checkpoint(ctx, tx, "invalid-auths-index")
}

func migrateAutobanBansV6(ctx context.Context, tx *sql.Tx) error {
	exists, err := sqliteMigrationTableExists(ctx, tx, "autoban_bans")
	if err != nil || !exists {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DROP TABLE IF EXISTS autoban_bans_v6_new`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
CREATE TABLE autoban_bans_v6_new (
  auth_id TEXT NOT NULL,
  auth_index TEXT NOT NULL DEFAULT '',
  source TEXT NOT NULL DEFAULT '',
  provider TEXT NOT NULL DEFAULT 'codex' CHECK (provider <> '' AND provider = trim(provider) AND provider = lower(provider)),
  window TEXT NOT NULL DEFAULT '',
  reason TEXT NOT NULL DEFAULT '',
  banned_at INTEGER NOT NULL,
  reset_at INTEGER NOT NULL,
  active INTEGER NOT NULL DEFAULT 1,
  last_status_code INTEGER NOT NULL DEFAULT 429,
  primary_used_percent REAL,
  primary_reset_at INTEGER,
  secondary_used_percent REAL,
  secondary_reset_at INTEGER,
  released_at INTEGER NOT NULL DEFAULT 0,
  release_reason TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (provider, auth_id)
)`); err != nil {
		return err
	}
	if err := sqliteMigrationV6Checkpoint(ctx, tx, "autoban-bans-create"); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
WITH canonical AS (
  SELECT
    rowid AS legacy_rowid,
    COALESCE(auth_id, '') AS auth_id,
    COALESCE(auth_index, '') AS auth_index,
    COALESCE(source, '') AS source,
    CASE WHEN trim(COALESCE(provider, '')) = '' THEN 'codex' ELSE lower(trim(provider)) END AS provider,
    COALESCE(window, '') AS window,
    COALESCE(reason, '') AS reason,
    COALESCE(banned_at, 0) AS banned_at,
    COALESCE(reset_at, 0) AS reset_at,
    COALESCE(active, 1) AS active,
    COALESCE(last_status_code, 429) AS last_status_code,
    primary_used_percent,
    primary_reset_at,
    secondary_used_percent,
    secondary_reset_at,
    COALESCE(released_at, 0) AS released_at,
    COALESCE(release_reason, '') AS release_reason
  FROM autoban_bans
), ranked AS (
  SELECT *, ROW_NUMBER() OVER (
    PARTITION BY provider, auth_id
    ORDER BY CASE
               WHEN active=0 AND released_at>banned_at THEN released_at
               ELSE banned_at
             END DESC,
             active ASC, reset_at DESC, banned_at DESC, released_at DESC,
             last_status_code DESC, release_reason DESC, reason DESC,
             window DESC, auth_index DESC, source DESC, legacy_rowid DESC
  ) AS winner_rank
  FROM canonical
)
INSERT INTO autoban_bans_v6_new (
  auth_id, auth_index, source, provider, window, reason, banned_at, reset_at,
  active, last_status_code, primary_used_percent, primary_reset_at,
  secondary_used_percent, secondary_reset_at, released_at, release_reason
)
SELECT auth_id, auth_index, source, provider, window, reason, banned_at, reset_at,
       active, last_status_code, primary_used_percent, primary_reset_at,
       secondary_used_percent, secondary_reset_at, released_at, release_reason
FROM ranked
WHERE winner_rank = 1`); err != nil {
		return err
	}
	if err := sqliteMigrationV6Checkpoint(ctx, tx, "autoban-bans-copy"); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DROP TABLE autoban_bans`); err != nil {
		return err
	}
	if err := sqliteMigrationV6Checkpoint(ctx, tx, "autoban-bans-drop"); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `ALTER TABLE autoban_bans_v6_new RENAME TO autoban_bans`); err != nil {
		return err
	}
	if err := sqliteMigrationV6Checkpoint(ctx, tx, "autoban-bans-rename"); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `CREATE INDEX idx_autoban_bans_active_reset ON autoban_bans(provider, active, reset_at)`); err != nil {
		return err
	}
	return sqliteMigrationV6Checkpoint(ctx, tx, "autoban-bans-index")
}

func migrateXAIAccountStatesV6(ctx context.Context, tx *sql.Tx) error {
	exists, err := sqliteMigrationTableExists(ctx, tx, "xai_account_states")
	if err != nil || !exists {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DROP TABLE IF EXISTS xai_account_states_v6_new`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
CREATE TABLE xai_account_states_v6_new (
  state_key TEXT NOT NULL,
  auth_id TEXT NOT NULL DEFAULT '',
  auth_index TEXT NOT NULL DEFAULT '',
  source TEXT NOT NULL DEFAULT '',
  provider TEXT NOT NULL DEFAULT 'xai' CHECK (provider <> '' AND provider = trim(provider) AND provider = lower(provider)),
  state TEXT NOT NULL DEFAULT '',
  reason TEXT NOT NULL DEFAULT '',
  observed_at INTEGER NOT NULL,
  reset_at INTEGER NOT NULL DEFAULT 0,
  active INTEGER NOT NULL DEFAULT 1,
  last_status_code INTEGER NOT NULL DEFAULT 0,
  auth_file TEXT NOT NULL DEFAULT '',
  auth_file_mtime INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (provider, state_key)
)`); err != nil {
		return err
	}
	if err := sqliteMigrationV6Checkpoint(ctx, tx, "xai-account-states-create"); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
WITH canonical AS (
  SELECT
    rowid AS legacy_rowid,
    COALESCE(state_key, '') AS state_key,
    COALESCE(auth_id, '') AS auth_id,
    COALESCE(auth_index, '') AS auth_index,
    COALESCE(source, '') AS source,
    CASE WHEN trim(COALESCE(provider, '')) = '' THEN 'xai' ELSE lower(trim(provider)) END AS provider,
    COALESCE(state, '') AS state,
    COALESCE(reason, '') AS reason,
    COALESCE(observed_at, 0) AS observed_at,
    COALESCE(reset_at, 0) AS reset_at,
    COALESCE(active, 1) AS active,
    COALESCE(last_status_code, 0) AS last_status_code,
    COALESCE(auth_file, '') AS auth_file,
    COALESCE(auth_file_mtime, 0) AS auth_file_mtime
  FROM xai_account_states
), ranked AS (
  SELECT *, ROW_NUMBER() OVER (
    PARTITION BY provider, state_key
    ORDER BY active DESC, observed_at DESC, reset_at DESC,
             last_status_code DESC, auth_file_mtime DESC, state DESC,
             reason DESC, auth_file DESC, auth_id DESC, auth_index DESC,
             source DESC, legacy_rowid DESC
  ) AS winner_rank
  FROM canonical
)
INSERT INTO xai_account_states_v6_new (
  state_key, auth_id, auth_index, source, provider, state, reason, observed_at,
  reset_at, active, last_status_code, auth_file, auth_file_mtime
)
SELECT state_key, auth_id, auth_index, source, provider, state, reason, observed_at,
       reset_at, active, last_status_code, auth_file, auth_file_mtime
FROM ranked
WHERE winner_rank = 1`); err != nil {
		return err
	}
	if err := sqliteMigrationV6Checkpoint(ctx, tx, "xai-account-states-copy"); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DROP TABLE xai_account_states`); err != nil {
		return err
	}
	if err := sqliteMigrationV6Checkpoint(ctx, tx, "xai-account-states-drop"); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `ALTER TABLE xai_account_states_v6_new RENAME TO xai_account_states`); err != nil {
		return err
	}
	if err := sqliteMigrationV6Checkpoint(ctx, tx, "xai-account-states-rename"); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `CREATE INDEX idx_xai_account_states_active_reset ON xai_account_states(provider, active, reset_at)`); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `CREATE INDEX idx_xai_account_states_auth ON xai_account_states(provider, auth_index, auth_id, source)`); err != nil {
		return err
	}
	return sqliteMigrationV6Checkpoint(ctx, tx, "xai-account-states-index")
}

func migrateAccountProtectionReservationsV6(ctx context.Context, tx *sql.Tx) error {
	exists, err := sqliteMigrationTableExists(ctx, tx, "account_protection_reservations")
	if err != nil || !exists {
		return err
	}
	columns, err := sqliteMigrationTableColumns(ctx, tx, "account_protection_reservations")
	if err != nil {
		return err
	}
	providerExpression := `'codex'`
	if columns["provider"] {
		providerExpression = `CASE WHEN trim(COALESCE(provider, '')) = '' THEN 'codex' ELSE lower(trim(provider)) END`
	}
	if _, err := tx.ExecContext(ctx, `DROP TABLE IF EXISTS account_protection_reservations_v6_new`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
CREATE TABLE account_protection_reservations_v6_new (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  provider TEXT NOT NULL DEFAULT 'codex' CHECK (provider <> '' AND provider = trim(provider) AND provider = lower(provider)),
  auth_id TEXT NOT NULL DEFAULT '',
  auth_index TEXT NOT NULL DEFAULT '',
  source TEXT NOT NULL DEFAULT '',
  auth_file TEXT NOT NULL DEFAULT '',
  plan_type TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
)`); err != nil {
		return err
	}
	if err := sqliteMigrationV6Checkpoint(ctx, tx, "reservations-create"); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO account_protection_reservations_v6_new (
  id, provider, auth_id, auth_index, source, auth_file, plan_type, created_at, expires_at
)
SELECT id, `+providerExpression+`, COALESCE(auth_id, ''), COALESCE(auth_index, ''),
       COALESCE(source, ''), COALESCE(auth_file, ''), COALESCE(plan_type, ''),
       COALESCE(created_at, 0), COALESCE(expires_at, 0)
FROM account_protection_reservations`); err != nil {
		return err
	}
	if err := sqliteMigrationV6Checkpoint(ctx, tx, "reservations-copy"); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DROP TABLE account_protection_reservations`); err != nil {
		return err
	}
	if err := sqliteMigrationV6Checkpoint(ctx, tx, "reservations-drop"); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `ALTER TABLE account_protection_reservations_v6_new RENAME TO account_protection_reservations`); err != nil {
		return err
	}
	if err := sqliteMigrationV6Checkpoint(ctx, tx, "reservations-rename"); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `CREATE INDEX idx_account_protection_reservations_expiry ON account_protection_reservations(expires_at)`); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `CREATE INDEX idx_account_protection_reservations_auth ON account_protection_reservations(provider, auth_index, auth_id, source, expires_at)`); err != nil {
		return err
	}
	return sqliteMigrationV6Checkpoint(ctx, tx, "reservations-index")
}

func sqliteMigrationTableColumns(ctx context.Context, tx *sql.Tx, table string) (map[string]bool, error) {
	rows, err := tx.QueryContext(ctx, `PRAGMA table_info(`+quoteSQLiteIdentifier(table)+`)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	columns := map[string]bool{}
	for rows.Next() {
		var cid int
		var name, typ string
		var notNull int
		var defaultValue any
		var pk int
		if err := rows.Scan(&cid, &name, &typ, &notNull, &defaultValue, &pk); err != nil {
			return nil, err
		}
		columns[name] = true
	}
	return columns, rows.Err()
}

func rebuildProviderIndexesV6(ctx context.Context, tx *sql.Tx) error {
	statements := []string{
		`DROP INDEX IF EXISTS idx_account_protection_reservations_auth`,
		`CREATE INDEX idx_account_protection_reservations_auth ON account_protection_reservations(provider, auth_index, auth_id, source, expires_at)`,
		`DROP INDEX IF EXISTS idx_xai_account_states_active_reset`,
		`CREATE INDEX idx_xai_account_states_active_reset ON xai_account_states(provider, active, reset_at)`,
		`DROP INDEX IF EXISTS idx_xai_account_states_auth`,
		`CREATE INDEX idx_xai_account_states_auth ON xai_account_states(provider, auth_index, auth_id, source)`,
		`DROP INDEX IF EXISTS idx_autoban_bans_active_reset`,
		`CREATE INDEX idx_autoban_bans_active_reset ON autoban_bans(provider, active, reset_at)`,
		`DROP INDEX IF EXISTS idx_invalid_auths_active`,
		`CREATE INDEX idx_invalid_auths_active ON invalid_auths(provider, active)`,
		`DROP INDEX IF EXISTS idx_quota_trigger_runs_account`,
		`CREATE INDEX idx_quota_trigger_runs_account ON quota_trigger_runs(provider, auth_index, auth_id, source, auth_file, finished_at)`,
	}
	for _, statement := range statements {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return err
		}
	}
	return nil
}

type sqliteV6Verifier interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

// verifySQLiteV6Schema is the normal-open fast path. It verifies only schema
// metadata and the small revision rows; it intentionally avoids quick_check
// and Provider distribution scans over user tables. Full data/integrity scans
// remain mandatory inside and immediately after a migration, and are also
// available to explicit maintenance/tests through verifySQLiteV6Store.
func verifySQLiteV6Schema(ctx context.Context, store sqliteV6Verifier) error {
	var version int
	if err := store.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&version); err != nil {
		return err
	}
	if version != currentSQLiteSchemaVersion {
		return fmt.Errorf("usage database schema %d does not match required schema %d", version, currentSQLiteSchemaVersion)
	}

	requiredColumns := map[string][]string{
		"usage_events": {
			"id", "requested_at", "provider", "executor_type", "model", "alias", "api_key",
			"auth_id", "auth_index", "auth_type", "source", "reasoning_effort", "service_tier",
			"generate", "latency_ms", "ttft_ms", "failed", "status_code", "input_tokens",
			"output_tokens", "reasoning_tokens", "cached_tokens", "cache_read_tokens",
			"cache_creation_tokens", "total_tokens", "primary_used_percent", "primary_reset_at",
			"secondary_used_percent", "secondary_reset_at", "primary_used_tokens",
			"primary_remaining_tokens", "primary_limit_tokens", "secondary_used_tokens",
			"secondary_remaining_tokens", "secondary_limit_tokens",
		},
		"account_protection_reservations": {"id", "provider", "auth_id", "auth_index", "source", "auth_file", "plan_type", "created_at", "expires_at"},
		"xai_account_states":              {"state_key", "auth_id", "auth_index", "source", "provider", "state", "reason", "observed_at", "reset_at", "active", "last_status_code", "auth_file", "auth_file_mtime"},
		"summary_cache":                   {"cache_key", "window", "limit_count", "cached_at", "duration_ms", "revision", "last_error", "data_json"},
		"store_state":                     {"key", "value"},
		"autoban_bans":                    {"auth_id", "auth_index", "source", "provider", "window", "reason", "banned_at", "reset_at", "active", "last_status_code", "primary_used_percent", "primary_reset_at", "secondary_used_percent", "secondary_reset_at", "released_at", "release_reason"},
		"invalid_auths":                   {"auth_id", "auth_index", "source", "provider", "reason", "invalidated_at", "active", "last_status_code", "auth_file", "auth_file_mtime"},
		"quota_trigger_runs":              {"id", "auth_id", "auth_index", "source", "provider", "auth_file", "mode", "status", "http_status", "error", "started_at", "finished_at", "primary_used_percent", "primary_reset_at", "secondary_used_percent", "secondary_reset_at", "primary_used_tokens", "primary_remaining_tokens", "primary_limit_tokens", "secondary_used_tokens", "secondary_remaining_tokens", "secondary_limit_tokens"},
	}
	for table, required := range requiredColumns {
		columns, _, err := sqliteV6TableInfo(ctx, store, table)
		if err != nil {
			return err
		}
		if len(columns) == 0 {
			return fmt.Errorf("required SQLite table %s is missing", table)
		}
		for _, column := range required {
			if !columns[column] {
				return fmt.Errorf("required SQLite column %s.%s is missing", table, column)
			}
		}
	}

	for table, want := range map[string][]string{
		"invalid_auths":      {"provider", "auth_id"},
		"autoban_bans":       {"provider", "auth_id"},
		"xai_account_states": {"provider", "state_key"},
	} {
		_, primaryKey, err := sqliteV6TableInfo(ctx, store, table)
		if err != nil {
			return err
		}
		if strings.Join(primaryKey, ",") != strings.Join(want, ",") {
			return fmt.Errorf("SQLite table %s primary key is %v, want %v", table, primaryKey, want)
		}
	}
	for _, table := range []string{
		"usage_events", "quota_trigger_runs", "invalid_auths", "autoban_bans",
		"xai_account_states", "account_protection_reservations",
	} {
		var tableSQL string
		if err := store.QueryRowContext(ctx, `SELECT sql FROM sqlite_master WHERE type='table' AND name=?`, table).Scan(&tableSQL); err != nil {
			return err
		}
		lowerSQL := strings.ToLower(tableSQL)
		for _, fragment := range []string{"provider <> ''", "provider = trim(provider)", "provider = lower(provider)"} {
			if !strings.Contains(lowerSQL, fragment) {
				return fmt.Errorf("SQLite table %s is missing provider constraint %q", table, fragment)
			}
		}
	}

	for _, key := range []string{schedulerRevisionCodexKey, schedulerRevisionXAIKey, schedulerRevisionPrivacyKey} {
		var raw string
		if err := store.QueryRowContext(ctx, `SELECT value FROM store_state WHERE key=?`, key).Scan(&raw); err != nil {
			return fmt.Errorf("required SQLite scheduler revision %s is missing: %w", key, err)
		}
		value, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
		if err != nil || value < 0 {
			return fmt.Errorf("SQLite scheduler revision %s is invalid: %q", key, raw)
		}
	}
	for _, trigger := range []string{
		"trg_invalid_auths_revision_insert", "trg_invalid_auths_revision_update", "trg_invalid_auths_revision_delete",
		"trg_autoban_bans_revision_insert", "trg_autoban_bans_revision_update", "trg_autoban_bans_revision_delete",
		"trg_xai_account_states_revision_insert", "trg_xai_account_states_revision_update", "trg_xai_account_states_revision_delete",
		"trg_privacy_quarantine_revision_insert", "trg_privacy_quarantine_revision_update", "trg_privacy_quarantine_revision_delete",
	} {
		var count int
		if err := store.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type='trigger' AND name=?`, trigger).Scan(&count); err != nil {
			return err
		}
		if count != 1 {
			return fmt.Errorf("required SQLite trigger %s is missing", trigger)
		}
	}

	requiredIndexes := []string{
		"idx_usage_events_requested_at", "idx_usage_events_auth", "idx_usage_events_model",
		"idx_usage_events_requested_auth_id", "idx_usage_events_requested_source",
		"idx_usage_events_quota_scan", "idx_usage_events_api_key_requested",
		"idx_usage_events_provider_requested", "idx_usage_events_status_requested",
		"idx_usage_events_requested_id_desc", "idx_usage_events_lower_auth_index_requested",
		"idx_usage_events_lower_auth_id_requested", "idx_usage_events_lower_source_requested",
		"idx_usage_events_provider_model_requested", "idx_usage_events_api_key_provider_requested",
		"idx_account_protection_reservations_expiry", "idx_account_protection_reservations_auth",
		"idx_xai_account_states_active_reset", "idx_xai_account_states_auth",
		"idx_summary_cache_cached_at", "idx_autoban_bans_active_reset", "idx_invalid_auths_active",
		"idx_quota_trigger_runs_account", "idx_quota_trigger_runs_finished_at",
		"idx_quota_trigger_runs_status_finished", "idx_quota_trigger_runs_auth_file_finished",
	}
	for _, index := range requiredIndexes {
		var count int
		if err := store.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name=?`, index).Scan(&count); err != nil {
			return err
		}
		if count != 1 {
			return fmt.Errorf("required SQLite index %s is missing", index)
		}
	}
	for index, want := range map[string][]string{
		"idx_account_protection_reservations_auth": {"provider", "auth_index", "auth_id", "source", "expires_at"},
		"idx_xai_account_states_active_reset":      {"provider", "active", "reset_at"},
		"idx_xai_account_states_auth":              {"provider", "auth_index", "auth_id", "source"},
		"idx_autoban_bans_active_reset":            {"provider", "active", "reset_at"},
		"idx_invalid_auths_active":                 {"provider", "active"},
		"idx_quota_trigger_runs_account":           {"provider", "auth_index", "auth_id", "source", "auth_file", "finished_at"},
	} {
		got, err := sqliteV6IndexColumns(ctx, store, index)
		if err != nil {
			return err
		}
		if strings.Join(got, ",") != strings.Join(want, ",") {
			return fmt.Errorf("SQLite index %s columns are %v, want %v", index, got, want)
		}
	}

	var temporaryTables int
	if err := store.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name LIKE '%_v6_new'`).Scan(&temporaryTables); err != nil {
		return err
	}
	if temporaryTables != 0 {
		return fmt.Errorf("SQLite v6 migration left %d temporary tables", temporaryTables)
	}
	return nil
}

func verifySQLiteV6Store(ctx context.Context, store sqliteV6Verifier) error {
	if err := verifySQLiteV6Schema(ctx, store); err != nil {
		return err
	}
	if err := verifySQLiteQuickCheck(ctx, store); err != nil {
		return err
	}
	for _, table := range []string{"invalid_auths", "autoban_bans", "xai_account_states"} {
		if err := verifySQLiteProviderDistribution(ctx, store, table, true); err != nil {
			return err
		}
	}
	for _, table := range []string{"usage_events", "quota_trigger_runs", "account_protection_reservations"} {
		if err := verifySQLiteProviderDistribution(ctx, store, table, false); err != nil {
			return err
		}
	}
	return nil
}

func verifySQLiteQuickCheck(ctx context.Context, store sqliteV6Verifier) error {
	rows, err := store.QueryContext(ctx, `PRAGMA quick_check`)
	if err != nil {
		return err
	}
	defer rows.Close()
	checked := false
	for rows.Next() {
		var result string
		if err := rows.Scan(&result); err != nil {
			return err
		}
		checked = true
		if !strings.EqualFold(strings.TrimSpace(result), "ok") {
			return fmt.Errorf("SQLite quick_check failed: %s", result)
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if !checked {
		return fmt.Errorf("SQLite quick_check returned no result")
	}
	return nil
}

func sqliteV6TableInfo(ctx context.Context, store sqliteV6Verifier, table string) (map[string]bool, []string, error) {
	rows, err := store.QueryContext(ctx, `PRAGMA table_info(`+quoteSQLiteIdentifier(table)+`)`)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	columns := map[string]bool{}
	primaryKeyByPosition := map[int]string{}
	maxPrimaryKeyPosition := 0
	for rows.Next() {
		var cid int
		var name, typ string
		var notNull int
		var defaultValue any
		var primaryKeyPosition int
		if err := rows.Scan(&cid, &name, &typ, &notNull, &defaultValue, &primaryKeyPosition); err != nil {
			return nil, nil, err
		}
		columns[name] = true
		if primaryKeyPosition > 0 {
			primaryKeyByPosition[primaryKeyPosition] = name
			if primaryKeyPosition > maxPrimaryKeyPosition {
				maxPrimaryKeyPosition = primaryKeyPosition
			}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	primaryKey := make([]string, maxPrimaryKeyPosition)
	for position, name := range primaryKeyByPosition {
		primaryKey[position-1] = name
	}
	return columns, primaryKey, nil
}

func sqliteV6IndexColumns(ctx context.Context, store sqliteV6Verifier, index string) ([]string, error) {
	rows, err := store.QueryContext(ctx, `PRAGMA index_info(`+quoteSQLiteIdentifier(index)+`)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var columns []string
	for rows.Next() {
		var sequence, columnID int
		var name string
		if err := rows.Scan(&sequence, &columnID, &name); err != nil {
			return nil, err
		}
		columns = append(columns, name)
	}
	return columns, rows.Err()
}

func verifySQLiteProviderDistribution(ctx context.Context, store sqliteV6Verifier, table string, hasActive bool) error {
	activeExpression := "0"
	if hasActive {
		activeExpression = "COALESCE(SUM(CASE WHEN active=1 THEN 1 ELSE 0 END),0)"
		var invalidActive int
		if err := store.QueryRowContext(ctx, `SELECT COUNT(*) FROM `+quoteSQLiteIdentifier(table)+` WHERE active NOT IN (0,1)`).Scan(&invalidActive); err != nil {
			return err
		}
		if invalidActive != 0 {
			return fmt.Errorf("SQLite table %s has %d invalid active values", table, invalidActive)
		}
	}
	rows, err := store.QueryContext(ctx, `SELECT provider, COUNT(*), `+activeExpression+` FROM `+quoteSQLiteIdentifier(table)+` GROUP BY provider`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var provider string
		var total, active int64
		if err := rows.Scan(&provider, &total, &active); err != nil {
			return err
		}
		if provider == "" || canonicalProvider(provider) != provider {
			return fmt.Errorf("SQLite table %s contains non-canonical provider %q", table, provider)
		}
		if total < 0 || active < 0 || active > total {
			return fmt.Errorf("SQLite table %s has invalid provider distribution %q=%d/%d", table, provider, active, total)
		}
	}
	return rows.Err()
}

type sqliteStoreExecer interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

func normalizeStoredResetColumns(ctx context.Context, exec sqliteStoreExecer) error {
	statements := []string{
		`UPDATE usage_events SET primary_reset_at = CAST(primary_reset_at / 1000 AS INTEGER) WHERE primary_reset_at > 1000000000000`,
		`UPDATE usage_events SET secondary_reset_at = CAST(secondary_reset_at / 1000 AS INTEGER) WHERE secondary_reset_at > 1000000000000`,
		`UPDATE autoban_bans SET reset_at = CAST(reset_at / 1000 AS INTEGER) WHERE reset_at > 1000000000000`,
		`UPDATE autoban_bans SET primary_reset_at = CAST(primary_reset_at / 1000 AS INTEGER) WHERE primary_reset_at > 1000000000000`,
		`UPDATE autoban_bans SET secondary_reset_at = CAST(secondary_reset_at / 1000 AS INTEGER) WHERE secondary_reset_at > 1000000000000`,
		`UPDATE quota_trigger_runs SET primary_reset_at = CAST(primary_reset_at / 1000 AS INTEGER) WHERE primary_reset_at > 1000000000000`,
		`UPDATE quota_trigger_runs SET secondary_reset_at = CAST(secondary_reset_at / 1000 AS INTEGER) WHERE secondary_reset_at > 1000000000000`,
	}
	for _, statement := range statements {
		if _, err := exec.ExecContext(ctx, statement); err != nil {
			return err
		}
	}
	return nil
}
