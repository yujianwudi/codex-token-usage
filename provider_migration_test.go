package main

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// historicalSQLiteSchemaV0To4 is the schemaSQL shipped by v0.1.32 through
// v0.1.34 (schema versions 0/1, 2, and 3). Version 4 used the same table shape
// immediately before v0.1.35 added reservation auth_file and stamped v5.
const historicalSQLiteSchemaV0To4 = `
CREATE TABLE IF NOT EXISTS usage_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  requested_at INTEGER NOT NULL,
  provider TEXT NOT NULL DEFAULT '',
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
);
CREATE INDEX IF NOT EXISTS idx_usage_events_requested_at ON usage_events(requested_at);
CREATE INDEX IF NOT EXISTS idx_usage_events_auth ON usage_events(auth_index, auth_id, requested_at);
CREATE INDEX IF NOT EXISTS idx_usage_events_model ON usage_events(model, alias, requested_at);
CREATE INDEX IF NOT EXISTS idx_usage_events_requested_auth_id ON usage_events(requested_at, auth_id);
CREATE INDEX IF NOT EXISTS idx_usage_events_requested_source ON usage_events(requested_at, source);
CREATE INDEX IF NOT EXISTS idx_usage_events_quota_scan ON usage_events(requested_at, failed, status_code);
CREATE INDEX IF NOT EXISTS idx_usage_events_api_key_requested ON usage_events(api_key, requested_at);
CREATE INDEX IF NOT EXISTS idx_usage_events_provider_requested ON usage_events(provider, requested_at);
CREATE INDEX IF NOT EXISTS idx_usage_events_status_requested ON usage_events(status_code, requested_at);
CREATE INDEX IF NOT EXISTS idx_usage_events_requested_id_desc ON usage_events(requested_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_usage_events_lower_auth_index_requested ON usage_events(lower(auth_index), requested_at);
CREATE INDEX IF NOT EXISTS idx_usage_events_lower_auth_id_requested ON usage_events(lower(auth_id), requested_at);
CREATE INDEX IF NOT EXISTS idx_usage_events_lower_source_requested ON usage_events(lower(source), requested_at);
CREATE INDEX IF NOT EXISTS idx_usage_events_provider_model_requested ON usage_events(provider, model, alias, requested_at);
CREATE INDEX IF NOT EXISTS idx_usage_events_api_key_provider_requested ON usage_events(api_key, provider, requested_at);
CREATE TABLE IF NOT EXISTS account_protection_reservations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  auth_id TEXT NOT NULL DEFAULT '',
  auth_index TEXT NOT NULL DEFAULT '',
  source TEXT NOT NULL DEFAULT '',
  plan_type TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_account_protection_reservations_expiry ON account_protection_reservations(expires_at);
CREATE INDEX IF NOT EXISTS idx_account_protection_reservations_auth ON account_protection_reservations(auth_index, auth_id, source, expires_at);
CREATE TABLE IF NOT EXISTS xai_account_states (
  state_key TEXT PRIMARY KEY,
  auth_id TEXT NOT NULL DEFAULT '',
  auth_index TEXT NOT NULL DEFAULT '',
  source TEXT NOT NULL DEFAULT '',
  provider TEXT NOT NULL DEFAULT 'xai',
  state TEXT NOT NULL DEFAULT '',
  reason TEXT NOT NULL DEFAULT '',
  observed_at INTEGER NOT NULL,
  reset_at INTEGER NOT NULL DEFAULT 0,
  active INTEGER NOT NULL DEFAULT 1,
  last_status_code INTEGER NOT NULL DEFAULT 0,
  auth_file TEXT NOT NULL DEFAULT '',
  auth_file_mtime INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_xai_account_states_active_reset ON xai_account_states(active, reset_at);
CREATE INDEX IF NOT EXISTS idx_xai_account_states_auth ON xai_account_states(auth_index, auth_id, source);
CREATE TABLE IF NOT EXISTS summary_cache (
  cache_key TEXT PRIMARY KEY,
  window TEXT NOT NULL DEFAULT '',
  limit_count INTEGER NOT NULL DEFAULT 0,
  cached_at INTEGER NOT NULL DEFAULT 0,
  duration_ms INTEGER NOT NULL DEFAULT 0,
  revision TEXT NOT NULL DEFAULT '',
  last_error TEXT NOT NULL DEFAULT '',
  data_json TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_summary_cache_cached_at ON summary_cache(cached_at);
CREATE TABLE IF NOT EXISTS store_state (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS autoban_bans (
  auth_id TEXT PRIMARY KEY,
  auth_index TEXT NOT NULL DEFAULT '',
  source TEXT NOT NULL DEFAULT '',
  provider TEXT NOT NULL DEFAULT '',
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
  release_reason TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_autoban_bans_active_reset ON autoban_bans(active, reset_at);
CREATE TABLE IF NOT EXISTS invalid_auths (
  auth_id TEXT PRIMARY KEY,
  auth_index TEXT NOT NULL DEFAULT '',
  source TEXT NOT NULL DEFAULT '',
  provider TEXT NOT NULL DEFAULT '',
  reason TEXT NOT NULL DEFAULT '',
  invalidated_at INTEGER NOT NULL,
  active INTEGER NOT NULL DEFAULT 1,
  last_status_code INTEGER NOT NULL DEFAULT 401,
  auth_file TEXT NOT NULL DEFAULT '',
  auth_file_mtime INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_invalid_auths_active ON invalid_auths(active);
CREATE TABLE IF NOT EXISTS quota_trigger_runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  auth_id TEXT NOT NULL DEFAULT '',
  auth_index TEXT NOT NULL DEFAULT '',
  source TEXT NOT NULL DEFAULT '',
  provider TEXT NOT NULL DEFAULT '',
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
);
CREATE INDEX IF NOT EXISTS idx_quota_trigger_runs_account ON quota_trigger_runs(auth_index, auth_id, source, auth_file, finished_at);
CREATE INDEX IF NOT EXISTS idx_quota_trigger_runs_finished_at ON quota_trigger_runs(finished_at);
CREATE INDEX IF NOT EXISTS idx_quota_trigger_runs_status_finished ON quota_trigger_runs(status, finished_at);
CREATE INDEX IF NOT EXISTS idx_quota_trigger_runs_auth_file_finished ON quota_trigger_runs(auth_file, finished_at);
`

func TestCanonicalProvider(t *testing.T) {
	for _, test := range []struct {
		name     string
		value    string
		fallback string
		want     string
	}{
		{name: "canonical codex", value: "  CoDeX  ", fallback: providerXAI, want: providerCodex},
		{name: "unknown preserved", value: " Custom-AI ", fallback: providerCodex, want: "custom-ai"},
		{name: "fallback", value: " \t ", fallback: " XAI ", want: providerXAI},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := canonicalProviderOr(test.value, test.fallback); got != test.want {
				t.Fatalf("canonicalProviderOr(%q, %q) = %q, want %q", test.value, test.fallback, got, test.want)
			}
		})
	}
}

func TestSQLiteHistoricalSchemasV0ThroughV5Migrate(t *testing.T) {
	historicalV5 := strings.Replace(
		historicalSQLiteSchemaV0To4,
		"  source TEXT NOT NULL DEFAULT '',\n  plan_type TEXT NOT NULL DEFAULT '',",
		"  source TEXT NOT NULL DEFAULT '',\n  auth_file TEXT NOT NULL DEFAULT '',\n  plan_type TEXT NOT NULL DEFAULT '',",
		1,
	)
	for version := 0; version <= 5; version++ {
		version := version
		t.Run(fmt.Sprintf("v%d", version), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "usage.db")
			db := openProviderMigrationDB(t, path)
			dll := historicalSQLiteSchemaV0To4
			if version == 5 {
				dll = historicalV5
			}
			if _, err := db.Exec(dll); err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec(fmt.Sprintf(`PRAGMA user_version=%d`, version)); err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec(`
INSERT INTO usage_events(requested_at,provider) VALUES(1,'codex');
INSERT INTO invalid_auths(auth_id,provider,reason,invalidated_at,active) VALUES('legacy-invalid','','legacy',1,1);
INSERT INTO autoban_bans(auth_id,provider,window,reason,banned_at,reset_at,active) VALUES('legacy-ban','','5h','legacy',1,9999999999,1);
INSERT INTO xai_account_states(state_key,state,reason,observed_at,active) VALUES('legacy-xai','rate_limited','legacy',1,1);`); err != nil {
				t.Fatal(err)
			}
			reservationInsert := `INSERT INTO account_protection_reservations(auth_id,auth_index,source,plan_type,created_at,expires_at) VALUES('legacy','legacy','','plus',1,9999999999)`
			if version == 5 {
				reservationInsert = `INSERT INTO account_protection_reservations(auth_id,auth_index,source,auth_file,plan_type,created_at,expires_at) VALUES('legacy','legacy','','legacy.json','plus',1,9999999999)`
			}
			if _, err := db.Exec(reservationInsert); err != nil {
				t.Fatal(err)
			}

			if err := migrateSQLiteStore(context.Background(), db, path); err != nil {
				t.Fatal(err)
			}
			if err := verifySQLiteV6Store(context.Background(), db); err != nil {
				t.Fatal(err)
			}
			for table, wantProvider := range map[string]string{
				"invalid_auths":      providerCodex,
				"autoban_bans":       providerCodex,
				"xai_account_states": providerXAI,
			} {
				var got string
				if err := db.QueryRow(`SELECT provider FROM ` + quoteSQLiteIdentifier(table) + ` LIMIT 1`).Scan(&got); err != nil {
					t.Fatal(err)
				}
				if got != wantProvider {
					t.Fatalf("%s provider = %q, want %q", table, got, wantProvider)
				}
			}
			var generate int
			if err := db.QueryRow(`SELECT generate FROM usage_events LIMIT 1`).Scan(&generate); err != nil {
				t.Fatal(err)
			}
			if generate != 1 {
				t.Fatalf("historical usage generate = %d, want 1", generate)
			}
			var reservations int
			if err := db.QueryRow(`SELECT COUNT(*) FROM account_protection_reservations`).Scan(&reservations); err != nil {
				t.Fatal(err)
			}
			wantReservations := 0
			if version == 5 {
				wantReservations = 1
			}
			if reservations != wantReservations {
				t.Fatalf("reservations = %d, want %d", reservations, wantReservations)
			}
		})
	}
}

func TestSQLiteV6FreshSchemaProviderConstraints(t *testing.T) {
	path := filepath.Join(t.TempDir(), "usage.db")
	db := openProviderMigrationDB(t, path)
	if _, err := db.Exec(schemaSQL); err != nil {
		t.Fatal(err)
	}
	if err := migrateSQLiteStore(context.Background(), db, path); err != nil {
		t.Fatal(err)
	}

	assertSQLiteSchemaVersion(t, db, currentSQLiteSchemaVersion)
	assertCompositePrimaryKey(t, db, "invalid_auths", []string{"provider", "auth_id"})
	assertCompositePrimaryKey(t, db, "autoban_bans", []string{"provider", "auth_id"})
	assertCompositePrimaryKey(t, db, "xai_account_states", []string{"provider", "state_key"})

	for name, statement := range map[string]string{
		"usage missing": `INSERT INTO usage_events(requested_at) VALUES(1)`,
		"usage event":   `INSERT INTO usage_events(requested_at,provider) VALUES(1,' OpenAI ')`,
		"quota run":     `INSERT INTO quota_trigger_runs(provider,started_at,finished_at) VALUES('OPENAI',1,2)`,
		"invalid auth":  `INSERT INTO invalid_auths(auth_id,provider,invalidated_at) VALUES('bad',' OpenAI ',1)`,
		"autoban":       `INSERT INTO autoban_bans(auth_id,provider,banned_at,reset_at) VALUES('bad','OPENAI',1,2)`,
		"xai state":     `INSERT INTO xai_account_states(state_key,provider,observed_at) VALUES('bad',' xai',1)`,
		"reservation":   `INSERT INTO account_protection_reservations(provider,created_at,expires_at) VALUES('Custom-AI ',1,2)`,
	} {
		t.Run(name+" provider check", func(t *testing.T) {
			if _, err := db.Exec(statement); err == nil {
				t.Fatal("non-canonical provider unexpectedly passed the database CHECK")
			}
		})
	}

	if _, err := db.Exec(`
INSERT INTO invalid_auths(auth_id,provider,invalidated_at) VALUES('shared','custom-ai',1);
INSERT INTO invalid_auths(auth_id,provider,invalidated_at) VALUES('shared','codex',2);
INSERT INTO xai_account_states(state_key,observed_at) VALUES('default-xai',1);
INSERT INTO account_protection_reservations(created_at,expires_at) VALUES(1,2);
INSERT INTO usage_events(requested_at,provider) VALUES(1,'codex');
INSERT INTO quota_trigger_runs(started_at,finished_at) VALUES(1,2);`); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM invalid_auths WHERE auth_id='shared'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("provider-scoped invalid auth rows = %d, want 2", count)
	}
	var xaiProvider, reservationProvider, usageProvider, quotaProvider string
	var generate int
	if err := db.QueryRow(`SELECT provider FROM xai_account_states WHERE state_key='default-xai'`).Scan(&xaiProvider); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT provider FROM account_protection_reservations LIMIT 1`).Scan(&reservationProvider); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT generate FROM usage_events LIMIT 1`).Scan(&generate); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT provider FROM usage_events LIMIT 1`).Scan(&usageProvider); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT provider FROM quota_trigger_runs LIMIT 1`).Scan(&quotaProvider); err != nil {
		t.Fatal(err)
	}
	if xaiProvider != providerXAI || reservationProvider != providerCodex || usageProvider != providerCodex || quotaProvider != providerCodex || generate != 1 {
		t.Fatalf("fresh defaults = xai:%q reservation:%q usage:%q quota:%q generate:%d", xaiProvider, reservationProvider, usageProvider, quotaProvider, generate)
	}
}

func TestSQLiteSyntheticMalformedV5ProviderMigrationCanonicalizesAndKeepsWholeWinner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "usage.db")
	db := openProviderMigrationDB(t, path)
	createSyntheticMalformedProviderMigrationV5Fixture(t, db, true)

	if err := migrateSQLiteStore(context.Background(), db, path); err != nil {
		t.Fatal(err)
	}
	assertSQLiteSchemaVersion(t, db, currentSQLiteSchemaVersion)
	assertNoV6TemporaryTables(t, db)

	var provider, authIndex, reason string
	var invalidatedAt int64
	var active int
	if err := db.QueryRow(`SELECT provider,auth_index,reason,invalidated_at,active FROM invalid_auths WHERE provider='openai' AND auth_id='dup'`).Scan(
		&provider, &authIndex, &reason, &invalidatedAt, &active,
	); err != nil {
		t.Fatal(err)
	}
	if provider != "openai" || authIndex != "active-whole-row" || reason != "active-wins" || invalidatedAt != 10 || active != 1 {
		t.Fatalf("invalid-auth winner was column-mixed: provider=%q auth_index=%q reason=%q invalidated_at=%d active=%d", provider, authIndex, reason, invalidatedAt, active)
	}
	var banReason, releaseReason string
	var bannedAt, releasedAt int64
	if err := db.QueryRow(`SELECT reason,banned_at,active,released_at,release_reason FROM autoban_bans WHERE provider='grok' AND auth_id='ban-dup'`).Scan(
		&banReason, &bannedAt, &active, &releasedAt, &releaseReason,
	); err != nil {
		t.Fatal(err)
	}
	if banReason != "inactive-loses" || bannedAt != 100 || active != 0 || releasedAt != 101 || releaseReason != "released" {
		t.Fatalf("autoban released-state winner was column-mixed: reason=%q banned=%d active=%d released=%d release_reason=%q", banReason, bannedAt, active, releasedAt, releaseReason)
	}

	for _, check := range []struct {
		query string
		want  string
	}{
		{query: `SELECT provider FROM invalid_auths WHERE auth_id='blank-provider'`, want: providerCodex},
		{query: `SELECT provider FROM invalid_auths WHERE auth_id='unknown-provider'`, want: "custom-ai"},
		{query: `SELECT provider FROM autoban_bans WHERE auth_id='ban-dup'`, want: "grok"},
		{query: `SELECT provider FROM xai_account_states WHERE state_key='state-dup'`, want: "openai"},
		{query: `SELECT provider FROM account_protection_reservations WHERE id=1`, want: providerCodex},
		{query: `SELECT provider FROM usage_events WHERE id=1`, want: providerCodex},
		{query: `SELECT provider FROM quota_trigger_runs WHERE id=1`, want: providerXAI},
	} {
		var got string
		if err := db.QueryRow(check.query).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != check.want {
			t.Fatalf("%s = %q, want %q", check.query, got, check.want)
		}
	}

	var shared int
	if err := db.QueryRow(`SELECT COUNT(*) FROM invalid_auths WHERE auth_id='shared-auth'`).Scan(&shared); err != nil {
		t.Fatal(err)
	}
	if shared != 2 {
		t.Fatalf("unknown provider partition collapsed rows: got %d, want 2", shared)
	}
	var generate int
	if err := db.QueryRow(`SELECT generate FROM usage_events WHERE id=1`).Scan(&generate); err != nil {
		t.Fatal(err)
	}
	if generate != 1 {
		t.Fatalf("legacy usage generate = %d, want 1", generate)
	}
}

func TestSQLiteHistoricalV5ProviderMigration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "usage.db")
	db := openProviderMigrationDB(t, path)
	createHistoricalSQLiteV5Fixture(t, db, true)

	if err := migrateSQLiteStore(context.Background(), db, path); err != nil {
		t.Fatal(err)
	}
	assertSQLiteSchemaVersion(t, db, currentSQLiteSchemaVersion)
	assertNoV6TemporaryTables(t, db)
	for _, check := range []struct {
		query string
		want  string
	}{
		{query: `SELECT provider FROM usage_events WHERE id=1`, want: providerCodex},
		{query: `SELECT provider FROM quota_trigger_runs WHERE id=1`, want: providerXAI},
		{query: `SELECT provider FROM invalid_auths WHERE auth_id='historical-invalid'`, want: providerCodex},
		{query: `SELECT provider FROM autoban_bans WHERE auth_id='historical-ban'`, want: providerCodex},
		{query: `SELECT provider FROM xai_account_states WHERE state_key='historical-xai'`, want: providerXAI},
		{query: `SELECT provider FROM account_protection_reservations WHERE id=1`, want: providerCodex},
	} {
		var got string
		if err := db.QueryRow(check.query).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != check.want {
			t.Fatalf("%s = %q, want %q", check.query, got, check.want)
		}
	}
	var generate int
	if err := db.QueryRow(`SELECT generate FROM usage_events WHERE id=1`).Scan(&generate); err != nil {
		t.Fatal(err)
	}
	if generate != 1 {
		t.Fatalf("historical usage generate = %d, want 1", generate)
	}
}

func TestSQLiteHistoricalV5MigrationReadsCommittedWALSidecars(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "usage.db")
	writer := openProviderMigrationDB(t, path)
	if _, err := writer.Exec(`PRAGMA wal_autocheckpoint=0`); err != nil {
		t.Fatal(err)
	}
	createHistoricalSQLiteV5Fixture(t, writer, false)
	if _, err := writer.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Exec(`INSERT INTO usage_events(requested_at,provider,auth_id,total_tokens) VALUES(100,'','wal-only',1234)`); err != nil {
		t.Fatal(err)
	}
	for _, sidecar := range []string{path + "-wal", path + "-shm"} {
		info, err := os.Stat(sidecar)
		if err != nil {
			t.Fatalf("committed SQLite sidecar %s is missing: %v", filepath.Base(sidecar), err)
		}
		if info.Size() == 0 {
			t.Fatalf("committed SQLite sidecar %s is empty", filepath.Base(sidecar))
		}
	}

	migrator := openProviderMigrationDB(t, path)
	if err := migrateSQLiteStore(context.Background(), migrator, path); err != nil {
		t.Fatal(err)
	}
	var provider string
	var tokens int64
	if err := migrator.QueryRow(`SELECT provider,total_tokens FROM usage_events WHERE auth_id='wal-only'`).Scan(&provider, &tokens); err != nil {
		t.Fatal(err)
	}
	if provider != providerCodex || tokens != 1234 {
		t.Fatalf("WAL row after migration provider=%q tokens=%d", provider, tokens)
	}
	if err := verifySQLiteV6Store(context.Background(), migrator); err != nil {
		t.Fatal(err)
	}
}

func TestSQLiteHistoricalV2PrivacyRewriteUsesProviderScopedKeysFirst(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "usage.db")
	writeAPIKeySecretForTest(t, dir, bytes.Repeat([]byte{0x71}, 32))
	crossProviderRaw := "opaque-provider-key-cross-provider-collision-001"
	sameProviderRaw := "opaque-provider-key-same-provider-collision-002"
	writeConfiguredAPIKeysForTest(t, crossProviderRaw, sameProviderRaw)
	crossProviderFingerprint := privacySafeAPIKey(path, crossProviderRaw)
	sameProviderFingerprint := privacySafeAPIKey(path, sameProviderRaw)

	db := openProviderMigrationDB(t, path)
	if _, err := db.Exec(historicalSQLiteSchemaV0To4); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`PRAGMA user_version=2`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`
INSERT INTO invalid_auths(auth_id,provider,reason,invalidated_at,active,last_status_code)
VALUES(?, 'codex', 'cross-codex-raw', 10, 1, 401);
INSERT INTO invalid_auths(auth_id,provider,reason,invalidated_at,active,last_status_code)
VALUES(?, 'xai', 'cross-xai-protected', 20, 1, 403);
INSERT INTO invalid_auths(auth_id,provider,reason,invalidated_at,active,last_status_code)
VALUES(?, 'codex', 'same-active-wins', 10, 1, 401);
INSERT INTO invalid_auths(auth_id,provider,reason,invalidated_at,active,last_status_code)
VALUES(?, 'codex', 'same-inactive-newer', 100, 0, 403);`, crossProviderRaw, crossProviderFingerprint, sameProviderRaw, sameProviderFingerprint); err != nil {
		t.Fatal(err)
	}

	if err := initializeSQLiteStore(context.Background(), db, path); err != nil {
		t.Fatal(err)
	}
	var crossCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM invalid_auths WHERE auth_id=? AND provider IN ('codex','xai')`, crossProviderFingerprint).Scan(&crossCount); err != nil {
		t.Fatal(err)
	}
	if crossCount != 2 {
		t.Fatalf("cross-Provider protected identity rows = %d, want 2", crossCount)
	}
	var reason string
	var active int
	if err := db.QueryRow(`SELECT reason,active FROM invalid_auths WHERE provider='codex' AND auth_id=?`, sameProviderFingerprint).Scan(&reason, &active); err != nil {
		t.Fatal(err)
	}
	if reason != "same-active-wins" || active != 1 {
		t.Fatalf("same-Provider protected collision winner reason=%q active=%d", reason, active)
	}
}

func TestSQLiteHistoricalV2ForeignV1RestrictionDoesNotBindSecret(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "usage.db")
	t.Setenv("CPA_CONFIG_PATH", filepath.Join(dir, "missing-config.yaml"))
	db := openProviderMigrationDB(t, path)
	if _, err := db.Exec(historicalSQLiteSchemaV0To4); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`PRAGMA user_version=2`); err != nil {
		t.Fatal(err)
	}
	foreignFingerprint := "keyfp:v1:0123456789abcdef0123456789abcdef:ABCD"
	if _, err := db.Exec(`INSERT INTO invalid_auths(auth_id,provider,reason,invalidated_at,active) VALUES(?,'custom-ai','foreign inert',1,1)`, foreignFingerprint); err != nil {
		t.Fatal(err)
	}

	if err := initializeSQLiteStore(context.Background(), db, path); err != nil {
		t.Fatal(err)
	}
	var provider, authID string
	if err := db.QueryRow(`SELECT provider,auth_id FROM invalid_auths WHERE provider='custom-ai'`).Scan(&provider, &authID); err != nil {
		t.Fatal(err)
	}
	if provider != "custom-ai" || authID != foreignFingerprint {
		t.Fatalf("foreign v1 row provider=%q auth_id=%q", provider, authID)
	}
}

func TestSQLiteV6MigrationConcurrentHandles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "usage.db")
	setup := openProviderMigrationDB(t, path)
	createHistoricalSQLiteV5Fixture(t, setup, false)
	if err := setup.Close(); err != nil {
		t.Fatal(err)
	}

	db1 := openProviderMigrationDB(t, path)
	db2 := openProviderMigrationDB(t, path)
	start := make(chan struct{})
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for _, db := range []*sql.DB{db1, db2} {
		wg.Add(1)
		go func(db *sql.DB) {
			defer wg.Done()
			<-start
			errs <- migrateSQLiteStore(context.Background(), db, path)
		}(db)
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent migration: %v", err)
		}
	}
	assertSQLiteSchemaVersion(t, db1, currentSQLiteSchemaVersion)
	assertNoV6TemporaryTables(t, db1)
}

func TestSQLiteV6MigrationFaultRollsBackWithoutTemporaryTables(t *testing.T) {
	stages := []string{
		"bootstrap-create", "additive-columns",
		"secret-binding", "reset-normalization", "reservation-cleanup", "summary-cache-v2-cleanup",
		"privacy-usage-events", "privacy-summary-cache",
		"privacy-invalid-auths", "privacy-autoban-bans", "privacy-xai-account-states",
		"privacy-account-protection-reservations", "privacy-quota-trigger-runs",
		"privacy-quarantine-markers", "privacy-unlinkable-state", "summary-cache-v3-cleanup",
		"provider-canonicalization",
		"usage-events-create", "usage-events-copy", "usage-events-drop", "usage-events-rename", "usage-events-index",
		"quota-trigger-runs-create", "quota-trigger-runs-copy", "quota-trigger-runs-drop", "quota-trigger-runs-rename", "quota-trigger-runs-index",
		"invalid-auths-create", "invalid-auths-copy", "invalid-auths-drop", "invalid-auths-rename", "invalid-auths-index",
		"autoban-bans-create", "autoban-bans-copy", "autoban-bans-drop", "autoban-bans-rename", "autoban-bans-index",
		"xai-account-states-create", "xai-account-states-copy", "xai-account-states-drop", "xai-account-states-rename", "xai-account-states-index",
		"reservations-create", "reservations-copy", "reservations-drop", "reservations-rename", "reservations-index",
		"provider-indexes", "version", "schema-indexes", "verify",
	}
	for _, stage := range stages {
		t.Run(stage, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "usage.db")
			db := openProviderMigrationDB(t, path)
			createProviderMigrationV0FaultFixture(t, db)

			wantErr := errors.New("forced v6 migration failure at " + stage)
			reached := false
			sqliteMigrationV6FaultHook = func(_ context.Context, _ *sql.Tx, got string) error {
				if got != stage {
					return nil
				}
				reached = true
				return wantErr
			}
			t.Cleanup(func() { sqliteMigrationV6FaultHook = nil })
			if err := migrateSQLiteStore(context.Background(), db, path); !errors.Is(err, wantErr) {
				t.Fatalf("migration error = %v, want %v", err, wantErr)
			}
			if !reached {
				t.Fatalf("fault stage %q was not reached", stage)
			}
			assertSQLiteSchemaVersion(t, db, 0)
			assertNoV6TemporaryTables(t, db)

			columns := tableColumnNames(t, db, "usage_events")
			if columns["generate"] {
				t.Fatal("rolled-back generate column is still present")
			}
			var provider string
			if err := db.QueryRow(`SELECT provider FROM invalid_auths ORDER BY rowid LIMIT 1`).Scan(&provider); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(provider, " ") {
				t.Fatalf("provider was canonicalized despite rollback: %q", provider)
			}
			var quarantineMarkers, reservations, summaries int
			if err := db.QueryRow(`SELECT COUNT(*) FROM store_state WHERE key GLOB 'api_key_privacy_quarantine_*'`).Scan(&quarantineMarkers); err != nil {
				t.Fatal(err)
			}
			if err := db.QueryRow(`SELECT COUNT(*) FROM account_protection_reservations`).Scan(&reservations); err != nil {
				t.Fatal(err)
			}
			if err := db.QueryRow(`SELECT COUNT(*) FROM summary_cache`).Scan(&summaries); err != nil {
				t.Fatal(err)
			}
			if quarantineMarkers != 0 || reservations != 1 || summaries != 1 {
				t.Fatalf("rollback state markers=%d reservations=%d summaries=%d, want 0/1/1", quarantineMarkers, reservations, summaries)
			}

			sqliteMigrationV6FaultHook = nil
			if err := migrateSQLiteStore(context.Background(), db, path); err != nil {
				t.Fatalf("retry migration: %v", err)
			}
			assertSQLiteSchemaVersion(t, db, currentSQLiteSchemaVersion)
			assertNoV6TemporaryTables(t, db)
		})
	}
}

func createProviderMigrationV0FaultFixture(t *testing.T, db *sql.DB) {
	t.Helper()
	if _, err := db.Exec(historicalSQLiteSchemaV0To4); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`PRAGMA user_version=0`); err != nil {
		t.Fatal(err)
	}
	fingerprint := legacyV0Fingerprint("sk-provider-migration-fault-unconfigured")
	if _, err := db.Exec(`INSERT INTO usage_events
		(requested_at,provider,api_key,auth_id,auth_index,source,primary_reset_at)
		VALUES(1,' CoDeX ',?,?,?,?,1700000000000)`, fingerprint, fingerprint, fingerprint, fingerprint); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO account_protection_reservations
		(auth_id,auth_index,source,plan_type,created_at,expires_at)
		VALUES('reservation','reservation','','plus',1,9999999999)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO summary_cache
		(cache_key,window,limit_count,cached_at,duration_ms,revision,last_error,data_json)
		VALUES('invalid','invalid',13,1,1,'','','{}')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO invalid_auths
		(auth_id,auth_index,source,provider,reason,invalidated_at,active)
		VALUES(?,?,?,' CoDeX ','fault fixture',1,1)`, fingerprint, fingerprint, fingerprint); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO autoban_bans
		(auth_id,auth_index,source,provider,window,reason,banned_at,reset_at,active)
		VALUES('fault-ban','fault-ban','',' CoDeX ','5h','fault fixture',1,9999999999,1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO xai_account_states
		(state_key,auth_id,auth_index,source,provider,state,reason,observed_at,active)
		VALUES('fault-xai','fault-xai','fault-xai','',' XAI ','rate_limited','fault fixture',1,1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO quota_trigger_runs
		(auth_id,auth_index,source,provider,auth_file,started_at,finished_at)
		VALUES('fault-quota','fault-quota','',' CoDeX ','fault.json',1,2)`); err != nil {
		t.Fatal(err)
	}
}

func openProviderMigrationDB(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := openSQLiteDB(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// createSyntheticMalformedProviderMigrationV5Fixture intentionally omits the
// historical global auth_id/state_key primary keys. It exercises deterministic
// repair of a hand-edited or partially reconstructed database, not a genuine
// v5 schema. Real v5 migration coverage uses createHistoricalSQLiteV5Fixture.
func createSyntheticMalformedProviderMigrationV5Fixture(t *testing.T, db *sql.DB, withRows bool) {
	t.Helper()
	if _, err := db.Exec(`
CREATE TABLE usage_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  requested_at INTEGER NOT NULL,
  provider TEXT
);
CREATE TABLE quota_trigger_runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  provider TEXT,
  started_at INTEGER,
  finished_at INTEGER
);
CREATE TABLE store_state (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL DEFAULT ''
);
CREATE TABLE invalid_auths (
  auth_id TEXT, auth_index TEXT, source TEXT, provider TEXT, reason TEXT,
  invalidated_at INTEGER, active INTEGER, last_status_code INTEGER,
  auth_file TEXT, auth_file_mtime INTEGER
);
CREATE TABLE autoban_bans (
  auth_id TEXT, auth_index TEXT, source TEXT, provider TEXT, window TEXT, reason TEXT,
  banned_at INTEGER, reset_at INTEGER, active INTEGER, last_status_code INTEGER,
  primary_used_percent REAL, primary_reset_at INTEGER,
  secondary_used_percent REAL, secondary_reset_at INTEGER,
  released_at INTEGER, release_reason TEXT
);
CREATE TABLE xai_account_states (
  state_key TEXT, auth_id TEXT, auth_index TEXT, source TEXT, provider TEXT,
  state TEXT, reason TEXT, observed_at INTEGER, reset_at INTEGER, active INTEGER,
  last_status_code INTEGER, auth_file TEXT, auth_file_mtime INTEGER
);
CREATE TABLE account_protection_reservations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  auth_id TEXT, auth_index TEXT, source TEXT, auth_file TEXT, plan_type TEXT,
  created_at INTEGER, expires_at INTEGER
);
PRAGMA user_version=5;`); err != nil {
		t.Fatal(err)
	}
	if !withRows {
		return
	}
	if _, err := db.Exec(`
INSERT INTO usage_events(id,requested_at,provider) VALUES(1,100,' ');
INSERT INTO quota_trigger_runs(id,provider,started_at,finished_at) VALUES(1,' XAI ',1,2);
INSERT INTO invalid_auths VALUES
  ('dup','inactive-newer','source-newer',' OpenAI ','inactive-loses',100,0,403,'newer.json',100),
  ('dup','active-whole-row','source-active','openai','active-wins',10,1,401,'active.json',10),
  ('blank-provider','','','','blank',1,1,401,'',0),
  ('unknown-provider','','',' Custom-AI ','unknown',1,1,401,'',0),
  ('shared-auth','','','codex','codex-row',1,1,401,'',0),
  ('shared-auth','','','xai','xai-row',1,1,401,'',0);
INSERT INTO autoban_bans VALUES
  ('ban-dup','inactive-newer','',' Grok ','5h','inactive-loses',100,500,0,429,NULL,NULL,NULL,NULL,101,'released'),
  ('ban-dup','active-whole-row','','grok','week','active-wins',10,20,1,429,95.0,20,80.0,30,0,'');
INSERT INTO xai_account_states VALUES
  ('state-dup','inactive-newer','','',' OpenAI ','unauthorized','inactive-loses',100,500,0,401,'newer.json',100),
  ('state-dup','active-whole-row','','','openai','rate_limited','active-wins',10,20,1,429,'active.json',10);
INSERT INTO account_protection_reservations
  (id,auth_id,auth_index,source,auth_file,plan_type,created_at,expires_at)
  VALUES(1,'reservation','reservation','','reservation.json','plus',1,1000);`); err != nil {
		t.Fatal(err)
	}
}

func createHistoricalSQLiteV5Fixture(t *testing.T, db *sql.DB, withRows bool) {
	t.Helper()
	if _, err := db.Exec(historicalSQLiteSchemaV0To4); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`ALTER TABLE account_protection_reservations ADD COLUMN auth_file TEXT NOT NULL DEFAULT ''`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`PRAGMA user_version=5`); err != nil {
		t.Fatal(err)
	}
	if !withRows {
		return
	}
	if _, err := db.Exec(`
INSERT INTO usage_events(id,requested_at,provider,auth_id,total_tokens)
VALUES(1,100,'','historical-usage',1000);
INSERT INTO quota_trigger_runs(id,auth_id,provider,started_at,finished_at)
VALUES(1,'historical-quota',' XAI ',1,2);
INSERT INTO invalid_auths(auth_id,provider,reason,invalidated_at,active)
VALUES('historical-invalid','','legacy',10,1);
INSERT INTO autoban_bans(auth_id,provider,window,reason,banned_at,reset_at,active)
VALUES('historical-ban','','5h','legacy',10,1000,1);
INSERT INTO xai_account_states(state_key,provider,state,reason,observed_at,active)
VALUES('historical-xai','','rate_limited','legacy',10,1);
INSERT INTO account_protection_reservations(id,auth_id,plan_type,created_at,expires_at,auth_file)
VALUES(1,'historical-reservation','plus',1,1000,'historical.json');`); err != nil {
		t.Fatal(err)
	}
}

func assertSQLiteSchemaVersion(t *testing.T, db *sql.DB, want int) {
	t.Helper()
	var got int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("schema version = %d, want %d", got, want)
	}
}

func assertCompositePrimaryKey(t *testing.T, db *sql.DB, table string, want []string) {
	t.Helper()
	rows, err := db.Query(`PRAGMA table_info(` + quoteSQLiteIdentifier(table) + `)`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	got := make([]string, len(want))
	for rows.Next() {
		var cid int
		var name, typ string
		var notNull int
		var defaultValue any
		var pk int
		if err := rows.Scan(&cid, &name, &typ, &notNull, &defaultValue, &pk); err != nil {
			t.Fatal(err)
		}
		if pk > len(got) {
			t.Fatalf("%s primary key position %d for %s exceeds expected width %d", table, pk, name, len(got))
		}
		if pk > 0 {
			got[pk-1] = name
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("%s primary key = %v, want %v", table, got, want)
		}
	}
}

func assertNoV6TemporaryTables(t *testing.T, db *sql.DB) {
	t.Helper()
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name LIKE '%_v6_new'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("v6 temporary tables left behind: %d", count)
	}
}

func tableColumnNames(t *testing.T, db *sql.DB, table string) map[string]bool {
	t.Helper()
	rows, err := db.Query(`PRAGMA table_info(` + quoteSQLiteIdentifier(table) + `)`)
	if err != nil {
		t.Fatal(err)
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
			t.Fatal(err)
		}
		columns[name] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return columns
}
