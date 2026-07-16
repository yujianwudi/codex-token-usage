package main

import (
	"context"
	"path/filepath"
	"testing"
)

func TestResetNormalizationRunsOnlyDuringV4Migration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "usage.db")
	db, err := openSQLiteDB(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Exec(schemaSQL); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`PRAGMA user_version=3`); err != nil {
		t.Fatal(err)
	}
	const milliseconds = int64(1_700_000_000_000)
	if _, err := db.Exec(`INSERT INTO usage_events (requested_at, provider, primary_reset_at, secondary_reset_at) VALUES (1, 'codex', ?, ?)`, milliseconds, milliseconds); err != nil {
		t.Fatal(err)
	}
	if err := migrateSQLiteStore(context.Background(), db, path); err != nil {
		t.Fatal(err)
	}
	var version int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != currentSQLiteSchemaVersion {
		t.Fatalf("schema version = %d, want %d", version, currentSQLiteSchemaVersion)
	}
	var primary, secondary int64
	if err := db.QueryRow(`SELECT primary_reset_at, secondary_reset_at FROM usage_events`).Scan(&primary, &secondary); err != nil {
		t.Fatal(err)
	}
	if primary != milliseconds/1000 || secondary != milliseconds/1000 {
		t.Fatalf("normalized reset timestamps = %d/%d", primary, secondary)
	}

	const postMigrationMilliseconds = int64(1_800_000_000_000)
	if _, err := db.Exec(`UPDATE usage_events SET primary_reset_at=?, secondary_reset_at=?`, postMigrationMilliseconds, postMigrationMilliseconds); err != nil {
		t.Fatal(err)
	}
	if err := migrateSQLiteStore(context.Background(), db, path); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT primary_reset_at, secondary_reset_at FROM usage_events`).Scan(&primary, &secondary); err != nil {
		t.Fatal(err)
	}
	if primary != postMigrationMilliseconds || secondary != postMigrationMilliseconds {
		t.Fatalf("mature schema was rescanned: reset timestamps = %d/%d", primary, secondary)
	}
}

func TestV5MigrationAddsReservationAuthFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "usage.db")
	db, err := openSQLiteDB(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Exec(`
CREATE TABLE account_protection_reservations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  auth_id TEXT NOT NULL DEFAULT '',
  auth_index TEXT NOT NULL DEFAULT '',
  source TEXT NOT NULL DEFAULT '',
  plan_type TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
PRAGMA user_version=4;`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO account_protection_reservations
		(auth_id, auth_index, source, plan_type, created_at, expires_at)
		VALUES ('legacy', 'legacy', '', 'plus', 1, 9999999999)`); err != nil {
		t.Fatal(err)
	}
	if err := migrateSQLiteStore(context.Background(), db, path); err != nil {
		t.Fatal(err)
	}
	rows, err := db.Query(`PRAGMA table_info(account_protection_reservations)`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	found := false
	for rows.Next() {
		var cid int
		var name, typ string
		var notNull int
		var defaultValue any
		var pk int
		if err := rows.Scan(&cid, &name, &typ, &notNull, &defaultValue, &pk); err != nil {
			t.Fatal(err)
		}
		found = found || name == "auth_file"
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatal("reservation auth_file column was not added")
	}
	var version int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != currentSQLiteSchemaVersion {
		t.Fatalf("schema version = %d, want %d", version, currentSQLiteSchemaVersion)
	}
	var reservations int
	if err := db.QueryRow(`SELECT COUNT(*) FROM account_protection_reservations`).Scan(&reservations); err != nil {
		t.Fatal(err)
	}
	if reservations != 0 {
		t.Fatalf("legacy reservations retained after v5 migration: %d", reservations)
	}
}
