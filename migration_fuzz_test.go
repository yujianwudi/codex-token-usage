package main

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

func FuzzSQLiteV6MigrationFixture(f *testing.F) {
	fuzzRoot := f.TempDir()
	f.Setenv("CPA_TOKEN_USAGE_DIR", fuzzRoot)
	f.Setenv("CPA_CONFIG_PATH", filepath.Join(fuzzRoot, "missing-config.yaml"))
	for version := byte(0); version <= 5; version++ {
		f.Add([]byte{version, 0, 0, version, 1})
	}
	// A real historical schema with a deliberately missing required column must
	// fail atomically instead of being mistaken for a valid historical fixture.
	f.Add([]byte{5, 1, 1, 2, 1})

	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 64 {
			raw = raw[:64]
		}
		cursor := fuzzByteCursor{raw: raw}
		version := int(cursor.next() % 6)
		withDuplicateMutation := cursor.next()%2 == 1
		withMissingRequiredColumn := cursor.next()%4 == 1
		unknownProviders := [...]string{" Custom-AI ", "GROK", " Future.Provider "}
		unknownProvider := unknownProviders[int(cursor.next())%len(unknownProviders)]
		milliseconds := cursor.next()%2 == 1

		dir := t.TempDir()
		path := filepath.Join(dir, "usage.db")

		db, err := openSQLiteDB(path)
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		createHistoricalMigrationFuzzFixture(t, db, version, withDuplicateMutation, unknownProvider, milliseconds)
		if withMissingRequiredColumn {
			mutateHistoricalUsageFixtureMissingRequestedAt(t, db)
			assertMigrationFuzzRollback(t, db, path, version)
			return
		}

		if err := migrateSQLiteStore(context.Background(), db, path); err != nil {
			t.Fatalf("migrate structured historical v%d fixture: %v", version, err)
		}
		if err := verifySQLiteV6Store(context.Background(), db); err != nil {
			t.Fatalf("verify migrated historical v%d fixture: %v", version, err)
		}
		assertNoV6TemporaryTables(t, db)

		canonicalUnknown := canonicalProvider(unknownProvider)
		assertFuzzProviderValue(t, db, `SELECT provider FROM usage_events WHERE id=1`, providerCodex)
		assertFuzzProviderValue(t, db, `SELECT provider FROM invalid_auths WHERE auth_id='legacy-blank'`, providerCodex)
		assertFuzzProviderValue(t, db, `SELECT provider FROM autoban_bans WHERE auth_id='legacy-ban'`, providerCodex)
		assertFuzzProviderValue(t, db, `SELECT provider FROM xai_account_states WHERE state_key='legacy-xai'`, providerXAI)
		assertFuzzProviderValue(t, db, `SELECT provider FROM invalid_auths WHERE auth_id='duplicate'`, canonicalUnknown)

		var duplicateRows int
		if err := db.QueryRow(`SELECT COUNT(*) FROM invalid_auths WHERE provider=? AND auth_id='duplicate'`, canonicalUnknown).Scan(&duplicateRows); err != nil {
			t.Fatal(err)
		}
		if duplicateRows != 1 {
			t.Fatalf("canonical duplicate rows = %d, want 1", duplicateRows)
		}

		var primaryReset int64
		if err := db.QueryRow(`SELECT primary_reset_at FROM usage_events WHERE id=1`).Scan(&primaryReset); err != nil {
			t.Fatal(err)
		}
		wantReset := int64(1_700_000_000)
		if milliseconds && version >= 4 {
			wantReset = 1_700_000_000_000
		}
		if primaryReset != wantReset {
			t.Fatalf("v%d migrated reset = %d, want %d", version, primaryReset, wantReset)
		}
	})
}

func createHistoricalMigrationFuzzFixture(
	t *testing.T,
	db *sql.DB,
	version int,
	withDuplicateMutation bool,
	unknownProvider string,
	milliseconds bool,
) {
	t.Helper()
	historicalSchema := historicalSQLiteSchemaV0To4
	if version == 5 {
		historicalSchema = strings.Replace(
			historicalSQLiteSchemaV0To4,
			"  source TEXT NOT NULL DEFAULT '',\n  plan_type TEXT NOT NULL DEFAULT '',",
			"  source TEXT NOT NULL DEFAULT '',\n  auth_file TEXT NOT NULL DEFAULT '',\n  plan_type TEXT NOT NULL DEFAULT '',",
			1,
		)
	}
	if _, err := db.Exec(historicalSchema); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(fmt.Sprintf(`PRAGMA user_version=%d`, version)); err != nil {
		t.Fatal(err)
	}

	reset := int64(1_700_000_000)
	if milliseconds {
		reset *= 1000
	}
	if _, err := db.Exec(`INSERT INTO usage_events(id,requested_at,provider,primary_reset_at,secondary_reset_at) VALUES(1,1,' CoDeX ',?,?)`, reset, reset); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`
INSERT INTO invalid_auths(auth_id,provider,reason,invalidated_at,active) VALUES
  ('legacy-blank','','blank',1,1),
  ('duplicate',?,'inactive-newer',20,0);
INSERT INTO autoban_bans(auth_id,provider,window,reason,banned_at,reset_at,active) VALUES
  ('legacy-ban','','5h','blank',1,9999999999,1);
INSERT INTO xai_account_states(state_key,provider,state,reason,observed_at,reset_at,active) VALUES
  ('legacy-xai','','rate_limited','blank',1,9999999999,1);`, unknownProvider); err != nil {
		t.Fatal(err)
	}

	if withDuplicateMutation {
		mutateHistoricalInvalidAuthFixtureForDuplicates(t, db)
		if _, err := db.Exec(`INSERT INTO invalid_auths(
			auth_id,auth_index,source,provider,reason,invalidated_at,active,last_status_code,auth_file,auth_file_mtime
		) VALUES('duplicate','','',?,'active-winner',10,1,401,'',0)`, canonicalProvider(unknownProvider)); err != nil {
			t.Fatal(err)
		}
	}

	if version == 5 {
		if _, err := db.Exec(`INSERT INTO account_protection_reservations(auth_id,auth_index,source,auth_file,plan_type,created_at,expires_at) VALUES('reservation','reservation','','reservation.json','plus',1,9999999999)`); err != nil {
			t.Fatal(err)
		}
	} else if _, err := db.Exec(`INSERT INTO account_protection_reservations(auth_id,auth_index,source,plan_type,created_at,expires_at) VALUES('reservation','reservation','','plus',1,9999999999)`); err != nil {
		t.Fatal(err)
	}
}

func mutateHistoricalInvalidAuthFixtureForDuplicates(t *testing.T, db *sql.DB) {
	t.Helper()
	if _, err := db.Exec(`
ALTER TABLE invalid_auths RENAME TO invalid_auths_historical_original;
CREATE TABLE invalid_auths AS SELECT * FROM invalid_auths_historical_original;
DROP TABLE invalid_auths_historical_original;`); err != nil {
		t.Fatal(err)
	}
}

func mutateHistoricalUsageFixtureMissingRequestedAt(t *testing.T, db *sql.DB) {
	t.Helper()
	if _, err := db.Exec(`
ALTER TABLE usage_events RENAME TO usage_events_historical_original;
CREATE TABLE usage_events AS
  SELECT id,provider,primary_reset_at,secondary_reset_at
  FROM usage_events_historical_original;
DROP TABLE usage_events_historical_original;`); err != nil {
		t.Fatal(err)
	}
}

func assertMigrationFuzzRollback(t *testing.T, db *sql.DB, path string, wantVersion int) {
	t.Helper()
	err := migrateSQLiteStore(context.Background(), db, path)
	if err == nil {
		t.Fatal("migration unexpectedly accepted a historical schema missing usage_events.requested_at")
	}
	assertSQLiteSchemaVersion(t, db, wantVersion)
	assertNoV6TemporaryTables(t, db)
	if err := verifySQLiteQuickCheck(context.Background(), db); err != nil {
		t.Fatalf("quick_check after rollback: %v", err)
	}
	columns := tableColumnNames(t, db, "usage_events")
	if columns["requested_at"] || !columns["id"] || !columns["provider"] {
		t.Fatalf("rollback changed malformed historical columns: %#v", columns)
	}
	var provider string
	if err := db.QueryRow(`SELECT provider FROM usage_events WHERE id=1`).Scan(&provider); err != nil {
		t.Fatal(err)
	}
	if provider != " CoDeX " {
		t.Fatalf("failed migration partially canonicalized usage provider: %q", provider)
	}
}

func assertFuzzProviderValue(t *testing.T, db *sql.DB, query, want string) {
	t.Helper()
	var got string
	if err := db.QueryRow(query).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("provider query %q = %q, want %q", query, got, want)
	}
}
