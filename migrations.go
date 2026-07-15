package main

import (
	"context"
	"database/sql"
	"fmt"
)

const currentSQLiteSchemaVersion = 5

func migrateSQLiteStore(ctx context.Context, db *sql.DB, dbPath string) error {
	var version int
	if err := db.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&version); err != nil {
		return err
	}
	if version > currentSQLiteSchemaVersion {
		return fmt.Errorf("usage database schema %d is newer than supported schema %d", version, currentSQLiteSchemaVersion)
	}
	// Reservation auth_file became part of the persisted identity in v5. Add it
	// before both the v3 privacy rewrite and the schema-version fast path so
	// direct migrations and repaired mature databases use the same shape.
	if err := ensureAccountProtectionReservationColumns(ctx, db); err != nil {
		return err
	}
	if version == currentSQLiteSchemaVersion {
		return nil
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if version < 3 {
		if err := bindAPIKeyFingerprintSecret(ctx, tx, dbPath); err != nil {
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
	}
	if version < 5 {
		// Reservations belong to in-flight calls from the previous plugin
		// process. They cannot be assigned safely to the new file-scoped identity,
		// and no such calls survive the plugin upgrade, so discard them instead of
		// temporarily under-counting duplicate credentials until their TTLs expire.
		if _, err := tx.ExecContext(ctx, `DELETE FROM account_protection_reservations`); err != nil {
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
		if _, err := tx.ExecContext(ctx, `DELETE FROM summary_cache`); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, fmt.Sprintf(`PRAGMA user_version=%d`, currentSQLiteSchemaVersion)); err != nil {
		return err
	}
	return tx.Commit()
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
