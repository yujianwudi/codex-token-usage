package main

import (
	"context"
	"database/sql"
	"fmt"
)

const currentSQLiteSchemaVersion = 3

func migrateSQLiteStore(ctx context.Context, db *sql.DB, dbPath string) error {
	var version int
	if err := db.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&version); err != nil {
		return err
	}
	if version > currentSQLiteSchemaVersion {
		return fmt.Errorf("usage database schema %d is newer than supported schema %d", version, currentSQLiteSchemaVersion)
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
