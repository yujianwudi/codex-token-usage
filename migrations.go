package main

import (
	"context"
	"database/sql"
	"fmt"
)

const currentSQLiteSchemaVersion = 2

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
	if version < 2 {
		if err := migrateStoredAPIKeys(ctx, tx, dbPath); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
DELETE FROM summary_cache
WHERE lower(trim(window)) NOT IN ('today','24h','7d','30d','all')
   OR limit_count NOT IN (50,100,500,2000,5000)`); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, fmt.Sprintf(`PRAGMA user_version=%d`, currentSQLiteSchemaVersion)); err != nil {
		return err
	}
	return tx.Commit()
}
