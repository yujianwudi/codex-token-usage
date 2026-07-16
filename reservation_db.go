package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/mattn/go-sqlite3"
)

const accountProtectionReservationBusyTimeoutMS = 200

// reservationTransactionDB returns a handle whose BeginTx uses SQLite
// BEGIN IMMEDIATE. The early writer reservation is the cross-process
// serialization boundary for read-capacity -> choose -> insert-reservation.
// In-memory databases cannot be reopened as the same database, so unit tests
// using :memory: retain the ordinary handle and rely on their single process.
func (s *store) reservationTransactionDB(ctx context.Context, mainDB *sql.DB) (*sql.DB, func(), error) {
	// The store already owns the canonical file path in production. Prefer it
	// before querying PRAGMA database_list: a concurrent usage refresh can hold
	// the primary pool's existing connection, and opening another primary DSN
	// would repeat journal_mode=WAL negotiation while a writer lock is held.
	path := knownReservationSQLitePath(s, mainDB)
	if path == "" {
		var err error
		path, err = reservationSQLiteMainDatabasePath(ctx, mainDB)
		if err != nil {
			return nil, nil, err
		}
	}
	if path == "" {
		return mainDB, func() {}, nil
	}

	cacheable := false
	if s != nil {
		s.mu.Lock()
		cacheable = s.db == mainDB && sameSQLitePath(s.dbPath, path)
		if cacheable && s.reservationDB != nil && sameSQLitePath(s.reservationDBPath, path) {
			db := s.reservationDB
			s.mu.Unlock()
			return db, func() {}, nil
		}
		if cacheable && s.reservationDB != nil {
			_ = s.reservationDB.Close()
			s.reservationDB = nil
			s.reservationDBPath = ""
		}
		s.mu.Unlock()
	}

	db, err := openSQLiteReservationDB(path)
	if err != nil {
		return nil, nil, err
	}
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, nil, err
	}
	if !cacheable || s == nil {
		return db, func() { _ = db.Close() }, nil
	}

	s.mu.Lock()
	if s.db == mainDB && sameSQLitePath(s.dbPath, path) {
		if s.reservationDB != nil {
			_ = s.reservationDB.Close()
		}
		s.reservationDB = db
		s.reservationDBPath = path
		s.mu.Unlock()
		return db, func() {}, nil
	}
	s.mu.Unlock()
	return db, func() { _ = db.Close() }, nil
}

func knownReservationSQLitePath(s *store, mainDB *sql.DB) string {
	if s == nil || mainDB == nil {
		return ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db != mainDB {
		return ""
	}
	path := strings.TrimSpace(s.dbPath)
	if isMemorySQLitePath(path) {
		return ""
	}
	return path
}

func isMemorySQLitePath(path string) bool {
	normalized := strings.ToLower(strings.TrimSpace(path))
	return normalized == ":memory:" ||
		strings.HasPrefix(normalized, "file::memory:") ||
		strings.Contains(normalized, "?mode=memory") ||
		strings.Contains(normalized, "&mode=memory")
}

func openSQLiteReservationDB(path string) (*sql.DB, error) {
	// The primary store enables and verifies WAL before the reservation handle
	// is opened. Reissuing journal_mode=WAL on every new reservation connection
	// can itself require the SQLite writer lock. Under contention that consumes
	// one busy timeout before BEGIN IMMEDIATE consumes another, allowing a cold
	// scheduler pick to exceed the host's 750 ms deadline. Keep this handle
	// limited to the bounded lock wait and IMMEDIATE transaction mode; WAL is a
	// database property already established by initializeSQLiteStore.
	dsn := path + fmt.Sprintf("?_busy_timeout=%d&_txlock=immediate", accountProtectionReservationBusyTimeoutMS)
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	return db, nil
}

func reservationSQLiteMainDatabasePath(ctx context.Context, db *sql.DB) (string, error) {
	if db == nil {
		return "", errors.New("reservation database is unavailable")
	}
	rows, err := db.QueryContext(ctx, `PRAGMA database_list`)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	for rows.Next() {
		var seq int
		var name, path string
		if err := rows.Scan(&seq, &name, &path); err != nil {
			return "", err
		}
		if name == "main" {
			return strings.TrimSpace(path), nil
		}
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	return "", errors.New("sqlite main database path is unavailable")
}

func sameSQLitePath(left, right string) bool {
	return strings.EqualFold(strings.TrimSpace(left), strings.TrimSpace(right))
}

func isSQLiteBusyError(err error) bool {
	if err == nil {
		return false
	}
	var sqliteErr sqlite3.Error
	if errors.As(err, &sqliteErr) {
		return sqliteErr.Code == sqlite3.ErrBusy || sqliteErr.Code == sqlite3.ErrLocked
	}
	text := strings.ToLower(err.Error())
	return strings.Contains(text, "database is locked") || strings.Contains(text, "database table is locked")
}
