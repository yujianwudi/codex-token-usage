package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	migrationProcessChildEnv     = "CPA_TEST_SQLITE_V6_MIGRATION_CHILD"
	migrationProcessDBEnv        = "CPA_TEST_SQLITE_V6_MIGRATION_DB"
	migrationProcessRoleEnv      = "CPA_TEST_SQLITE_V6_MIGRATION_ROLE"
	migrationProcessSignalsEnv   = "CPA_TEST_SQLITE_V6_MIGRATION_SIGNALS"
	migrationProcessRoleHolder   = "holder"
	migrationProcessRoleWaiter   = "waiter"
	migrationSignalHolderLocked  = "holder-locked"
	migrationSignalHolderRelease = "holder-release"
	migrationSignalWaiterReady   = "waiter-ready"
	migrationSignalWaiterStart   = "waiter-start"
	migrationSignalWaiterAttempt = "waiter-begin-attempted"
	migrationSignalWaiterLocked  = "waiter-locked"
)

type migrationChildProcess struct {
	cmd    *exec.Cmd
	output bytes.Buffer
	done   chan error
}

func TestSQLiteV6MigrationTwoOSProcesses(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "usage.db")
	setup := openProviderMigrationDB(t, path)
	historicalV5 := strings.Replace(
		historicalSQLiteSchemaV0To4,
		"  source TEXT NOT NULL DEFAULT '',\n  plan_type TEXT NOT NULL DEFAULT '',",
		"  source TEXT NOT NULL DEFAULT '',\n  auth_file TEXT NOT NULL DEFAULT '',\n  plan_type TEXT NOT NULL DEFAULT '',",
		1,
	)
	if _, err := setup.Exec(historicalV5); err != nil {
		t.Fatal(err)
	}
	if _, err := setup.Exec(`
PRAGMA user_version=5;
INSERT INTO usage_events(id,requested_at,provider) VALUES(1,100,' CoDeX ');
INSERT INTO quota_trigger_runs(id,provider,status,started_at,finished_at) VALUES(1,' XAI ','failed',1,2);
INSERT INTO invalid_auths(auth_id,provider,reason,invalidated_at,active) VALUES('legacy-invalid',' OpenAI ','active-wins',1,1);
INSERT INTO autoban_bans(auth_id,provider,window,reason,banned_at,reset_at,active) VALUES('legacy-ban',' CODEX ','5h','legacy',1,9999999999,1);
INSERT INTO xai_account_states(state_key,auth_id,provider,state,reason,observed_at,active) VALUES('legacy-xai','legacy-xai',' OpenAI ','rate_limited','active-wins',1,1);
INSERT INTO account_protection_reservations(id,auth_id,auth_index,source,auth_file,plan_type,created_at,expires_at) VALUES(1,'legacy','legacy','','legacy.json','plus',1,9999999999);`); err != nil {
		t.Fatal(err)
	}
	if err := bindAPIKeyFingerprintSecret(context.Background(), setup, path); err != nil {
		t.Fatal(err)
	}
	if err := setup.Close(); err != nil {
		t.Fatal(err)
	}

	signals := filepath.Join(dir, "migration-signals")
	if err := os.Mkdir(signals, 0o700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	holder := startSQLiteV6MigrationChild(t, ctx, path, signals, migrationProcessRoleHolder)
	waitForMigrationSignal(t, ctx, signals, migrationSignalHolderLocked)

	waiter := startSQLiteV6MigrationChild(t, ctx, path, signals, migrationProcessRoleWaiter)
	waitForMigrationSignal(t, ctx, signals, migrationSignalWaiterReady)
	writeMigrationSignal(t, signals, migrationSignalWaiterStart)
	waitForMigrationSignal(t, ctx, signals, migrationSignalWaiterAttempt)

	// The holder has already returned from BEGIN IMMEDIATE, while the waiter has
	// crossed its final pre-BEGIN handshake. The waiter must not acquire the
	// writer lock until the holder is allowed to finish and commit.
	blockedCtx, blockedCancel := context.WithTimeout(ctx, 250*time.Millisecond)
	err := waitForMigrationProcessFiles(blockedCtx, []string{migrationSignalPath(signals, migrationSignalWaiterLocked)})
	blockedCancel()
	if err == nil {
		t.Fatal("migration waiter acquired BEGIN IMMEDIATE while the holder still owned the writer lock")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("wait for blocked migration waiter: %v", err)
	}
	assertMigrationChildRunning(t, waiter, "waiter blocked on BEGIN IMMEDIATE")

	writeMigrationSignal(t, signals, migrationSignalHolderRelease)
	waitForMigrationChild(t, ctx, holder, migrationProcessRoleHolder)
	waitForMigrationChild(t, ctx, waiter, migrationProcessRoleWaiter)
	if _, err := os.Stat(migrationSignalPath(signals, migrationSignalWaiterLocked)); err != nil {
		t.Fatalf("migration waiter never acquired BEGIN IMMEDIATE after holder release: %v", err)
	}

	db := openProviderMigrationDB(t, path)
	if err := verifySQLiteV6Store(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	assertNoV6TemporaryTables(t, db)
	for _, check := range []struct {
		query string
		want  string
	}{
		{query: `SELECT provider FROM usage_events WHERE id=1`, want: providerCodex},
		{query: `SELECT provider FROM quota_trigger_runs WHERE id=1`, want: providerXAI},
		{query: `SELECT reason FROM invalid_auths WHERE provider='openai' AND auth_id='legacy-invalid'`, want: "active-wins"},
		{query: `SELECT reason FROM xai_account_states WHERE provider='openai' AND state_key='legacy-xai'`, want: "active-wins"},
	} {
		var got string
		if err := db.QueryRow(check.query).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != check.want {
			t.Fatalf("%s = %q, want %q", check.query, got, check.want)
		}
	}
}

func TestSQLiteV6MigrationProcessHelper(t *testing.T) {
	if os.Getenv(migrationProcessChildEnv) != "1" {
		t.Skip("migration subprocess helper")
	}
	path := os.Getenv(migrationProcessDBEnv)
	role := os.Getenv(migrationProcessRoleEnv)
	signals := os.Getenv(migrationProcessSignalsEnv)
	if path == "" || signals == "" || (role != migrationProcessRoleHolder && role != migrationProcessRoleWaiter) {
		t.Fatal("migration subprocess environment is incomplete")
	}
	db, err := openSQLiteDB(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Ping(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	sqliteMigrationV6LockHook = func(ctx context.Context, stage string) error {
		switch role {
		case migrationProcessRoleHolder:
			if stage != "after-begin" {
				return nil
			}
			if err := writeMigrationSignalFile(signals, migrationSignalHolderLocked); err != nil {
				return err
			}
			return waitForMigrationSignalFile(ctx, signals, migrationSignalHolderRelease)
		case migrationProcessRoleWaiter:
			switch stage {
			case "before-begin":
				if err := writeMigrationSignalFile(signals, migrationSignalWaiterReady); err != nil {
					return err
				}
				if err := waitForMigrationSignalFile(ctx, signals, migrationSignalWaiterStart); err != nil {
					return err
				}
				return writeMigrationSignalFile(signals, migrationSignalWaiterAttempt)
			case "after-begin":
				return writeMigrationSignalFile(signals, migrationSignalWaiterLocked)
			}
		}
		return nil
	}
	if err := initializeSQLiteStore(ctx, db, path); err != nil {
		t.Fatal(fmt.Errorf("initialize migrated store: %w", err))
	}
}

func startSQLiteV6MigrationChild(t *testing.T, ctx context.Context, path, signals, role string) *migrationChildProcess {
	t.Helper()
	child := &migrationChildProcess{
		cmd:  exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSQLiteV6MigrationProcessHelper$", "-test.count=1"),
		done: make(chan error, 1),
	}
	child.cmd.Env = append(os.Environ(),
		migrationProcessChildEnv+"=1",
		migrationProcessDBEnv+"="+path,
		migrationProcessRoleEnv+"="+role,
		migrationProcessSignalsEnv+"="+signals,
	)
	child.cmd.Stdout = &child.output
	child.cmd.Stderr = &child.output
	if err := child.cmd.Start(); err != nil {
		t.Fatalf("start migration %s: %v", role, err)
	}
	go func() { child.done <- child.cmd.Wait() }()
	return child
}

func waitForMigrationChild(t *testing.T, ctx context.Context, child *migrationChildProcess, role string) {
	t.Helper()
	select {
	case err := <-child.done:
		if err != nil {
			t.Fatalf("migration %s: %v\n%s", role, err, child.output.String())
		}
	case <-ctx.Done():
		t.Fatalf("migration %s did not finish: %v\n%s", role, ctx.Err(), child.output.String())
	}
}

func assertMigrationChildRunning(t *testing.T, child *migrationChildProcess, state string) {
	t.Helper()
	select {
	case err := <-child.done:
		t.Fatalf("migration child exited before %s: %v\n%s", state, err, child.output.String())
	default:
	}
}

func migrationSignalPath(dir, name string) string {
	return filepath.Join(dir, name)
}

func writeMigrationSignal(t *testing.T, dir, name string) {
	t.Helper()
	if err := writeMigrationSignalFile(dir, name); err != nil {
		t.Fatal(err)
	}
}

func writeMigrationSignalFile(dir, name string) error {
	return os.WriteFile(migrationSignalPath(dir, name), []byte(name), 0o600)
}

func waitForMigrationSignal(t *testing.T, ctx context.Context, dir, name string) {
	t.Helper()
	if err := waitForMigrationSignalFile(ctx, dir, name); err != nil {
		t.Fatalf("wait for migration signal %s: %v", name, err)
	}
}

func waitForMigrationSignalFile(ctx context.Context, dir, name string) error {
	return waitForMigrationProcessFiles(ctx, []string{migrationSignalPath(dir, name)})
}

func waitForMigrationProcessFiles(ctx context.Context, paths []string) error {
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		ready := true
		for _, path := range paths {
			if _, err := os.Stat(path); err != nil {
				if !os.IsNotExist(err) {
					return err
				}
				ready = false
			}
		}
		if ready {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}
