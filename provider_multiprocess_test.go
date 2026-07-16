package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	migrationProcessChildEnv   = "CPA_TEST_SQLITE_V6_MIGRATION_CHILD"
	migrationProcessDBEnv      = "CPA_TEST_SQLITE_V6_MIGRATION_DB"
	migrationProcessGateEnv    = "CPA_TEST_SQLITE_V6_MIGRATION_GATE"
	migrationProcessEnteredEnv = "CPA_TEST_SQLITE_V6_MIGRATION_ENTERED"
)

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

	gate := filepath.Join(dir, "release-migration")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	type childProcess struct {
		cmd    *exec.Cmd
		output bytes.Buffer
	}
	children := make([]childProcess, 2)
	enteredFiles := make([]string, len(children))
	for i := range children {
		child := &children[i]
		enteredFiles[i] = filepath.Join(dir, fmt.Sprintf("migration-entered-%d", i))
		child.cmd = exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSQLiteV6MigrationProcessHelper$", "-test.count=1")
		child.cmd.Env = append(os.Environ(),
			migrationProcessChildEnv+"=1",
			migrationProcessDBEnv+"="+path,
			migrationProcessGateEnv+"="+gate,
			migrationProcessEnteredEnv+"="+enteredFiles[i],
		)
		child.cmd.Stdout = &child.output
		child.cmd.Stderr = &child.output
		if err := child.cmd.Start(); err != nil {
			t.Fatalf("start migration child %d: %v", i, err)
		}
	}
	barrierCtx, barrierCancel := context.WithTimeout(ctx, 5*time.Second)
	defer barrierCancel()
	if err := waitForMigrationProcessFiles(barrierCtx, enteredFiles); err != nil {
		t.Fatalf("migration children did not reach the pre-migration barrier: %v", err)
	}
	if err := os.WriteFile(gate, []byte("go"), 0o600); err != nil {
		t.Fatal(err)
	}
	for i := range children {
		if err := children[i].cmd.Wait(); err != nil {
			t.Fatalf("migration child %d: %v\n%s", i, err, children[i].output.String())
		}
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
	gate := os.Getenv(migrationProcessGateEnv)
	entered := os.Getenv(migrationProcessEnteredEnv)
	if path == "" || gate == "" || entered == "" {
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
	// Publish entered only after this process owns a live SQLite handle and has
	// reached the final barrier immediately before initializeSQLiteStore.
	if err := os.WriteFile(entered, []byte("entered"), 0o600); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(gate); err == nil {
			break
		} else if !os.IsNotExist(err) {
			t.Fatal(err)
		}
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for migration subprocess gate")
		}
		time.Sleep(5 * time.Millisecond)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := initializeSQLiteStore(ctx, db, path); err != nil {
		t.Fatal(fmt.Errorf("initialize migrated store: %w", err))
	}
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
