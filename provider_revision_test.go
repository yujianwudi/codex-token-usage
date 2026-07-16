package main

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

const (
	schedulerRevisionProcessChildEnv = "CPA_TEST_SCHEDULER_REVISION_CHILD"
	schedulerRevisionProcessDirEnv   = "CPA_TEST_SCHEDULER_REVISION_DIR"
)

type schedulerRevisionProcessCommand struct {
	Action   string `json:"action"`
	Provider string `json:"provider,omitempty"`
}

type schedulerRevisionProcessResult struct {
	Ready           bool                  `json:"ready,omitempty"`
	Response        schedulerPickResponse `json:"response"`
	Error           string                `json:"error,omitempty"`
	ErrorCode       string                `json:"error_code,omitempty"`
	CodexGeneration uint64                `json:"codex_generation"`
	XAIGeneration   uint64                `json:"xai_generation"`
}

type schedulerRevisionChild struct {
	cmd     *exec.Cmd
	stdin   io.WriteCloser
	scanner *bufio.Scanner
	stderr  bytes.Buffer
	waited  bool
}

func TestProviderRevisionInvalidatesBeforeObservation(t *testing.T) {
	var state persistentSchedulerRevisionState
	state.reset(persistentSchedulerRevisions{Codex: 1, XAI: 1, Privacy: 1})

	invalidationStarted := make(chan struct{})
	releaseInvalidation := make(chan struct{})
	firstDone := make(chan struct{})
	unexpected := make(chan string, 1)
	go func() {
		state.reconcileProviders(persistentSchedulerRevisions{Codex: 2, XAI: 1, Privacy: 1}, func(provider string) {
			if provider != providerCodex {
				unexpected <- provider
			}
			close(invalidationStarted)
			<-releaseInvalidation
		})
		close(firstDone)
	}()
	<-invalidationStarted

	secondDone := make(chan struct{})
	secondInvalidations := make(chan string, 1)
	go func() {
		state.reconcileProviders(persistentSchedulerRevisions{Codex: 2, XAI: 1, Privacy: 1}, func(provider string) {
			secondInvalidations <- provider
		})
		close(secondDone)
	}()

	select {
	case <-secondDone:
		close(releaseInvalidation)
		<-firstDone
		t.Fatal("concurrent picker observed the revision before invalidation completed")
	case <-time.After(100 * time.Millisecond):
	}
	close(releaseInvalidation)
	<-firstDone
	<-secondDone

	select {
	case provider := <-unexpected:
		t.Fatalf("first invalidation targeted %q, want %q", provider, providerCodex)
	default:
	}
	select {
	case provider := <-secondInvalidations:
		t.Fatalf("revision was invalidated twice; second provider=%q", provider)
	default:
	}
}

func TestInitialPrivacySnapshotRevisionRaceRetriesUntilStable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "usage.db")
	db, err := openSQLiteDB(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := initializeSQLiteStore(context.Background(), db, path); err != nil {
		t.Fatal(err)
	}
	writer, err := openSQLiteDB(path)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()

	testStore := &store{}
	firstRefreshComplete := make(chan struct{})
	releaseFirstRefresh := make(chan struct{})
	type initializationResult struct {
		revisions persistentSchedulerRevisions
		refreshes int
		err       error
	}
	result := make(chan initializationResult, 1)
	go func() {
		refreshes := 0
		revisions, err := stabilizePrivacySnapshot(
			context.Background(),
			func(ctx context.Context) (persistentSchedulerRevisions, error) {
				return queryPersistentSchedulerRevisions(ctx, db)
			},
			func(ctx context.Context) error {
				if err := testStore.refreshAPIKeyPrivacyQuarantine(ctx, db, path); err != nil {
					return err
				}
				refreshes++
				if refreshes == 1 {
					close(firstRefreshComplete)
					<-releaseFirstRefresh
				}
				return nil
			},
		)
		result <- initializationResult{revisions: revisions, refreshes: refreshes, err: err}
	}()

	select {
	case <-firstRefreshComplete:
	case <-time.After(5 * time.Second):
		t.Fatal("initial privacy snapshot refresh did not reach the test barrier")
	}
	_, writeErr := writer.Exec(`INSERT INTO store_state(key,value) VALUES('api_key_privacy_quarantine_codex','malformed-marker')`)
	afterWrite, readErr := queryPersistentSchedulerRevisions(context.Background(), writer)
	close(releaseFirstRefresh)
	if writeErr != nil {
		t.Fatal(writeErr)
	}
	if readErr != nil {
		t.Fatal(readErr)
	}

	var initialized initializationResult
	select {
	case initialized = <-result:
	case <-time.After(5 * time.Second):
		t.Fatal("initial privacy snapshot stabilization did not complete")
	}
	if initialized.err != nil {
		t.Fatal(initialized.err)
	}
	if initialized.refreshes != 2 {
		t.Fatalf("privacy snapshot refreshes = %d, want 2", initialized.refreshes)
	}
	if initialized.revisions.Privacy != afterWrite.Privacy {
		t.Fatalf("observed privacy revision = %d, want %d", initialized.revisions.Privacy, afterWrite.Privacy)
	}
	if reason, quarantined := testStore.apiKeyPrivacyQuarantineReason(providerCodex); !quarantined || reason == "" {
		t.Fatalf("racing quarantine marker was not present in the stable snapshot: quarantined=%v reason=%q", quarantined, reason)
	}
}

func TestRuntimePrivacySnapshotRevisionRaceRetriesUntilStable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "usage.db")
	db, err := openSQLiteDB(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := initializeSQLiteStore(context.Background(), db, path); err != nil {
		t.Fatal(err)
	}
	writer, err := openSQLiteDB(path)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()

	testStore := &store{}
	testStore.providerRevisions.reset(mustSchedulerRevisions(t, db))
	if _, err := writer.Exec(`INSERT INTO store_state(key,value) VALUES('api_key_privacy_quarantine_codex','runtime-codex-marker')`); err != nil {
		t.Fatal(err)
	}
	changed := mustSchedulerRevisions(t, writer)
	if !testStore.providerRevisions.reconcileProviders(changed, nil) {
		t.Fatal("runtime privacy revision change was not detected")
	}

	firstRefreshComplete := make(chan struct{})
	releaseFirstRefresh := make(chan struct{})
	type refreshResult struct {
		revisions persistentSchedulerRevisions
		refreshes int
		err       error
	}
	result := make(chan refreshResult, 1)
	go func() {
		refreshes := 0
		revisions, err := testStore.providerRevisions.refreshStablePrivacySnapshot(
			context.Background(),
			func(ctx context.Context) (persistentSchedulerRevisions, error) {
				return queryPersistentSchedulerRevisions(ctx, db)
			},
			func(ctx context.Context) error {
				if err := testStore.refreshAPIKeyPrivacyQuarantine(ctx, db, path); err != nil {
					return err
				}
				refreshes++
				if refreshes == 1 {
					close(firstRefreshComplete)
					<-releaseFirstRefresh
				}
				return nil
			},
		)
		result <- refreshResult{revisions: revisions, refreshes: refreshes, err: err}
	}()

	select {
	case <-firstRefreshComplete:
	case <-time.After(5 * time.Second):
		t.Fatal("runtime privacy refresh did not reach the test barrier")
	}
	_, writeErr := writer.Exec(`INSERT INTO store_state(key,value) VALUES('api_key_privacy_quarantine_xai','runtime-xai-marker')`)
	afterWrite, readErr := queryPersistentSchedulerRevisions(context.Background(), writer)
	close(releaseFirstRefresh)
	if writeErr != nil {
		t.Fatal(writeErr)
	}
	if readErr != nil {
		t.Fatal(readErr)
	}

	var refreshed refreshResult
	select {
	case refreshed = <-result:
	case <-time.After(5 * time.Second):
		t.Fatal("runtime privacy snapshot stabilization did not complete")
	}
	if refreshed.err != nil {
		t.Fatal(refreshed.err)
	}
	if refreshed.refreshes != 2 {
		t.Fatalf("runtime privacy snapshot refreshes = %d, want 2", refreshed.refreshes)
	}
	if refreshed.revisions.Privacy != afterWrite.Privacy || testStore.providerRevisions.privacyChanged(afterWrite.Privacy) {
		t.Fatalf("runtime observed privacy revision = %d, want stable %d", refreshed.revisions.Privacy, afterWrite.Privacy)
	}
	for _, provider := range []string{providerCodex, providerXAI} {
		if reason, quarantined := testStore.apiKeyPrivacyQuarantineReason(provider); !quarantined || reason == "" {
			t.Fatalf("racing %s quarantine marker missing from stable runtime snapshot: quarantined=%v reason=%q", provider, quarantined, reason)
		}
	}
}

func TestPersistentSchedulerRevisionsAcrossProcesses(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("CPA_TOKEN_USAGE_DIR", dir)
	t.Setenv("CPA_AUTH_DIR", filepath.Join(dir, "auth"))
	path := filepath.Join(dir, "usage.db")
	db, err := openSQLiteDB(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := initializeSQLiteStore(context.Background(), db, path); err != nil {
		t.Fatal(err)
	}

	assertSchedulerRevisionRollback(t, db, schedulerRevisionCodexKey, `
INSERT INTO invalid_auths(auth_id,provider,reason,invalidated_at,active)
VALUES('rollback-codex','codex','rollback',1,1)`)
	assertSchedulerRevisionRollback(t, db, schedulerRevisionXAIKey, `
INSERT INTO xai_account_states(state_key,auth_id,provider,state,reason,observed_at,active)
VALUES('rollback-xai','rollback-xai','xai','rate_limited','rollback',1,1)`)
	assertSchedulerRevisionRollback(t, db, schedulerRevisionPrivacyKey, `
INSERT INTO store_state(key,value) VALUES('api_key_privacy_quarantine_rollback','malformed')`)

	beforeUnknown := mustSchedulerRevisions(t, db)
	if _, err := db.Exec(`
INSERT INTO invalid_auths(auth_id,provider,reason,invalidated_at,active)
VALUES('unknown-codex','custom-ai','unknown',1,1);
INSERT INTO xai_account_states(state_key,auth_id,provider,state,reason,observed_at,active)
VALUES('unknown-xai','unknown-xai','custom-ai','rate_limited','unknown',1,1);`); err != nil {
		t.Fatal(err)
	}
	afterUnknown := mustSchedulerRevisions(t, db)
	if afterUnknown != beforeUnknown {
		t.Fatalf("unknown providers changed scheduler revisions: before=%+v after=%+v", beforeUnknown, afterUnknown)
	}
	if _, err := db.Exec(`DELETE FROM invalid_auths WHERE provider='custom-ai'; DELETE FROM xai_account_states WHERE provider='custom-ai'`); err != nil {
		t.Fatal(err)
	}
	if got := mustSchedulerRevisions(t, db); got != beforeUnknown {
		t.Fatalf("unknown-provider cleanup changed scheduler revisions: before=%+v after=%+v", beforeUnknown, got)
	}

	child := startSchedulerRevisionChild(t, dir)
	defer child.abort()
	ready := child.read(t)
	if !ready.Ready {
		t.Fatalf("scheduler revision child did not become ready: %+v", ready)
	}
	baselineCodexGeneration := ready.CodexGeneration
	baselineXAIGeneration := ready.XAIGeneration

	beforeCodex := mustSchedulerRevisions(t, db)
	if _, err := db.Exec(`
INSERT INTO invalid_auths(auth_id,provider,reason,invalidated_at,active,last_status_code)
VALUES('codex-a','codex','external invalid auth',?,1,401)`, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	afterCodexInsert := mustSchedulerRevisions(t, db)
	assertSchedulerRevisionDelta(t, beforeCodex, afterCodexInsert, 1, 0, 0)
	codexBlocked := child.pick(t, providerCodex)
	if codexBlocked.Error != "" || !codexBlocked.Response.Handled || codexBlocked.Response.AuthID != "codex-b" {
		t.Fatalf("external Codex restriction was not reconciled on next pick: %+v", codexBlocked)
	}
	if codexBlocked.CodexGeneration <= baselineCodexGeneration || codexBlocked.XAIGeneration != baselineXAIGeneration {
		t.Fatalf("Codex revision invalidated the wrong provider: ready=%+v pick=%+v", ready, codexBlocked)
	}

	if _, err := db.Exec(`DELETE FROM invalid_auths WHERE provider='codex' AND auth_id='codex-a'`); err != nil {
		t.Fatal(err)
	}
	afterCodexDelete := mustSchedulerRevisions(t, db)
	assertSchedulerRevisionDelta(t, afterCodexInsert, afterCodexDelete, 1, 0, 0)
	codexRestored := child.pick(t, providerCodex)
	if codexRestored.Error != "" || codexRestored.Response.Handled {
		t.Fatalf("cleared Codex restriction was not reconciled on next pick: %+v", codexRestored)
	}
	codexGenerationAfterRestore := codexRestored.CodexGeneration
	if codexRestored.XAIGeneration != baselineXAIGeneration {
		t.Fatalf("Codex clear invalidated xAI generation: ready=%+v pick=%+v", ready, codexRestored)
	}

	beforeXAI := mustSchedulerRevisions(t, db)
	if _, err := db.Exec(`
INSERT INTO xai_account_states(state_key,auth_id,provider,state,reason,observed_at,active,last_status_code)
VALUES('xai-a','xai-a','xai','rate_limited','external rate limit',?,1,429)`, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	afterXAIInsert := mustSchedulerRevisions(t, db)
	assertSchedulerRevisionDelta(t, beforeXAI, afterXAIInsert, 0, 1, 0)
	xaiBlocked := child.pick(t, providerXAI)
	if xaiBlocked.Error != "" || !xaiBlocked.Response.Handled || xaiBlocked.Response.AuthID != "xai-b" {
		t.Fatalf("external xAI restriction was not reconciled on next pick: %+v", xaiBlocked)
	}
	if xaiBlocked.CodexGeneration != codexGenerationAfterRestore || xaiBlocked.XAIGeneration <= baselineXAIGeneration {
		t.Fatalf("xAI revision invalidated the wrong provider: previous=%+v pick=%+v", codexRestored, xaiBlocked)
	}

	if _, err := db.Exec(`DELETE FROM xai_account_states WHERE provider='xai' AND state_key='xai-a'`); err != nil {
		t.Fatal(err)
	}
	afterXAIDelete := mustSchedulerRevisions(t, db)
	assertSchedulerRevisionDelta(t, afterXAIInsert, afterXAIDelete, 0, 1, 0)
	xaiRestored := child.pick(t, providerXAI)
	if xaiRestored.Error != "" || xaiRestored.Response.Handled {
		t.Fatalf("cleared xAI restriction was not reconciled on next pick: %+v", xaiRestored)
	}
	if xaiRestored.CodexGeneration != codexGenerationAfterRestore {
		t.Fatalf("xAI clear invalidated Codex generation: previous=%+v pick=%+v", codexRestored, xaiRestored)
	}

	beforePrivacy := mustSchedulerRevisions(t, db)
	if _, err := db.Exec(`INSERT INTO store_state(key,value) VALUES('api_key_privacy_quarantine_codex','malformed-marker')`); err != nil {
		t.Fatal(err)
	}
	afterPrivacyInsert := mustSchedulerRevisions(t, db)
	assertSchedulerRevisionDelta(t, beforePrivacy, afterPrivacyInsert, 0, 0, 1)
	privacyBlocked := child.pick(t, providerCodex)
	if privacyBlocked.ErrorCode != "privacy_quarantine" {
		t.Fatalf("external privacy quarantine was not reconciled on next pick: %+v", privacyBlocked)
	}
	if privacyBlocked.CodexGeneration != xaiRestored.CodexGeneration || privacyBlocked.XAIGeneration != xaiRestored.XAIGeneration {
		t.Fatalf("privacy revision invalidated a provider snapshot: previous=%+v pick=%+v", xaiRestored, privacyBlocked)
	}

	if _, err := db.Exec(`DELETE FROM store_state WHERE key='api_key_privacy_quarantine_codex'`); err != nil {
		t.Fatal(err)
	}
	afterPrivacyDelete := mustSchedulerRevisions(t, db)
	assertSchedulerRevisionDelta(t, afterPrivacyInsert, afterPrivacyDelete, 0, 0, 1)
	privacyRestored := child.pick(t, providerCodex)
	if privacyRestored.Error != "" || privacyRestored.Response.Handled {
		t.Fatalf("cleared privacy quarantine was not reconciled on next pick: %+v", privacyRestored)
	}

	child.send(t, schedulerRevisionProcessCommand{Action: "quit"})
	_ = child.read(t)
	if err := child.wait(); err != nil {
		t.Fatalf("scheduler revision child exit: %v\n%s", err, child.stderr.String())
	}
}

func TestPersistentSchedulerRevisionProcessHelper(t *testing.T) {
	if os.Getenv(schedulerRevisionProcessChildEnv) != "1" {
		t.Skip("scheduler revision subprocess helper")
	}
	dir := os.Getenv(schedulerRevisionProcessDirEnv)
	if dir == "" {
		t.Fatal("scheduler revision subprocess directory is missing")
	}
	if err := os.Setenv("CPA_TOKEN_USAGE_DIR", dir); err != nil {
		t.Fatal(err)
	}
	if err := os.Setenv("CPA_AUTH_DIR", filepath.Join(dir, "auth")); err != nil {
		t.Fatal(err)
	}
	globalStore = &store{}
	resetSchedulerStateForTest()
	globalSchedulerAffinity.reset()
	db, _, err := globalStore.open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := globalSchedulerState.refresh(context.Background(), db); err != nil {
		t.Fatal(err)
	}

	encoder := json.NewEncoder(os.Stdout)
	write := func(result schedulerRevisionProcessResult) {
		result.CodexGeneration = globalSchedulerState.providerGeneration(providerCodex)
		result.XAIGeneration = globalSchedulerState.providerGeneration(providerXAI)
		if err := encoder.Encode(result); err != nil {
			t.Fatal(err)
		}
	}
	write(schedulerRevisionProcessResult{Ready: true})
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		var command schedulerRevisionProcessCommand
		if err := json.Unmarshal(scanner.Bytes(), &command); err != nil {
			t.Fatal(err)
		}
		switch command.Action {
		case "pick":
			provider := canonicalProvider(command.Provider)
			request := schedulerPickRequest{
				Provider:  provider,
				Providers: []string{provider},
				Candidates: []schedulerAuthCandidate{
					{ID: provider + "-a", Provider: provider, Status: "active"},
					{ID: provider + "-b", Provider: provider, Status: "active"},
				},
			}
			response, err := globalStore.pickAuth(context.Background(), request)
			result := schedulerRevisionProcessResult{Response: response}
			if err != nil {
				result.Error = err.Error()
				var reject *schedulerRejectError
				if errors.As(err, &reject) {
					result.ErrorCode = reject.Code
				}
			}
			write(result)
		case "quit":
			write(schedulerRevisionProcessResult{})
			globalStore.close()
			return
		default:
			write(schedulerRevisionProcessResult{Error: "unknown command: " + command.Action})
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
}

func startSchedulerRevisionChild(t *testing.T, dir string) *schedulerRevisionChild {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	child := &schedulerRevisionChild{}
	child.cmd = exec.CommandContext(ctx, os.Args[0], "-test.run=^TestPersistentSchedulerRevisionProcessHelper$", "-test.count=1")
	child.cmd.Env = append(os.Environ(),
		schedulerRevisionProcessChildEnv+"=1",
		schedulerRevisionProcessDirEnv+"="+dir,
	)
	stdout, err := child.cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	child.stdin, err = child.cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	child.cmd.Stderr = &child.stderr
	child.scanner = bufio.NewScanner(stdout)
	if err := child.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	return child
}

func (c *schedulerRevisionChild) send(t *testing.T, command schedulerRevisionProcessCommand) {
	t.Helper()
	if err := json.NewEncoder(c.stdin).Encode(command); err != nil {
		t.Fatalf("send scheduler revision child command: %v", err)
	}
}

func (c *schedulerRevisionChild) read(t *testing.T) schedulerRevisionProcessResult {
	t.Helper()
	if !c.scanner.Scan() {
		err := c.scanner.Err()
		if err == nil {
			err = errors.New("unexpected EOF")
		}
		t.Fatalf("read scheduler revision child: %v\n%s", err, c.stderr.String())
	}
	var result schedulerRevisionProcessResult
	if err := json.Unmarshal(c.scanner.Bytes(), &result); err != nil {
		t.Fatalf("decode scheduler revision child result %q: %v", c.scanner.Text(), err)
	}
	return result
}

func (c *schedulerRevisionChild) pick(t *testing.T, provider string) schedulerRevisionProcessResult {
	t.Helper()
	c.send(t, schedulerRevisionProcessCommand{Action: "pick", Provider: provider})
	return c.read(t)
}

func (c *schedulerRevisionChild) wait() error {
	if c == nil || c.waited {
		return nil
	}
	c.waited = true
	_ = c.stdin.Close()
	return c.cmd.Wait()
}

func (c *schedulerRevisionChild) abort() {
	if c == nil || c.waited || c.cmd == nil || c.cmd.Process == nil {
		return
	}
	_ = c.cmd.Process.Kill()
	_ = c.wait()
}

func mustSchedulerRevisions(t *testing.T, db *sql.DB) persistentSchedulerRevisions {
	t.Helper()
	revisions, err := queryPersistentSchedulerRevisions(context.Background(), db)
	if err != nil {
		t.Fatal(err)
	}
	return revisions
}

func assertSchedulerRevisionRollback(t *testing.T, db *sql.DB, key, statement string) {
	t.Helper()
	before := mustSchedulerRevisions(t, db)
	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(statement); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	var inside int64
	if err := tx.QueryRow(`SELECT CAST(value AS INTEGER) FROM store_state WHERE key=?`, key).Scan(&inside); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	wantInside := before.Codex
	switch key {
	case schedulerRevisionXAIKey:
		wantInside = before.XAI
	case schedulerRevisionPrivacyKey:
		wantInside = before.Privacy
	}
	if inside != wantInside+1 {
		_ = tx.Rollback()
		t.Fatalf("revision inside transaction = %d, want %d", inside, wantInside+1)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	after := mustSchedulerRevisions(t, db)
	if after != before {
		t.Fatalf("rolled-back state write changed scheduler revisions: before=%+v after=%+v inside=%d", before, after, inside)
	}
}

func assertSchedulerRevisionDelta(t *testing.T, before, after persistentSchedulerRevisions, codex, xai, privacy int64) {
	t.Helper()
	want := persistentSchedulerRevisions{
		Codex:   before.Codex + codex,
		XAI:     before.XAI + xai,
		Privacy: before.Privacy + privacy,
	}
	if after != want {
		t.Fatalf("scheduler revision delta = %+v -> %+v, want %+v", before, after, want)
	}
}
