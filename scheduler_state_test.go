package main

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestSchedulerStateFastPathAvoidsOpeningDatabase(t *testing.T) {
	resetSchedulerStateForTest()
	t.Cleanup(resetSchedulerStateForTest)
	globalSchedulerState.setRestricted("codex", false)
	previousCfg := globalAccountProtection.config()
	cfg := defaultPluginConfig()
	cfg.AccountProtectionEnabled = false
	globalAccountProtection.configure(cfg)
	t.Cleanup(func() { globalAccountProtection.configure(previousCfg) })

	s := &store{}
	globalStore = s
	t.Cleanup(func() {
		s.close()
		globalStore = &store{}
	})
	resp, err := s.pickAuthOnce(context.Background(), schedulerPickRequest{
		Provider: "codex",
		Model:    "gpt-5.5",
		Candidates: []schedulerAuthCandidate{
			{ID: "alice", Provider: "codex", Priority: 1},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Handled {
		t.Fatalf("response=%+v, want native scheduler delegation", resp)
	}
	if s.db != nil {
		t.Fatal("healthy fast path opened SQLite")
	}
}

func TestSchedulerStateRefreshTracksActiveRestrictions(t *testing.T) {
	resetSchedulerStateForTest()
	t.Cleanup(resetSchedulerStateForTest)
	s := newTestStore(t)
	db, _, err := s.open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	if _, err := db.Exec(`INSERT INTO autoban_bans
		(auth_id, provider, window, reason, banned_at, reset_at, active)
		VALUES ('alice', 'codex', '5h', 'test', ?, ?, 1)`, now, now+3600); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO xai_account_states
		(state_key, provider, state, reason, observed_at, reset_at, active)
		VALUES ('grok', 'xai', 'rate_limited', 'test', ?, ?, 1)`, now, now+60); err != nil {
		t.Fatal(err)
	}
	if err := globalSchedulerState.refresh(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	if globalSchedulerState.needsDatabase("codex", false) {
		t.Fatal("active Codex restrictions did not produce a usable identity snapshot")
	}
	if globalSchedulerState.needsDatabase("xai", false) {
		t.Fatal("active xAI restrictions did not produce a usable identity snapshot")
	}
}

func TestSchedulerRestrictedSnapshotFiltersWithoutReopeningDatabase(t *testing.T) {
	resetSchedulerStateForTest()
	t.Cleanup(resetSchedulerStateForTest)
	s := newTestStore(t)
	db, _, err := s.open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	if _, err := db.Exec(`INSERT INTO autoban_bans
		(auth_id, auth_index, provider, window, reason, banned_at, reset_at, active)
		VALUES ('alice', 'alice', 'codex', '5h', 'test', ?, ?, 1)`, now, now+3600); err != nil {
		t.Fatal(err)
	}
	if err := globalSchedulerState.refresh(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	s.close()
	globalStore = s
	t.Cleanup(func() { globalStore = &store{} })

	resp, err := s.pickAuthOnce(context.Background(), schedulerPickRequest{
		Provider: "codex",
		Model:    "gpt-5.5",
		Candidates: []schedulerAuthCandidate{
			{ID: "alice", Provider: "codex", Priority: 1, Attributes: map[string]string{"auth_index": "alice"}},
			{ID: "bob", Provider: "codex", Priority: 1, Attributes: map[string]string{"auth_index": "bob"}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !resp.Handled || resp.AuthID != "bob" {
		t.Fatalf("response=%+v, want cached restriction to choose bob", resp)
	}
	if s.db != nil {
		t.Fatal("restricted identity snapshot reopened SQLite")
	}
}

func TestCodexSchedulerSnapshotSeparatesDuplicateIDsByAuthFile(t *testing.T) {
	now := time.Now().Unix()
	snapshot := newCodexSchedulerSnapshot(nil, []invalidAuthRow{{
		AuthID:        "a.json",
		AuthIndex:     "shared-workspace",
		AuthFile:      "a.json",
		Active:        true,
		InvalidatedAt: now,
	}}, now)
	candidates := []schedulerAuthCandidate{
		{ID: "shared-workspace", Provider: "codex", Attributes: map[string]string{"auth_index": "shared-workspace", "auth_file": "a.json"}},
		{ID: "shared-workspace", Provider: "codex", Attributes: map[string]string{"auth_index": "shared-workspace", "auth_file": "b.json"}},
	}
	if matched, _ := snapshot.matchIndexes(candidates[0]); !matched {
		t.Fatal("matching auth file was not restricted")
	}
	if matched, _ := snapshot.matchIndexes(candidates[1]); matched {
		t.Fatal("restriction leaked to a duplicate candidate ID with another auth file")
	}
}

func TestXAISchedulerSnapshotSeparatesDuplicateIDsByAuthFile(t *testing.T) {
	now := time.Now().Unix()
	candidates := []schedulerAuthCandidate{
		{ID: "shared-workspace", Provider: "xai", Attributes: map[string]string{"auth_index": "shared-workspace", "auth_file": "a.json"}},
		{ID: "shared-workspace", Provider: "xai", Attributes: map[string]string{"auth_index": "shared-workspace", "auth_file": "b.json"}},
	}
	for _, state := range []xaiAccountStateRow{
		{StateKey: "a.json", AuthID: "shared-workspace", AuthIndex: "shared-workspace", AuthFile: "a.json", Active: true},
		// Legacy rows may predate auth_file while retaining the canonical file in
		// state_key; they must remain strict rather than falling back to shared ID.
		{StateKey: "a.json", AuthID: "shared-workspace", AuthIndex: "shared-workspace", Active: true},
	} {
		snapshot := newXAISchedulerSnapshot([]xaiAccountStateRow{state}, now)
		if !snapshot.matches(candidates[0]) {
			t.Fatalf("matching xAI auth file was not restricted for state %+v", state)
		}
		if snapshot.matches(candidates[1]) {
			t.Fatalf("xAI restriction leaked across duplicate IDs for state %+v", state)
		}
	}
}

func TestConcurrentSnapshotPublishUsesWinningRefresh(t *testing.T) {
	t.Run("codex", func(t *testing.T) {
		var state schedulerStateCache
		generation := state.providerGeneration("codex")
		now := time.Now().Unix()
		snapshots := []*codexSchedulerSnapshot{
			newCodexSchedulerSnapshot(nil, nil, now),
			newCodexSchedulerSnapshot(nil, nil, now),
		}
		start := make(chan struct{})
		results := make(chan bool, len(snapshots))
		var wg sync.WaitGroup
		for _, snapshot := range snapshots {
			wg.Add(1)
			go func(snapshot *codexSchedulerSnapshot) {
				defer wg.Done()
				<-start
				_, ok := state.publishCodexOrCurrent(generation, snapshot, now)
				results <- ok
			}(snapshot)
		}
		close(start)
		wg.Wait()
		close(results)
		for ok := range results {
			if !ok {
				t.Fatal("benign concurrent Codex refresh surfaced as unavailable")
			}
		}
	})

	t.Run("xai", func(t *testing.T) {
		var state schedulerStateCache
		generation := state.providerGeneration("xai")
		now := time.Now().Unix()
		snapshots := []*xaiSchedulerSnapshot{
			newXAISchedulerSnapshot(nil, now),
			newXAISchedulerSnapshot(nil, now),
		}
		start := make(chan struct{})
		results := make(chan bool, len(snapshots))
		var wg sync.WaitGroup
		for _, snapshot := range snapshots {
			wg.Add(1)
			go func(snapshot *xaiSchedulerSnapshot) {
				defer wg.Done()
				<-start
				_, ok := state.publishXAIOrCurrent(generation, snapshot, now)
				results <- ok
			}(snapshot)
		}
		close(start)
		wg.Wait()
		close(results)
		for ok := range results {
			if !ok {
				t.Fatal("benign concurrent xAI refresh surfaced as unavailable")
			}
		}
	})
}

func TestSchedulerStateChangeRetriesOnce(t *testing.T) {
	calls := 0
	response, err := retrySchedulerStateChange(context.Background(), func() (schedulerPickResponse, error) {
		calls++
		if calls == 1 {
			return schedulerPickResponse{}, errSchedulerStateChanged
		}
		return schedulerPickResponse{AuthID: "alice", Handled: true}, nil
	})
	if err != nil || calls != 2 || !response.Handled || response.AuthID != "alice" {
		t.Fatalf("retry response=%+v err=%v calls=%d", response, err, calls)
	}

	calls = 0
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = retrySchedulerStateChange(ctx, func() (schedulerPickResponse, error) {
		calls++
		return schedulerPickResponse{}, errSchedulerStateChanged
	})
	if !errors.Is(err, errSchedulerStateChanged) || calls != 1 {
		t.Fatalf("canceled retry err=%v calls=%d, want one fail-closed attempt", err, calls)
	}
}

func TestSchedulerSuccessfulUsageInvalidatesRestrictionSnapshot(t *testing.T) {
	resetSchedulerStateForTest()
	t.Cleanup(resetSchedulerStateForTest)
	previousCfg := globalAccountProtection.config()
	cfg := defaultPluginConfig()
	cfg.AccountProtectionEnabled = false
	globalAccountProtection.configure(cfg)
	t.Cleanup(func() { globalAccountProtection.configure(previousCfg) })

	s := newTestStore(t)
	db, _, err := s.open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	if _, err := db.Exec(`INSERT INTO invalid_auths
		(auth_id, auth_index, provider, reason, invalidated_at, active, last_status_code)
		VALUES ('alice', 'alice', 'codex', 'test', ?, 1, 401)`, now); err != nil {
		t.Fatal(err)
	}
	if err := globalSchedulerState.refresh(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	globalStore = s
	t.Cleanup(func() { globalStore = &store{} })
	req := schedulerPickRequest{Provider: "codex", Candidates: []schedulerAuthCandidate{{
		ID: "alice", Provider: "codex", Attributes: map[string]string{"auth_index": "alice"},
	}}}
	if _, err := s.pickAuthOnce(context.Background(), req); err == nil {
		t.Fatal("active invalid auth was not rejected")
	}
	if err := clearRecoveredAuthStateIfNeeded(context.Background(), db, usageRecord{
		Provider: "codex", AuthID: "alice", AuthIndex: "alice", RequestedAt: time.Now(),
	}, 200); err != nil {
		t.Fatal(err)
	}
	if !globalSchedulerState.needsDatabase("codex", false) {
		t.Fatal("successful recovery did not invalidate the cached restriction")
	}
	resp, err := s.pickAuthOnce(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Handled {
		t.Fatalf("response=%+v, want recovered auth delegated to native scheduler", resp)
	}
}

func TestStoredCodexStatesSeparateDuplicateIDsByAuthFile(t *testing.T) {
	resetSchedulerStateForTest()
	t.Cleanup(resetSchedulerStateForTest)
	s := newTestStore(t)
	db, _, err := s.open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	for _, authFile := range []string{"a.json", "b.json"} {
		rec := usageRecord{
			Provider:    "codex",
			AuthID:      "shared-workspace",
			AuthIndex:   "shared-workspace",
			AuthFile:    authFile,
			Source:      "shared@example.com",
			RequestedAt: now,
			Failed:      true,
			Failure:     usageFailure{StatusCode: 401},
		}
		if err := recordInvalidAuthIfNeeded(context.Background(), db, rec, 401); err != nil {
			t.Fatal(err)
		}
		rec.Failure.StatusCode = 429
		if err := recordAutobanIfNeeded(context.Background(), db, rec, 429, nil, nil, nil, nil); err != nil {
			t.Fatal(err)
		}
	}
	for _, table := range []string{"invalid_auths", "autoban_bans"} {
		var count int
		if err := db.QueryRow(`SELECT COUNT(*) FROM ` + table + ` WHERE auth_id IN ('a.json','b.json')`).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 2 {
			t.Fatalf("%s retained %d distinct auth-file states, want 2", table, count)
		}
	}
}

func TestMissingAuthCleanupDoesNotKeepDuplicateIDThroughSharedIndex(t *testing.T) {
	resetSchedulerStateForTest()
	t.Cleanup(resetSchedulerStateForTest)
	s := newTestStore(t)
	db, _, err := s.open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	for _, authFile := range []string{"a.json", "b.json"} {
		if _, err := db.Exec(`INSERT INTO invalid_auths
			(auth_id, auth_index, provider, reason, invalidated_at, active, auth_file)
			VALUES (?, 'shared-workspace', 'codex', 'test', ?, 1, ?)`, authFile, now, authFile); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`INSERT INTO autoban_bans
			(auth_id, auth_index, provider, window, reason, banned_at, reset_at, active)
			VALUES (?, 'shared-workspace', 'codex', '5h', 'test', ?, ?, 1)`, authFile, now, now+3600); err != nil {
			t.Fatal(err)
		}
	}
	configured := []configuredAccount{{AuthFile: "b.json", AuthIndex: "shared-workspace", ChatGPTAccountID: "shared-workspace"}}
	aliases := configuredAliasSet(configured)
	strictAliases := configuredStrictAliasSet(configured)
	if err := clearMissingInvalidAuths(context.Background(), db, aliases, strictAliases); err != nil {
		t.Fatal(err)
	}
	if err := clearMissingAutobans(context.Background(), db, aliases, strictAliases); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"invalid_auths", "autoban_bans"} {
		var activeA, activeB int
		if err := db.QueryRow(`SELECT active FROM ` + table + ` WHERE auth_id='a.json'`).Scan(&activeA); err != nil {
			t.Fatal(err)
		}
		if err := db.QueryRow(`SELECT active FROM ` + table + ` WHERE auth_id='b.json'`).Scan(&activeB); err != nil {
			t.Fatal(err)
		}
		if activeA != 0 || activeB != 1 {
			t.Fatalf("%s active states = a:%d b:%d, want a:0 b:1", table, activeA, activeB)
		}
	}
}

func TestReplacementCleanupDoesNotClearDuplicateIDWithAnotherAuthFile(t *testing.T) {
	resetSchedulerStateForTest()
	t.Cleanup(resetSchedulerStateForTest)
	dir := t.TempDir()
	authDir := filepath.Join(dir, "auth")
	if err := os.MkdirAll(authDir, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CPA_TOKEN_USAGE_DIR", dir)
	t.Setenv("CPA_AUTH_DIR", authDir)
	now := time.Now()
	bPath := filepath.Join(authDir, "b.json")
	if err := os.WriteFile(bPath, []byte(`{"provider":"codex","email":"b@example.com"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(bPath, now.Add(time.Minute), now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	s := &store{}
	t.Cleanup(s.close)
	db, _, err := s.open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, authFile := range []string{"a.json", "b.json"} {
		if _, err := db.Exec(`INSERT INTO invalid_auths
			(auth_id, auth_index, provider, reason, invalidated_at, active, auth_file)
			VALUES (?, 'shared-workspace', 'codex', 'test', ?, 1, ?)`, authFile, now.Unix(), authFile); err != nil {
			t.Fatal(err)
		}
	}
	if err := clearReplacedInvalidAuths(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	var activeA, activeB int
	if err := db.QueryRow(`SELECT active FROM invalid_auths WHERE auth_id='a.json'`).Scan(&activeA); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT active FROM invalid_auths WHERE auth_id='b.json'`).Scan(&activeB); err != nil {
		t.Fatal(err)
	}
	if activeA != 1 || activeB != 0 {
		t.Fatalf("replacement states = a:%d b:%d, want a:1 b:0", activeA, activeB)
	}
}

func TestSchedulerSnapshotTTLAndResetExpiryServeStaleForRefresh(t *testing.T) {
	now := time.Now().Unix()
	ban := autobanRow{AuthID: "alice", AuthIndex: "alice", Active: true, ResetAt: now + 60}
	snapshot := newCodexSchedulerSnapshot([]autobanRow{ban}, nil, now)
	var state schedulerStateCache
	if !state.publishCodexIfGeneration(state.providerGeneration("codex"), snapshot) {
		t.Fatal("failed to publish test snapshot")
	}
	snapshot.expiresAt = time.Now().Add(-time.Second)
	if _, ok := state.codex(now); ok {
		t.Fatal("expired snapshot remained scheduler-usable")
	}
	if staleSnapshot, stale, ok := state.codexForPick(now); !ok || !stale || staleSnapshot != snapshot {
		t.Fatal("expired snapshot was not available to the stale-while-revalidate pick path")
	}
	snapshot.expiresAt = time.Now().Add(-schedulerSnapshotStaleGrace - time.Second)
	if staleSnapshot, stale, ok := state.codexForPick(now); ok || !stale || staleSnapshot != nil {
		t.Fatal("snapshot remained usable after the stale refresh grace period")
	}
	snapshot.expiresAt = time.Now().Add(time.Hour)
	if _, ok := state.codex(now + 61); ok {
		t.Fatal("snapshot remained usable after its earliest reset")
	}
	if staleSnapshot, stale, ok := state.codexForPick(now + 61); !ok || !stale || staleSnapshot != snapshot {
		t.Fatal("reset-expired snapshot was not retained for conservative stale filtering")
	}
	afterResetGrace := now + 60 + int64(schedulerSnapshotStaleGrace/time.Second) + 1
	if staleSnapshot, stale, ok := state.codexForPick(afterResetGrace); ok || !stale || staleSnapshot != nil {
		t.Fatal("reset-expired snapshot remained usable after the stale refresh grace period")
	}
	state.invalidateProvider("codex")
	if _, _, ok := state.codexForPick(now); ok {
		t.Fatal("real provider invalidation was incorrectly served as stale")
	}
}

func TestSchedulerExpiredSnapshotRefreshIsSingleWorkerAndDoesNotOpenSQLite(t *testing.T) {
	resetSchedulerStateForTest()
	t.Cleanup(resetSchedulerStateForTest)
	previousStore := globalStore
	previousRefresher := globalSchedulerStateRefresher
	previousCfg := globalAccountProtection.config()
	cfg := defaultPluginConfig()
	cfg.AccountProtectionEnabled = false
	globalAccountProtection.configure(cfg)
	t.Cleanup(func() {
		globalAccountProtection.configure(previousCfg)
		globalStore = previousStore
		globalSchedulerStateRefresher = previousRefresher
	})

	t.Setenv("CPA_TOKEN_USAGE_DIR", t.TempDir())
	s := &store{}
	globalStore = s
	t.Cleanup(s.close)

	publish := func() error {
		now := time.Now().Unix()
		codexGeneration := globalSchedulerState.providerGeneration("codex")
		if !globalSchedulerState.publishCodexIfGeneration(codexGeneration, newCodexSchedulerSnapshot([]autobanRow{{
			AuthID: "alice", AuthIndex: "alice", Active: true, ResetAt: now + 3600,
		}}, nil, now)) {
			return errors.New("publish Codex scheduler snapshot")
		}
		xaiGeneration := globalSchedulerState.providerGeneration("xai")
		if !globalSchedulerState.publishXAIIfGeneration(xaiGeneration, newXAISchedulerSnapshot(nil, now)) {
			return errors.New("publish xAI scheduler snapshot")
		}
		return nil
	}

	initialDone := make(chan struct{})
	refreshStarted := make(chan struct{})
	releaseRefresh := make(chan struct{})
	var calls atomic.Int32
	var active atomic.Int32
	var maxActive atomic.Int32
	m := &schedulerStateRefreshManager{retryInitial: time.Millisecond, retryMax: 5 * time.Millisecond}
	m.refresh = func(ctx context.Context, _ *store) error {
		call := calls.Add(1)
		current := active.Add(1)
		defer active.Add(-1)
		for {
			previous := maxActive.Load()
			if current <= previous || maxActive.CompareAndSwap(previous, current) {
				break
			}
		}
		if call == 1 {
			err := publish()
			close(initialDone)
			return err
		}
		if call == 2 {
			close(refreshStarted)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-releaseRefresh:
			}
		}
		return publish()
	}
	globalSchedulerStateRefresher = m
	m.configure(s)
	t.Cleanup(m.stop)
	select {
	case <-initialDone:
	case <-time.After(time.Second):
		t.Fatal("initial scheduler snapshot was not published")
	}

	globalSchedulerState.mu.Lock()
	globalSchedulerState.codexSnapshot.expiresAt = time.Now().Add(-time.Second)
	globalSchedulerState.mu.Unlock()

	req := schedulerPickRequest{
		Provider: "codex",
		Model:    "gpt-5.5",
		Candidates: []schedulerAuthCandidate{
			{ID: "alice", Provider: "codex", Priority: 1, Attributes: map[string]string{"auth_index": "alice"}},
			{ID: "bob", Provider: "codex", Priority: 1, Attributes: map[string]string{"auth_index": "bob"}},
		},
	}
	start := make(chan struct{})
	results := make(chan error, 64)
	var wg sync.WaitGroup
	for i := 0; i < cap(results); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			resp, err := s.pickAuthOnce(context.Background(), req)
			if err != nil {
				results <- err
				return
			}
			if !resp.Handled || resp.AuthID != "bob" {
				results <- errors.New("stale restriction was not applied")
			}
		}()
	}
	close(start)
	completed := make(chan struct{})
	go func() {
		wg.Wait()
		close(completed)
	}()
	select {
	case <-refreshStarted:
	case <-time.After(time.Second):
		t.Fatal("expired snapshot did not trigger background refresh")
	}
	select {
	case <-completed:
	case <-time.After(time.Second):
		t.Fatal("scheduler picks waited for the stale snapshot refresh")
	}
	close(results)
	for err := range results {
		if err != nil {
			t.Fatal(err)
		}
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("refresh calls while the refresh was blocked = %d, want one active refresh after initialization", got)
	}
	if got := maxActive.Load(); got != 1 {
		t.Fatalf("concurrent refresh workers = %d, want 1", got)
	}
	s.mu.Lock()
	db := s.db
	s.mu.Unlock()
	if db != nil {
		t.Fatal("stale scheduler picks opened SQLite")
	}
	close(releaseRefresh)
}

func TestManualReleaseAndExpiryInvalidateSchedulerSnapshot(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(context.Context, *sql.DB, int64) error
	}{
		{
			name: "manual release",
			mutate: func(ctx context.Context, db *sql.DB, now int64) error {
				_, err := markAutobanReleased(ctx, db, "alice", now)
				return err
			},
		},
		{
			name: "reset expiry",
			mutate: func(ctx context.Context, db *sql.DB, now int64) error {
				return expireAutobans(ctx, db, now+3601)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resetSchedulerStateForTest()
			t.Cleanup(resetSchedulerStateForTest)
			s := newTestStore(t)
			db, _, err := s.open(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			now := time.Now().Unix()
			if _, err := db.Exec(`INSERT INTO autoban_bans
				(auth_id, auth_index, provider, window, reason, banned_at, reset_at, active)
				VALUES ('alice', 'alice', 'codex', '5h', 'test', ?, ?, 1)`, now, now+3600); err != nil {
				t.Fatal(err)
			}
			if err := globalSchedulerState.refresh(context.Background(), db); err != nil {
				t.Fatal(err)
			}
			if globalSchedulerState.needsDatabase("codex", false) {
				t.Fatal("precondition: active snapshot was not usable")
			}
			if err := tc.mutate(context.Background(), db, now); err != nil {
				t.Fatal(err)
			}
			if !globalSchedulerState.needsDatabase("codex", false) {
				t.Fatal("state mutation did not invalidate the scheduler snapshot")
			}
		})
	}
}

func TestSchedulerStateInitializesProvidersIndependently(t *testing.T) {
	var state schedulerStateCache
	state.setRestricted("codex", false)
	if state.needsDatabase("codex", false) {
		t.Fatal("initialized Codex state unexpectedly needs the database")
	}
	if !state.needsDatabase("xai", false) {
		t.Fatal("setting Codex state incorrectly initialized xAI")
	}

	state.setRestricted("xai", false)
	if state.needsDatabase("xai", false) {
		t.Fatal("initialized xAI state unexpectedly needs the database")
	}
}

func TestSchedulerStateRefreshDoesNotOverwriteNewerRestriction(t *testing.T) {
	var state schedulerStateCache
	generation := state.beginRefresh()

	// Simulate a restriction being recorded after refresh read its generation
	// but before the database snapshot is published.
	state.setRestricted("codex", true)
	state.applyRefresh(generation, false, 0, false, 0)

	if !state.needsDatabase("codex", false) {
		t.Fatal("stale refresh overwrote a newer Codex restriction")
	}
	if state.needsDatabase("xai", false) {
		t.Fatal("uncontended xAI refresh result was not published")
	}
}

func TestSchedulerStateInvalidateRejectsInFlightRefresh(t *testing.T) {
	var state schedulerStateCache
	generation := state.beginRefresh()
	state.invalidate()
	state.applyRefresh(generation, false, 0, false, 0)

	if !state.needsDatabase("codex", false) || !state.needsDatabase("xai", false) {
		t.Fatal("in-flight refresh repopulated invalidated scheduler state")
	}
}

func TestSchedulerStateOlderRefreshCannotOverwriteNewerRefresh(t *testing.T) {
	var state schedulerStateCache
	older := state.beginRefresh()
	newer := state.beginRefresh()

	state.applyRefresh(newer, true, time.Now().Unix()+60, false, 0)
	state.applyRefresh(older, false, 0, true, time.Now().Unix()+60)

	if !state.needsDatabase("codex", false) {
		t.Fatal("older refresh cleared the newer Codex restriction")
	}
	if state.needsDatabase("xai", false) {
		t.Fatal("older refresh overwrote the newer xAI result")
	}
}

func TestSchedulerStateConditionalClearRejectsNewerRestriction(t *testing.T) {
	for _, provider := range []string{"codex", "xai"} {
		t.Run(provider, func(t *testing.T) {
			var state schedulerStateCache
			generation := state.providerGeneration(provider)
			state.setRestricted(provider, true)

			if state.clearRestrictedIfGeneration(provider, generation) {
				t.Fatal("stale empty query cleared a newer restriction")
			}
			if !state.needsDatabase(provider, false) {
				t.Fatal("newer restriction was lost")
			}

			generation = state.providerGeneration(provider)
			if !state.clearRestrictedIfGeneration(provider, generation) {
				t.Fatal("current empty query did not clear restriction")
			}
			if state.needsDatabase(provider, false) {
				t.Fatal("current empty query left restriction active")
			}
		})
	}
}

func TestSchedulerStateConditionalClearIsProviderSpecific(t *testing.T) {
	var state schedulerStateCache
	codexGeneration := state.providerGeneration("codex")
	state.setRestricted("xai", true)
	if !state.clearRestrictedIfGeneration("codex", codexGeneration) {
		t.Fatal("xAI update incorrectly invalidated Codex snapshot")
	}
	if state.needsDatabase("codex", false) {
		t.Fatal("Codex empty result was not cached")
	}
	if !state.needsDatabase("xai", false) {
		t.Fatal("xAI restriction was unexpectedly cleared")
	}
}

func TestSchedulerStatePendingWriteRejectsEmptySnapshotPublish(t *testing.T) {
	for _, provider := range []string{"codex", "xai"} {
		t.Run(provider, func(t *testing.T) {
			var state schedulerStateCache
			state.setRestricted(provider, false)
			state.beginRestrictionWrite(provider)
			generation := state.providerGeneration(provider)
			if state.clearRestrictedIfGeneration(provider, generation) {
				t.Fatal("pending restriction write accepted an empty snapshot")
			}
			state.setRestricted(provider, false)
			if !state.needsDatabase(provider, false) {
				t.Fatal("pending restriction write was cleared by a healthy event")
			}
			state.finishRestrictionWrite(provider)
			if !state.needsDatabase(provider, false) {
				t.Fatal("finished restriction write was trusted before a fresh database snapshot")
			}
			generation = state.providerGeneration(provider)
			if !state.clearRestrictedIfGeneration(provider, generation) {
				t.Fatal("post-write database snapshot was not published")
			}
			if state.needsDatabase(provider, false) {
				t.Fatal("post-write empty snapshot did not restore the healthy fast path")
			}
		})
	}
}

func TestSchedulerStateRefreshCannotPublishAcrossPendingWrite(t *testing.T) {
	var state schedulerStateCache
	generation := state.beginRefresh()
	state.beginRestrictionWrite("codex")
	state.applySnapshotRefresh(
		generation,
		newCodexSchedulerSnapshot(nil, nil, time.Now().Unix()),
		newXAISchedulerSnapshot(nil, time.Now().Unix()),
	)
	if !state.needsDatabase("codex", false) {
		t.Fatal("refresh published Codex state across a pending write")
	}
	if state.needsDatabase("xai", false) {
		t.Fatal("uncontended xAI refresh was not published")
	}
	state.finishRestrictionWrite("codex")
}

func TestSchedulerStateSuccessfulRefreshRejectsSameGenerationReader(t *testing.T) {
	var state schedulerStateCache
	generation := state.beginRefresh()
	readerGeneration := state.providerGeneration(providerCodex)
	now := time.Now().Unix()
	fresh := newCodexSchedulerSnapshot([]autobanRow{{AuthID: "fresh", Provider: providerCodex, Active: true}}, nil, now)
	stale := newCodexSchedulerSnapshot(nil, nil, now)
	state.applySnapshotRefresh(generation, fresh, newXAISchedulerSnapshot(nil, now))

	if state.publishCodexIfGeneration(readerGeneration, stale) {
		t.Fatal("same-generation reader overwrote a completed background refresh")
	}
	current, _, ok := state.codexForPick(now)
	if !ok || current == nil || len(current.restrictions) != 1 || current.restrictions[0].AuthID != "fresh" {
		t.Fatalf("completed refresh snapshot was not preserved: %+v, ok=%v", current, ok)
	}
}

func TestSchedulerStateSuccessfulXAIRefreshRejectsSameGenerationReader(t *testing.T) {
	var state schedulerStateCache
	generation := state.beginRefresh()
	readerGeneration := state.providerGeneration(providerXAI)
	now := time.Now().Unix()
	fresh := newXAISchedulerSnapshot([]xaiAccountStateRow{{StateKey: "fresh", Provider: providerXAI, Active: true}}, now)
	stale := newXAISchedulerSnapshot(nil, now)
	state.applySnapshotRefresh(generation, newCodexSchedulerSnapshot(nil, nil, now), fresh)

	if state.publishXAIIfGeneration(readerGeneration, stale) {
		t.Fatal("same-generation xAI reader overwrote a completed background refresh")
	}
	current, _, ok := state.xaiForPick(now)
	if !ok || current == nil || len(current.states) != 1 || current.states[0].StateKey != "fresh" {
		t.Fatalf("completed xAI refresh snapshot was not preserved: %+v, ok=%v", current, ok)
	}
}

func TestQueryActiveAutobansDoesNotRewriteUsageHistory(t *testing.T) {
	s := newTestStore(t)
	db, _, err := s.open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO usage_events
		(requested_at, provider, primary_reset_at, total_tokens)
		VALUES (?, 'codex', ?, 1)`, time.Now().Unix(), int64(1_800_000_000_000)); err != nil {
		t.Fatal(err)
	}
	if _, err := queryActiveAutobans(context.Background(), db, providerCodex, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	var resetAt int64
	if err := db.QueryRow(`SELECT primary_reset_at FROM usage_events LIMIT 1`).Scan(&resetAt); err != nil {
		t.Fatal(err)
	}
	if resetAt != 1_800_000_000_000 {
		t.Fatalf("queryActiveAutobans rewrote usage history: %d", resetAt)
	}
}
