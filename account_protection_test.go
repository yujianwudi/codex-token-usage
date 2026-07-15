package main

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestAccountProtectionPlansRefreshOffSchedulerHotPath(t *testing.T) {
	dir := t.TempDir()
	authDir := filepath.Join(dir, "auth")
	if err := os.MkdirAll(authDir, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CPA_TOKEN_USAGE_DIR", dir)
	t.Setenv("CPA_AUTH_DIR", authDir)
	path := filepath.Join(authDir, "account.json")
	if err := os.WriteFile(path, []byte(`{"provider":"codex","email":"a@example.com","plan_type":"free"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var manager accountProtectionManager
	t.Cleanup(manager.stop)
	cfg := defaultPluginConfig()
	cfg.AccountProtectionEnabled = true
	manager.configure(cfg)
	if got := manager.configuredPlans()["a@example.com"]; got != "free" {
		t.Fatalf("initial plan = %q, want free", got)
	}
	if err := os.WriteFile(path, []byte(`{"provider":"codex","email":"a@example.com","plan_type":"team","name":"changed"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	manager.mu.Lock()
	manager.plansLoadedAt = time.Now().Add(-accountProtectionPlanRefreshInterval - time.Second)
	manager.mu.Unlock()

	// The expiring read returns the immutable old snapshot immediately and only
	// schedules filesystem work in the background.
	if got := manager.configuredPlans()["a@example.com"]; got != "free" {
		t.Fatalf("expiring read blocked on refresh and returned %q, want old free snapshot", got)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if got := manager.configuredPlans()["a@example.com"]; got == "team" {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("background plan refresh did not publish the changed auth-file plan")
}

func TestAccountProtectionStopCancelsAndJoinsPlanRefresh(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("CPA_TOKEN_USAGE_DIR", dir)
	t.Setenv("CPA_AUTH_DIR", filepath.Join(dir, "auth"))
	var manager accountProtectionManager
	t.Cleanup(manager.stop)
	cfg := defaultPluginConfig()
	cfg.AccountProtectionEnabled = true
	manager.configure(cfg)

	started := make(chan struct{})
	canceled := make(chan struct{})
	manager.mu.Lock()
	manager.plans = map[string]string{"stable": "free"}
	manager.plansLoadedAt = time.Now().Add(-accountProtectionPlanRefreshInterval - time.Second)
	manager.plansLoader = func(ctx context.Context) map[string]string {
		close(started)
		<-ctx.Done()
		close(canceled)
		return map[string]string{"stale": "team"}
	}
	manager.mu.Unlock()

	if got := manager.configuredPlans()["stable"]; got != "free" {
		t.Fatalf("expiring read = %q, want immutable free snapshot", got)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("background plan refresh did not start")
	}

	stopped := make(chan struct{})
	go func() {
		manager.stop()
		close(stopped)
	}()
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("account protection stop did not cancel plan refresh")
	}
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("account protection stop did not join plan refresh")
	}

	manager.mu.RLock()
	defer manager.mu.RUnlock()
	if manager.plansCtx != nil || manager.plansCancel != nil || manager.plansRefreshing {
		t.Fatalf("stopped manager retained plan work: ctx=%v cancel=%v refreshing=%v", manager.plansCtx, manager.plansCancel != nil, manager.plansRefreshing)
	}
	if _, published := manager.plans["stale"]; published {
		t.Fatal("canceled plan refresh published after stop")
	}
}

func TestAccountProtectionReconfigureCancelsAndJoinsPlanRefresh(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("CPA_TOKEN_USAGE_DIR", dir)
	t.Setenv("CPA_AUTH_DIR", filepath.Join(dir, "auth"))
	var manager accountProtectionManager
	t.Cleanup(manager.stop)
	cfg := defaultPluginConfig()
	cfg.AccountProtectionEnabled = true
	manager.configure(cfg)

	started := make(chan struct{})
	canceled := make(chan struct{})
	manager.mu.Lock()
	manager.plansLoadedAt = time.Now().Add(-accountProtectionPlanRefreshInterval - time.Second)
	manager.plansLoader = func(ctx context.Context) map[string]string {
		close(started)
		<-ctx.Done()
		close(canceled)
		return map[string]string{"stale": "team"}
	}
	manager.mu.Unlock()
	manager.configuredPlans()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("background plan refresh did not start")
	}

	disabled := cfg
	disabled.AccountProtectionEnabled = false
	reconfigured := make(chan struct{})
	go func() {
		manager.configure(disabled)
		close(reconfigured)
	}()
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("account protection reconfigure did not cancel plan refresh")
	}
	select {
	case <-reconfigured:
	case <-time.After(time.Second):
		t.Fatal("account protection reconfigure did not join plan refresh")
	}

	manager.mu.RLock()
	defer manager.mu.RUnlock()
	if manager.cfg.AccountProtectionEnabled || manager.plansCtx != nil || manager.plansCancel != nil || manager.plansRefreshing {
		t.Fatalf("reconfigured manager retained plan work: enabled=%v ctx=%v cancel=%v refreshing=%v", manager.cfg.AccountProtectionEnabled, manager.plansCtx, manager.plansCancel != nil, manager.plansRefreshing)
	}
	if _, published := manager.plans["stale"]; published {
		t.Fatal("canceled plan refresh published after reconfigure")
	}
}

func newProtectionTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Exec(schemaSQL); err != nil {
		t.Fatal(err)
	}
	return db
}

func protectionTestCandidate(id, plan string, priority int) schedulerAuthCandidate {
	return schedulerAuthCandidate{
		ID:       id,
		Provider: "codex",
		Priority: priority,
		Attributes: map[string]string{
			"auth_index": id,
			"plan_type":  plan,
		},
	}
}

func TestNormalizedProtectionPlan(t *testing.T) {
	for input, want := range map[string]string{
		"free": "free", "chatgpt plus": "plus", "K12": "k12", "education": "k12", "team": "team", "pro": "pro", "": "plus",
	} {
		if got := normalizedProtectionPlan(input); got != want {
			t.Fatalf("normalizedProtectionPlan(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestProtectionConcurrencySwitchesCandidate(t *testing.T) {
	globalSchedulerRotation.reset()
	db := newProtectionTestDB(t)
	cfg := defaultPluginConfig()
	cfg.AccountProtectionEnabled = true
	cfg.AccountProtectionFreeConcurrency = 2
	s := &store{}
	ctx := context.Background()
	candidates := []schedulerAuthCandidate{protectionTestCandidate("a", "free", 10), protectionTestCandidate("b", "free", 1)}
	for _, want := range []string{"a", "a", "b"} {
		got, err := s.pickProtectedAuth(ctx, db, candidates, cfg, "codex\x00test")
		if err != nil {
			t.Fatal(err)
		}
		if got.ID != want {
			t.Fatalf("picked %q, want %q", got.ID, want)
		}
	}
}

func TestProtectionTokenDemotionPrefersLowerUsageCandidate(t *testing.T) {
	globalSchedulerRotation.reset()
	db := newProtectionTestDB(t)
	cfg := defaultPluginConfig()
	cfg.AccountProtectionEnabled = true
	cfg.AccountProtectionFreeTokenLimit = 2_000_000
	now := time.Now().Unix()
	if _, err := db.Exec(`INSERT INTO usage_events (requested_at, provider, auth_id, auth_index, total_tokens) VALUES (?, 'codex', 'a', 'a', ?)`, now, 2_000_000); err != nil {
		t.Fatal(err)
	}
	got, err := (&store{}).pickProtectedAuth(context.Background(), db, []schedulerAuthCandidate{
		protectionTestCandidate("a", "free", 10), protectionTestCandidate("b", "free", 1),
	}, cfg, "codex\x00test")
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != "b" {
		t.Fatalf("picked %q, want lower-token candidate b", got.ID)
	}
}

func TestProtectionSaturationUsesLeastInFlightCandidate(t *testing.T) {
	globalSchedulerRotation.reset()
	db := newProtectionTestDB(t)
	cfg := defaultPluginConfig()
	cfg.AccountProtectionEnabled = true
	cfg.AccountProtectionFreeConcurrency = 1
	now := time.Now().Unix()
	for i := 0; i < 2; i++ {
		if _, err := db.Exec(`INSERT INTO account_protection_reservations (auth_id, auth_index, source, plan_type, created_at, expires_at) VALUES ('a', 'a', '', 'free', ?, ?)`, now, now+900); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec(`INSERT INTO account_protection_reservations (auth_id, auth_index, source, plan_type, created_at, expires_at) VALUES ('b', 'b', '', 'free', ?, ?)`, now, now+900); err != nil {
		t.Fatal(err)
	}
	got, err := (&store{}).pickProtectedAuth(context.Background(), db, []schedulerAuthCandidate{
		protectionTestCandidate("a", "free", 10), protectionTestCandidate("b", "free", 1),
	}, cfg, "codex\x00test")
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != "b" {
		t.Fatalf("picked %q, want least-in-flight candidate b", got.ID)
	}
}

func TestProtectionSaturationUsesPriorityBeforeTokenDemotion(t *testing.T) {
	globalSchedulerRotation.reset()
	states := []protectionCandidate{
		{
			Candidate: schedulerAuthCandidate{ID: "high", Priority: 10},
			InFlight:  1,
			Limit:     1,
			Tokens:    100,
			Threshold: 100,
		},
		{
			Candidate: schedulerAuthCandidate{ID: "low", Priority: 1},
			InFlight:  1,
			Limit:     1,
			Tokens:    0,
			Threshold: 100,
		},
	}
	if got := chooseProtectedCandidate(states, "test"); got.Candidate.ID != "high" {
		t.Fatalf("picked %q, want higher-priority saturated candidate", got.Candidate.ID)
	}
}

func TestProtectionRoundRobinsWithinSamePriority(t *testing.T) {
	globalSchedulerRotation.reset()
	states := []protectionCandidate{
		{Candidate: schedulerAuthCandidate{ID: "z-account", Priority: 1}, Limit: 5},
		{Candidate: schedulerAuthCandidate{ID: "a-account", Priority: 1}, Limit: 5},
	}
	if got := chooseProtectedCandidate(states, "test"); got.Candidate.ID != "a-account" {
		t.Fatalf("first pick = %q, want a-account", got.Candidate.ID)
	}
	if got := chooseProtectedCandidate(states, "test"); got.Candidate.ID != "z-account" {
		t.Fatalf("second pick = %q, want z-account", got.Candidate.ID)
	}
}

func TestSchedulerRotationUsesHighestPriorityAndStableOrder(t *testing.T) {
	var rotation schedulerRotationManager
	candidates := []schedulerAuthCandidate{
		{ID: "z-high", Priority: 9},
		{ID: "low", Priority: 1},
		{ID: "a-high", Priority: 9},
	}
	if got := rotation.pick("codex\x00model", candidates); got.ID != "a-high" {
		t.Fatalf("first pick = %q, want a-high", got.ID)
	}
	reordered := []schedulerAuthCandidate{candidates[2], candidates[0], candidates[1]}
	if got := rotation.pick("codex\x00model", reordered); got.ID != "z-high" {
		t.Fatalf("second pick = %q, want z-high", got.ID)
	}
	if got := rotation.pick("codex\x00model", candidates); got.ID != "a-high" {
		t.Fatalf("third pick = %q, want a-high", got.ID)
	}
}

func TestProtectionReservationExpiresAndReleasesOnUsage(t *testing.T) {
	db := newProtectionTestDB(t)
	now := time.Now().Unix()
	if _, err := db.Exec(`INSERT INTO account_protection_reservations (auth_id, auth_index, source, plan_type, created_at, expires_at) VALUES ('expired', 'expired', '', 'plus', ?, ?)`, now-1000, now-1); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO account_protection_reservations (auth_id, auth_index, source, plan_type, created_at, expires_at) VALUES ('active', 'active', '', 'plus', ?, ?)`, now, now+900); err != nil {
		t.Fatal(err)
	}
	cfg := defaultPluginConfig()
	_, err := (&store{}).pickProtectedAuth(context.Background(), db, []schedulerAuthCandidate{protectionTestCandidate("other", "plus", 1)}, cfg, "codex\x00test")
	if err != nil {
		t.Fatal(err)
	}
	if err := releaseProtectionReservation(context.Background(), db, usageRecord{AuthID: "active", AuthIndex: "active"}); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM account_protection_reservations WHERE auth_id IN ('expired','active')`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("reservation count = %d, want 0", count)
	}
}

func TestProtectionCandidateAliasesExcludeSharedWorkspaceID(t *testing.T) {
	candidates := []schedulerAuthCandidate{
		{ID: "shared-workspace", Attributes: map[string]string{"auth_index": "shared-workspace", "source": "a@example.com", "auth_file": "a.json"}},
		{ID: "shared-workspace", Attributes: map[string]string{"auth_index": "shared-workspace", "source": "b@example.com", "auth_file": "b.json"}},
	}
	sets := protectionCandidateAliasSets(candidates)
	if len(sets) != 2 {
		t.Fatalf("alias sets = %+v", sets)
	}
	for i, aliases := range sets {
		if containsAlias(aliases, "shared-workspace") {
			t.Fatalf("candidate %d retained shared workspace alias: %+v", i, aliases)
		}
	}
	if !containsAlias(sets[0], "a.json") || !containsAlias(sets[0], "a@example.com") {
		t.Fatalf("candidate A aliases = %+v", sets[0])
	}
	if !containsAlias(sets[1], "b.json") || !containsAlias(sets[1], "b@example.com") {
		t.Fatalf("candidate B aliases = %+v", sets[1])
	}
}

func TestConfiguredProtectionPlanIndexIgnoresSharedAliases(t *testing.T) {
	index := configuredProtectionPlanIndex([]configuredAccount{
		{AuthID: "shared", AuthIndex: "shared", Email: "a@example.com", AuthFile: "a.json", PlanType: "free"},
		{AuthID: "shared", AuthIndex: "shared", Email: "b@example.com", AuthFile: "b.json", PlanType: "team"},
	})
	if index["shared"] != "" {
		t.Fatalf("shared alias retained plan %q", index["shared"])
	}
	if index["a@example.com"] != "free" || index["b@example.com"] != "team" {
		t.Fatalf("unique plan index = %+v", index)
	}
}

func TestProtectionSnapshotBatchesReservationAndTokenMetrics(t *testing.T) {
	db := newProtectionTestDB(t)
	now := time.Now().Unix()
	if _, err := db.Exec(`INSERT INTO account_protection_reservations (auth_id, auth_index, source, plan_type, created_at, expires_at) VALUES ('shared', 'shared', 'a@example.com', 'k12', ?, ?)`, now, now+900); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO usage_events (requested_at, provider, auth_id, auth_index, source, total_tokens) VALUES (?, 'codex', 'shared', 'shared', 'a@example.com', 100), (?, 'codex', 'shared', 'shared', 'b@example.com', 200)`, now, now); err != nil {
		t.Fatal(err)
	}
	snapshot, err := loadProtectionSnapshot(context.Background(), db, now-300, now)
	if err != nil {
		t.Fatal(err)
	}
	inFlight, tokens := snapshot.metrics([]string{"a@example.com"})
	if inFlight != 1 || tokens != 100 {
		t.Fatalf("account A metrics = %d/%d, want 1/100", inFlight, tokens)
	}
	inFlight, tokens = snapshot.metrics([]string{"b@example.com"})
	if inFlight != 0 || tokens != 200 {
		t.Fatalf("account B metrics = %d/%d, want 0/200", inFlight, tokens)
	}
}

func TestProtectionSnapshotAggregatesUsageBeforeLoading(t *testing.T) {
	db := newProtectionTestDB(t)
	now := time.Now().Unix()
	if _, err := db.Exec(`INSERT INTO usage_events (requested_at, provider, auth_id, auth_index, source, total_tokens) VALUES
		(?, 'codex', 'a', 'a', 'a@example.com', 100),
		(?, 'CODEX', 'a', 'a', 'a@example.com', 200),
		(?, 'codex', 'b', 'b', 'b@example.com', 400)`, now, now, now); err != nil {
		t.Fatal(err)
	}
	snapshot, err := loadProtectionSnapshot(context.Background(), db, now-300, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Usage) != 2 {
		t.Fatalf("usage groups = %d, want 2", len(snapshot.Usage))
	}
	_, tokens := snapshot.metrics([]string{"a@example.com"})
	if tokens != 300 {
		t.Fatalf("account A tokens = %d, want 300", tokens)
	}
}

func TestProtectionSnapshotCountsGroupedReservations(t *testing.T) {
	db := newProtectionTestDB(t)
	now := time.Now().Unix()
	if _, err := db.Exec(`INSERT INTO account_protection_reservations (auth_id, auth_index, source, plan_type, created_at, expires_at) VALUES
		('a', 'a', '', 'plus', ?, ?),
		('a', 'a', '', 'plus', ?, ?),
		('a', 'a', '', 'plus', ?, ?)`, now, now+900, now, now+900, now, now+900); err != nil {
		t.Fatal(err)
	}
	snapshot, err := loadProtectionSnapshot(context.Background(), db, now-300, now)
	if err != nil {
		t.Fatal(err)
	}
	inFlight, _ := snapshot.metrics([]string{"a"})
	if inFlight != 3 {
		t.Fatalf("in-flight = %d, want 3", inFlight)
	}
}

func TestProtectionSnapshotDoesNotDoubleCountSharedAliases(t *testing.T) {
	snapshot := newProtectionSnapshot(
		[]protectionReservationSample{{Aliases: []string{"account", "account@example.com"}, Count: 2}},
		[]protectionUsageSample{{Aliases: []string{"account", "account@example.com"}, Tokens: 300}},
	)
	inFlight, tokens := snapshot.metrics([]string{"account", "account@example.com"})
	if inFlight != 2 || tokens != 300 {
		t.Fatalf("metrics = %d/%d, want 2/300", inFlight, tokens)
	}
}

func TestProtectionSnapshotAggregatesFragmentedIdentitySamples(t *testing.T) {
	snapshot := newProtectionSnapshot(
		[]protectionReservationSample{
			{Aliases: []string{"account-id"}, Count: 1},
			{Aliases: []string{"account@example.com"}, Count: 2},
		},
		[]protectionUsageSample{
			{Aliases: []string{"account-id"}, Tokens: 100},
			{Aliases: []string{"account@example.com"}, Tokens: 200},
		},
	)
	inFlight, tokens := snapshot.metrics([]string{"account-id", "account@example.com"})
	if inFlight != 3 || tokens != 300 {
		t.Fatalf("fragmented metrics = %d/%d, want 3/300", inFlight, tokens)
	}
}

func TestProtectionSnapshotSharedAliasDoesNotCrossCandidates(t *testing.T) {
	candidates := []schedulerAuthCandidate{
		{ID: "shared", Attributes: map[string]string{"auth_index": "shared", "source": "a@example.com", "auth_file": "a.json"}},
		{ID: "shared", Attributes: map[string]string{"auth_index": "shared", "source": "b@example.com", "auth_file": "b.json"}},
	}
	aliasSets := protectionCandidateAliasSets(candidates)
	snapshot := newProtectionSnapshot(
		[]protectionReservationSample{
			{Aliases: []string{"shared", "a@example.com"}, Count: 1},
			{Aliases: []string{"shared", "b@example.com"}, Count: 2},
		},
		[]protectionUsageSample{
			{Aliases: []string{"shared", "a@example.com"}, Tokens: 100},
			{Aliases: []string{"shared", "b@example.com"}, Tokens: 200},
		},
	)

	inFlight, tokens := snapshot.metrics(aliasSets[0])
	if inFlight != 1 || tokens != 100 {
		t.Fatalf("candidate A shared-alias metrics = %d/%d, want 1/100", inFlight, tokens)
	}
	inFlight, tokens = snapshot.metrics(aliasSets[1])
	if inFlight != 2 || tokens != 200 {
		t.Fatalf("candidate B shared-alias metrics = %d/%d, want 2/200", inFlight, tokens)
	}
}

func TestProtectionRotationHandlesDuplicateCandidateIDs(t *testing.T) {
	globalSchedulerRotation.reset()
	states := []protectionCandidate{
		{Candidate: schedulerAuthCandidate{ID: "shared", Priority: 1, Attributes: map[string]string{"auth_file": "b.json"}}, AuthIndex: "b", Limit: 5},
		{Candidate: schedulerAuthCandidate{ID: "shared", Priority: 1, Attributes: map[string]string{"auth_file": "a.json"}}, AuthIndex: "a", Limit: 5},
	}
	first := chooseProtectedCandidate(states, "duplicate")
	reordered := []protectionCandidate{states[1], states[0]}
	second := chooseProtectedCandidate(reordered, "duplicate")
	if first.AuthIndex != "a" || second.AuthIndex != "b" {
		t.Fatalf("duplicate-ID rotation = %q then %q, want a then b", first.AuthIndex, second.AuthIndex)
	}
}

func TestProtectionRotationDeduplicatesExactCandidateIdentity(t *testing.T) {
	globalSchedulerRotation.reset()
	duplicate := schedulerAuthCandidate{ID: "shared", Priority: 1, Attributes: map[string]string{"auth_file": "same.json"}}
	other := schedulerAuthCandidate{ID: "shared", Priority: 1, Attributes: map[string]string{"auth_file": "other.json"}}
	states := []protectionCandidate{
		{Candidate: duplicate, AuthIndex: "first", Limit: 5},
		{Candidate: duplicate, AuthIndex: "duplicate", Limit: 5},
		{Candidate: other, AuthIndex: "other", Limit: 5},
	}
	first := chooseProtectedCandidate(states, "exact-duplicate")
	second := chooseProtectedCandidate(states, "exact-duplicate")
	if first.AuthIndex == "duplicate" || second.AuthIndex == "duplicate" || first.AuthIndex == second.AuthIndex {
		t.Fatalf("exact duplicate participated in rotation: %q then %q", first.AuthIndex, second.AuthIndex)
	}
}

func TestDeleteFirstProtectionReservationAdvancesAfterConcurrentDelete(t *testing.T) {
	db := newProtectionTestDB(t)
	now := time.Now().Unix()
	for i := 0; i < 2; i++ {
		if _, err := db.Exec(`INSERT INTO account_protection_reservations
			(auth_id, auth_index, source, plan_type, created_at, expires_at)
			VALUES ('shared', 'shared', '', 'plus', ?, ?)`, now, now+900); err != nil {
			t.Fatal(err)
		}
	}
	rows, err := db.Query(`SELECT id FROM account_protection_reservations ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	if err := rows.Close(); err != nil {
		t.Fatal(err)
	}

	start := make(chan struct{})
	results := make(chan bool, 2)
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			deleted, err := deleteFirstProtectionReservation(context.Background(), db, ids)
			results <- deleted
			errs <- err
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	for deleted := range results {
		if !deleted {
			t.Fatal("concurrent release did not advance to an undeleted reservation")
		}
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM account_protection_reservations`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("reservation count = %d, want 0", count)
	}
}

func TestProtectionPickMutexWaitHonorsContext(t *testing.T) {
	db := newProtectionTestDB(t)
	cfg := defaultPluginConfig()
	cfg.AccountProtectionEnabled = true
	if err := globalAccountProtection.pickMu.lock(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer globalAccountProtection.pickMu.unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, err := (&store{}).pickProtectedAuth(ctx, db, []schedulerAuthCandidate{
		protectionTestCandidate("a", "plus", 1),
	}, cfg, "context-wait")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("pick error = %v, want context deadline exceeded", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("canceled mutex wait took %v", elapsed)
	}
}

func TestProtectionUsageMutexWaitHonorsContext(t *testing.T) {
	db := newProtectionTestDB(t)
	var manager accountProtectionManager
	if err := manager.usageMu.lock(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer manager.usageMu.unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, err := manager.loadUsageSnapshot(ctx, db, time.Now().Unix()-300)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("usage snapshot error = %v, want context deadline exceeded", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("canceled usage mutex wait took %v", elapsed)
	}
}
