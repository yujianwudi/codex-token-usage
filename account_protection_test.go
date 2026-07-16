package main

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
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

func TestAccountProtectionStopDoesNotWaitForStuckPlanLoader(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("CPA_TOKEN_USAGE_DIR", dir)
	t.Setenv("CPA_AUTH_DIR", filepath.Join(dir, "auth"))
	var manager accountProtectionManager
	var releaseOnce sync.Once
	release := make(chan struct{})
	releaseLoader := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(func() {
		releaseLoader()
		manager.stop()
	})
	cfg := defaultPluginConfig()
	cfg.AccountProtectionEnabled = true
	manager.configure(cfg)

	started := make(chan context.Context, 1)
	manager.mu.Lock()
	manager.plans = map[string]string{"stable": "free"}
	manager.plansLoadedAt = time.Now().Add(-accountProtectionPlanRefreshInterval - time.Second)
	manager.plansLoader = func(ctx context.Context) map[string]string {
		started <- ctx
		<-release // Deliberately ignore cancellation like a stuck filesystem call.
		return map[string]string{"stale": "team"}
	}
	manager.mu.Unlock()
	manager.configuredPlans()

	var refreshCtx context.Context
	select {
	case refreshCtx = <-started:
	case <-time.After(time.Second):
		t.Fatal("background plan refresh did not start")
	}
	manager.mu.RLock()
	done := manager.plansRefreshDone
	manager.mu.RUnlock()
	if done == nil {
		t.Fatal("background plan refresh did not publish a completion channel")
	}

	stopped := make(chan struct{})
	go func() {
		manager.stop()
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-time.After(time.Second):
		releaseLoader()
		t.Fatal("account protection stop waited indefinitely for a stuck loader")
	}
	if refreshCtx.Err() == nil {
		releaseLoader()
		t.Fatal("account protection stop did not cancel the stuck refresh context")
	}

	releaseLoader()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("released plan loader did not exit")
	}
	manager.mu.RLock()
	defer manager.mu.RUnlock()
	if _, published := manager.plans["stale"]; published {
		t.Fatal("stuck plan refresh published after stop")
	}
}

func TestAccountProtectionReconfigureDoesNotWaitForStuckPlanLoader(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("CPA_TOKEN_USAGE_DIR", dir)
	t.Setenv("CPA_AUTH_DIR", filepath.Join(dir, "auth"))
	var manager accountProtectionManager
	var releaseOnce sync.Once
	release := make(chan struct{})
	releaseLoader := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(func() {
		releaseLoader()
		manager.stop()
	})
	cfg := defaultPluginConfig()
	cfg.AccountProtectionEnabled = true
	manager.configure(cfg)

	started := make(chan struct{})
	manager.mu.Lock()
	manager.plansLoadedAt = time.Now().Add(-accountProtectionPlanRefreshInterval - time.Second)
	manager.plansLoader = func(context.Context) map[string]string {
		close(started)
		<-release // Deliberately ignore cancellation like a stuck filesystem call.
		return map[string]string{"stale": "team"}
	}
	manager.mu.Unlock()
	manager.configuredPlans()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("background plan refresh did not start")
	}
	manager.mu.RLock()
	done := manager.plansRefreshDone
	manager.mu.RUnlock()
	if done == nil {
		t.Fatal("background plan refresh did not publish a completion channel")
	}

	disabled := cfg
	disabled.AccountProtectionEnabled = false
	reconfigured := make(chan struct{})
	go func() {
		manager.configure(disabled)
		close(reconfigured)
	}()
	select {
	case <-reconfigured:
	case <-time.After(time.Second):
		releaseLoader()
		t.Fatal("account protection reconfigure waited indefinitely for a stuck loader")
	}
	manager.mu.Lock()
	manager.plans = map[string]string{"current": "pro"}
	manager.mu.Unlock()

	releaseLoader()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("released old-generation plan loader did not exit")
	}
	manager.mu.RLock()
	defer manager.mu.RUnlock()
	if got := manager.plans["current"]; got != "pro" {
		t.Fatalf("current generation plan = %q, want pro", got)
	}
	if _, published := manager.plans["stale"]; published {
		t.Fatal("old-generation stuck refresh overwrote reconfigured plans")
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
	previousCfg := globalAccountProtection.config()
	globalAccountProtection.configure(cfg)
	t.Cleanup(func() { globalAccountProtection.configure(previousCfg) })
	now := time.Now().Unix()
	if _, err := db.Exec(`INSERT INTO usage_events (requested_at, provider, auth_id, auth_index, total_tokens) VALUES (?, 'codex', 'a', 'a', ?)`, now, 2_000_000); err != nil {
		t.Fatal(err)
	}
	since := now - int64(cfg.AccountProtectionTokenWindowSeconds)
	if _, err := globalAccountProtection.loadUsageIndex(context.Background(), db, since); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		globalAccountProtection.usageCacheMu.RLock()
		index := globalAccountProtection.usage
		refreshing := globalAccountProtection.usageRefreshing
		globalAccountProtection.usageCacheMu.RUnlock()
		if index != nil && len(index.samples) == 1 && index.samples[0].Tokens == 2_000_000 && !refreshing {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	globalAccountProtection.usageCacheMu.RLock()
	loaded := globalAccountProtection.usage
	globalAccountProtection.usageCacheMu.RUnlock()
	if loaded == nil || len(loaded.samples) != 1 || loaded.samples[0].Tokens != 2_000_000 {
		t.Fatal("background token usage refresh did not publish the demotion index")
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

func TestProtectionSaturationRejectsWithoutCreatingReservation(t *testing.T) {
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
	_, err := (&store{}).pickProtectedAuth(context.Background(), db, []schedulerAuthCandidate{
		protectionTestCandidate("a", "free", 10), protectionTestCandidate("b", "free", 1),
	}, cfg, "codex\x00test")
	var reject *schedulerRejectError
	if !errors.As(err, &reject) || reject.Code != "account_protection_saturated" || reject.HTTPStatus != 503 {
		t.Fatalf("error = %#v / %v, want account_protection_saturated 503", reject, err)
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM account_protection_reservations`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 3 {
		t.Fatalf("reservation count = %d, want unchanged count 3", count)
	}
}

func TestProtectionSaturationCommitsExpiredReservationCleanup(t *testing.T) {
	globalSchedulerRotation.reset()
	db := newProtectionTestDB(t)
	cfg := defaultPluginConfig()
	cfg.AccountProtectionEnabled = true
	cfg.AccountProtectionFreeConcurrency = 1
	now := time.Now().Unix()
	if _, err := db.Exec(`INSERT INTO account_protection_reservations
		(provider,auth_id,auth_index,source,plan_type,created_at,expires_at) VALUES
		('codex','expired','expired','','free',?,?),
		('codex','active','active','','free',?,?)`, now-60, now-1, now, now+900); err != nil {
		t.Fatal(err)
	}

	_, err := (&store{}).pickProtectedAuth(context.Background(), db, []schedulerAuthCandidate{
		protectionTestCandidate("active", "free", 1),
	}, cfg, "codex\x00saturated-cleanup")
	var reject *schedulerRejectError
	if !errors.As(err, &reject) || reject.Code != "account_protection_saturated" {
		t.Fatalf("error = %#v / %v, want account_protection_saturated", reject, err)
	}
	var expired, active int
	if err := db.QueryRow(`SELECT COUNT(*) FROM account_protection_reservations WHERE auth_id='expired'`).Scan(&expired); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM account_protection_reservations WHERE auth_id='active'`).Scan(&active); err != nil {
		t.Fatal(err)
	}
	if expired != 0 || active != 1 {
		t.Fatalf("reservation rows expired=%d active=%d, want 0/1", expired, active)
	}
}

func TestProtectionSaturationCommitFailureOverridesCapacityConclusion(t *testing.T) {
	globalSchedulerRotation.reset()
	db := newProtectionTestDB(t)
	if _, err := db.Exec(`
PRAGMA foreign_keys=ON;
CREATE TABLE reservation_commit_parent (id INTEGER PRIMARY KEY);
CREATE TABLE reservation_commit_child (
  parent_id INTEGER,
  FOREIGN KEY(parent_id) REFERENCES reservation_commit_parent(id) DEFERRABLE INITIALLY DEFERRED
);
CREATE TRIGGER fail_saturated_cleanup_commit
AFTER DELETE ON account_protection_reservations
WHEN OLD.provider='codex'
BEGIN
  INSERT INTO reservation_commit_child(parent_id) VALUES(999);
END;`); err != nil {
		t.Fatal(err)
	}
	cfg := defaultPluginConfig()
	cfg.AccountProtectionEnabled = true
	cfg.AccountProtectionFreeConcurrency = 1
	now := time.Now().Unix()
	if _, err := db.Exec(`INSERT INTO account_protection_reservations
		(provider,auth_id,auth_index,source,plan_type,created_at,expires_at) VALUES
		('codex','expired','expired','','free',?,?),
		('codex','active','active','','free',?,?)`, now-60, now-1, now, now+900); err != nil {
		t.Fatal(err)
	}

	_, err := (&store{}).pickProtectedAuth(context.Background(), db, []schedulerAuthCandidate{
		protectionTestCandidate("active", "free", 1),
	}, cfg, "codex\x00saturated-commit-failure")
	if err == nil {
		t.Fatal("commit failure returned a saturated success path")
	}
	var reject *schedulerRejectError
	if errors.As(err, &reject) && reject.Code == "account_protection_saturated" {
		t.Fatalf("commit failure was hidden by saturated result: %v", err)
	}
	var expired, children int
	if err := db.QueryRow(`SELECT COUNT(*) FROM account_protection_reservations WHERE auth_id='expired'`).Scan(&expired); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM reservation_commit_child`).Scan(&children); err != nil {
		t.Fatal(err)
	}
	if expired != 1 || children != 0 {
		t.Fatalf("failed commit left partial state expired=%d child_rows=%d, want 1/0", expired, children)
	}
}

func TestUsageInsertAndProtectionReleaseAreAtomic(t *testing.T) {
	s := newTestStore(t)
	db, _, err := s.open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	if _, err := db.Exec(`INSERT INTO account_protection_reservations
		(auth_id, auth_index, source, plan_type, created_at, expires_at)
		VALUES ('atomic', 'atomic', '', 'free', ?, ?)`, now, now+900); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TRIGGER fail_atomic_reservation_release
		BEFORE DELETE ON account_protection_reservations
		WHEN OLD.auth_id = 'atomic'
		BEGIN SELECT RAISE(ABORT, 'forced reservation release failure'); END`); err != nil {
		t.Fatal(err)
	}
	err = s.recordUsage(context.Background(), usageRecord{
		Provider:    "codex",
		AuthID:      "atomic",
		AuthIndex:   "atomic",
		RequestedAt: time.Now(),
		Detail:      usageDetail{TotalTokens: 10},
	})
	if err == nil || !strings.Contains(err.Error(), "release protection reservation") {
		t.Fatalf("recordUsage error=%v, want atomic reservation release failure", err)
	}
	var usageRows, reservations int
	if err := db.QueryRow(`SELECT COUNT(*) FROM usage_events WHERE auth_id='atomic'`).Scan(&usageRows); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM account_protection_reservations WHERE auth_id='atomic'`).Scan(&reservations); err != nil {
		t.Fatal(err)
	}
	if usageRows != 0 || reservations != 1 {
		t.Fatalf("usageRows=%d reservations=%d, want rollback to 0 usage and 1 reservation", usageRows, reservations)
	}
}

func TestProtectionConcurrentPicksNeverExceedHardLimit(t *testing.T) {
	globalSchedulerRotation.reset()
	db := newProtectionTestDB(t)
	cfg := defaultPluginConfig()
	cfg.AccountProtectionEnabled = true
	cfg.AccountProtectionFreeConcurrency = 1
	candidate := protectionTestCandidate("only", "free", 1)
	const workers = 12
	start := make(chan struct{})
	results := make(chan error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := (&store{}).pickProtectedAuth(context.Background(), db, []schedulerAuthCandidate{candidate}, cfg, "codex\x00hard-limit")
			results <- err
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	successes := 0
	rejections := 0
	for err := range results {
		if err == nil {
			successes++
			continue
		}
		var reject *schedulerRejectError
		if !errors.As(err, &reject) || reject.Code != "account_protection_saturated" {
			t.Fatalf("unexpected pick error: %#v / %v", reject, err)
		}
		rejections++
	}
	if successes != 1 || rejections != workers-1 {
		t.Fatalf("successes=%d rejections=%d, want 1 and %d", successes, rejections, workers-1)
	}
	var reservations int
	if err := db.QueryRow(`SELECT COUNT(*) FROM account_protection_reservations`).Scan(&reservations); err != nil {
		t.Fatal(err)
	}
	if reservations != 1 {
		t.Fatalf("reservations=%d, want hard limit 1", reservations)
	}
}

func TestProtectionCandidateSelectionRejectsWhenEveryLimitIsReached(t *testing.T) {
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
	_, err := chooseProtectedCandidate(states, "test")
	var reject *schedulerRejectError
	if !errors.As(err, &reject) || reject.Code != "account_protection_saturated" {
		t.Fatalf("error = %#v / %v, want account_protection_saturated", reject, err)
	}
}

func TestProtectionRoundRobinsWithinSamePriority(t *testing.T) {
	globalSchedulerRotation.reset()
	states := []protectionCandidate{
		{Candidate: schedulerAuthCandidate{ID: "z-account", Priority: 1}, Limit: 5},
		{Candidate: schedulerAuthCandidate{ID: "a-account", Priority: 1}, Limit: 5},
	}
	got, err := chooseProtectedCandidate(states, "test")
	if err != nil {
		t.Fatal(err)
	}
	if got.Candidate.ID != "a-account" {
		t.Fatalf("first pick = %q, want a-account", got.Candidate.ID)
	}
	got, err = chooseProtectedCandidate(states, "test")
	if err != nil {
		t.Fatal(err)
	}
	if got.Candidate.ID != "z-account" {
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
	if _, err := releaseProtectionReservation(context.Background(), db, usageRecord{Provider: "codex", AuthID: "active", AuthIndex: "active"}); err != nil {
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

func TestApplyAccountProtectionStateExpiresOnlyCodexReservations(t *testing.T) {
	db := newProtectionTestDB(t)
	now := time.Now().Unix()
	for _, provider := range []string{providerCodex, "future-provider"} {
		if _, err := db.Exec(`INSERT INTO account_protection_reservations
			(provider, auth_id, auth_index, source, plan_type, created_at, expires_at)
			VALUES (?, ?, ?, '', 'plus', ?, ?)`, provider, provider, provider, now-1000, now-1); err != nil {
			t.Fatal(err)
		}
	}
	previousCfg := globalAccountProtection.config()
	cfg := defaultPluginConfig()
	cfg.AccountProtectionEnabled = true
	globalAccountProtection.configure(cfg)
	t.Cleanup(func() { globalAccountProtection.configure(previousCfg) })

	applyAccountProtectionState(context.Background(), db, nil)
	var codexRows, foreignRows int
	if err := db.QueryRow(`SELECT COUNT(*) FROM account_protection_reservations WHERE provider=?`, providerCodex).Scan(&codexRows); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM account_protection_reservations WHERE provider='future-provider'`).Scan(&foreignRows); err != nil {
		t.Fatal(err)
	}
	if codexRows != 0 || foreignRows != 1 {
		t.Fatalf("expired reservation rows codex=%d foreign=%d, want 0/1", codexRows, foreignRows)
	}
}

func TestProtectionReservationReleaseKeepsSiblingWithSharedAliases(t *testing.T) {
	db := newProtectionTestDB(t)
	now := time.Now().Unix()
	for _, reservation := range []struct {
		authFile  string
		createdAt int64
	}{
		{authFile: "b.json", createdAt: now - 10},
		{authFile: "a.json", createdAt: now},
	} {
		if _, err := db.Exec(`INSERT INTO account_protection_reservations
			(auth_id, auth_index, source, auth_file, plan_type, created_at, expires_at)
			VALUES ('shared-workspace', 'shared-workspace', 'shared@example.com', ?, 'plus', ?, ?)`, reservation.authFile, reservation.createdAt, now+900); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := releaseProtectionReservation(context.Background(), db, usageRecord{
		Provider:  "codex",
		AuthID:    "shared-workspace",
		AuthIndex: "shared-workspace",
		Source:    "shared@example.com",
		AuthFile:  "a.json",
	}); err != nil {
		t.Fatal(err)
	}
	var remaining string
	if err := db.QueryRow(`SELECT auth_file FROM account_protection_reservations`).Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if remaining != "b.json" {
		t.Fatalf("remaining reservation = %q, want b.json", remaining)
	}
}

func TestProtectionReservationSnapshotSeparatesDuplicateFiles(t *testing.T) {
	db := newProtectionTestDB(t)
	now := time.Now().Unix()
	for _, authFile := range []string{"a.json", "b.json"} {
		if _, err := db.Exec(`INSERT INTO account_protection_reservations
			(auth_id, auth_index, source, auth_file, plan_type, created_at, expires_at)
			VALUES ('shared-workspace', 'shared-workspace', 'shared@example.com', ?, 'plus', ?, ?)`, authFile, now, now+900); err != nil {
			t.Fatal(err)
		}
	}
	snapshot, err := loadProtectionReservationSnapshot(context.Background(), db, providerCodex, now)
	if err != nil {
		t.Fatal(err)
	}
	indexed := newProtectionSnapshot(snapshot, nil)
	for _, authFile := range []string{"a.json", "b.json"} {
		inFlight, _ := indexed.metrics([]string{authFile})
		if inFlight != 1 {
			t.Fatalf("%s in-flight = %d, want 1", authFile, inFlight)
		}
	}
}

func TestProtectionReservationCanonicalizesSchedulerAuthFile(t *testing.T) {
	t.Setenv("CPA_TOKEN_USAGE_DIR", t.TempDir())
	globalSchedulerRotation.reset()
	db := newProtectionTestDB(t)
	cfg := defaultPluginConfig()
	authPath := filepath.Join(t.TempDir(), "nested", "a.json")
	candidate := schedulerAuthCandidate{
		ID:       "shared-workspace",
		Provider: "codex",
		Attributes: map[string]string{
			"auth_index": "shared-workspace",
			"source":     authPath,
			"plan_type":  "plus",
		},
	}
	if _, err := (&store{}).pickProtectedAuth(context.Background(), db, []schedulerAuthCandidate{candidate}, cfg, "persist-auth-file"); err != nil {
		t.Fatal(err)
	}
	var authFile string
	if err := db.QueryRow(`SELECT auth_file FROM account_protection_reservations`).Scan(&authFile); err != nil {
		t.Fatal(err)
	}
	if authFile != "a.json" {
		t.Fatalf("stored auth file = %q, want a.json", authFile)
	}
	if _, err := releaseProtectionReservation(context.Background(), db, usageRecord{
		Provider:  "codex",
		AuthID:    "shared-workspace",
		AuthIndex: "shared-workspace",
		Source:    authPath,
	}); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM account_protection_reservations`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("canonical file reservation was not released: %d remain", count)
	}
}

func TestSchedulerCandidateAuthFileUsesAllFileIdentityFields(t *testing.T) {
	fullPath := filepath.Join("nested", "a.json")
	for name, candidate := range map[string]schedulerAuthCandidate{
		"auth_file":  {Attributes: map[string]string{"auth_file": fullPath}},
		"path":       {Attributes: map[string]string{"path": fullPath}},
		"file":       {Metadata: map[string]any{"file": fullPath}},
		"source":     {Attributes: map[string]string{"source": fullPath}},
		"auth_index": {Attributes: map[string]string{"auth_index": fullPath}},
		"id":         {ID: fullPath},
	} {
		t.Run(name, func(t *testing.T) {
			if got := schedulerCandidateAuthFile(candidate); got != "a.json" {
				t.Fatalf("schedulerCandidateAuthFile = %q, want a.json", got)
			}
		})
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

func TestProtectionUsageAliasesRetainSharedAuthIDFallbackForCPAPathSource(t *testing.T) {
	candidates := []schedulerAuthCandidate{
		{ID: "shared-workspace", Attributes: map[string]string{"source": "/auth/a.json", "auth_file": "a.json"}},
		{ID: "shared-workspace", Attributes: map[string]string{"source": "/auth/b.json", "auth_file": "b.json"}},
	}
	sets := protectionCandidateUsageAliasSets(candidates)
	if len(sets) != 2 ||
		!containsAlias(sets[0], "/auth/a.json") || !containsAlias(sets[0], "shared-workspace") ||
		!containsAlias(sets[1], "/auth/b.json") || !containsAlias(sets[1], "shared-workspace") {
		t.Fatalf("usage alias sets = %+v, want unique paths plus the shared auth ID fallback", sets)
	}

	// CPA usage callbacks do not necessarily repeat the scheduler's path source;
	// AuthID is the only guaranteed bridge for these duplicate candidates.
	snapshot := newProtectionSnapshotWithUsageIndex(nil, newProtectionUsageIndex([]protectionUsageSample{{
		Aliases: []string{"shared-workspace", "generated-index-a", "a@example.com"},
		Tokens:  2_000_000,
	}}))
	for i := range candidates {
		_, tokens := snapshot.metricsFor(nil, sets[i])
		if tokens != 2_000_000 {
			t.Fatalf("candidate %d tokens = %d, want conservative AuthID attribution", i, tokens)
		}
	}
}

func TestProtectionUsageAliasesConservativelyRetainFullyCollidingIdentity(t *testing.T) {
	candidates := []schedulerAuthCandidate{
		{ID: "shared-workspace", Attributes: map[string]string{"auth_index": "shared-workspace", "source": "shared@example.com", "auth_file": "a.json"}},
		{ID: "shared-workspace", Attributes: map[string]string{"auth_index": "shared-workspace", "source": "shared@example.com", "auth_file": "b.json"}},
	}
	reservationSets := protectionCandidateAliasSets(candidates)
	usageSets := protectionCandidateUsageAliasSets(candidates)
	for i := range candidates {
		if containsAlias(reservationSets[i], "shared-workspace") || containsAlias(reservationSets[i], "shared@example.com") {
			t.Fatalf("candidate %d hard-limit aliases retained a colliding broad identity: %+v", i, reservationSets[i])
		}
		if !containsAlias(usageSets[i], "shared-workspace") || !containsAlias(usageSets[i], "shared@example.com") {
			t.Fatalf("candidate %d soft-token aliases dropped an ambiguous usage identity: %+v", i, usageSets[i])
		}
	}

	snapshot := newProtectionSnapshotWithUsageIndex(nil, newProtectionUsageIndex([]protectionUsageSample{{
		Aliases: []string{"shared-workspace", "shared@example.com"},
		Tokens:  2_000_000,
	}}))
	for i := range candidates {
		inFlight, tokens := snapshot.metricsFor(reservationSets[i], usageSets[i])
		if inFlight != 0 || tokens != 2_000_000 {
			t.Fatalf("candidate %d ambiguous metrics = %d/%d, want 0/2000000", i, inFlight, tokens)
		}
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
		(?, 'codex', 'a', 'a', 'a@example.com', 200),
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
	first, err := chooseProtectedCandidate(states, "duplicate")
	if err != nil {
		t.Fatal(err)
	}
	reordered := []protectionCandidate{states[1], states[0]}
	second, err := chooseProtectedCandidate(reordered, "duplicate")
	if err != nil {
		t.Fatal(err)
	}
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
	first, err := chooseProtectedCandidate(states, "exact-duplicate")
	if err != nil {
		t.Fatal(err)
	}
	second, err := chooseProtectedCandidate(states, "exact-duplicate")
	if err != nil {
		t.Fatal(err)
	}
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
			deleted, err := deleteFirstProtectionReservation(context.Background(), db, "codex", ids)
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

func TestProtectionColdUsageIndexDoesNotWaitForRefreshMutex(t *testing.T) {
	db := newProtectionTestDB(t)
	var manager accountProtectionManager
	cfg := defaultPluginConfig()
	cfg.AccountProtectionEnabled = true
	manager.configure(cfg)
	t.Cleanup(manager.stop)
	if err := manager.usageMu.lock(context.Background()); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	started := time.Now()
	index, err := manager.loadUsageIndex(ctx, db, time.Now().Unix()-300)
	if err != nil {
		manager.usageMu.unlock()
		t.Fatal(err)
	}
	if len(index.samples) != 0 {
		manager.usageMu.unlock()
		t.Fatalf("cold usage samples=%d, want immediate empty soft-demotion snapshot", len(index.samples))
	}
	if elapsed := time.Since(started); elapsed > 100*time.Millisecond {
		manager.usageMu.unlock()
		t.Fatalf("cold usage read waited for refresh mutex for %v", elapsed)
	}
	manager.usageMu.unlock()
}

func TestProtectionUsageIndexServesStaleWhileRefreshing(t *testing.T) {
	db := newProtectionTestDB(t)
	var manager accountProtectionManager
	cfg := defaultPluginConfig()
	cfg.AccountProtectionEnabled = true
	manager.configure(cfg)
	t.Cleanup(manager.stop)
	now := time.Now().Unix()
	since := now - 300
	if _, err := db.Exec(`INSERT INTO usage_events (requested_at, provider, auth_id, auth_index, total_tokens) VALUES (?, 'codex', 'a', 'a', 100)`, now); err != nil {
		t.Fatal(err)
	}
	index, err := manager.loadUsageIndex(context.Background(), db, since)
	if err != nil {
		t.Fatal(err)
	}
	if len(index.samples) != 0 {
		t.Fatalf("cold usage samples=%d, want immediate empty snapshot", len(index.samples))
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		manager.usageCacheMu.RLock()
		index = manager.usage
		refreshing := manager.usageRefreshing
		manager.usageCacheMu.RUnlock()
		if index != nil && len(index.samples) == 1 && index.samples[0].Tokens == 100 && !refreshing {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if index == nil || len(index.samples) != 1 || index.samples[0].Tokens != 100 {
		t.Fatal("background cold usage refresh did not publish the initial index")
	}
	if _, err := db.Exec(`INSERT INTO usage_events (requested_at, provider, auth_id, auth_index, total_tokens) VALUES (?, 'codex', 'a', 'a', 200)`, now); err != nil {
		t.Fatal(err)
	}
	manager.usageCacheMu.Lock()
	manager.usageLoadedAt = time.Now().Add(-accountProtectionUsageRefreshInterval - time.Millisecond)
	manager.usageCacheMu.Unlock()
	started := time.Now()
	stale, err := manager.loadUsageIndex(context.Background(), db, since)
	if err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(started); elapsed > 100*time.Millisecond {
		t.Fatalf("stale usage read blocked for %v", elapsed)
	}
	if got := stale.samples[0].Tokens; got != 100 {
		t.Fatalf("stale tokens = %d, want cached 100", got)
	}
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		manager.usageCacheMu.RLock()
		current := manager.usage
		refreshing := manager.usageRefreshing
		manager.usageCacheMu.RUnlock()
		if current != nil && len(current.samples) == 1 && current.samples[0].Tokens == 300 && !refreshing {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("background usage refresh did not publish the updated index")
}

func TestProtectionUsageIndexServesOldWindowWhileRefreshing(t *testing.T) {
	db := newProtectionTestDB(t)
	var manager accountProtectionManager
	cfg := defaultPluginConfig()
	cfg.AccountProtectionEnabled = true
	manager.configure(cfg)
	t.Cleanup(manager.stop)
	since := time.Now().Unix() - 300
	manager.usageCacheMu.Lock()
	manager.usageDB = db
	manager.usageSince = since
	manager.usageLoadedAt = time.Now()
	manager.usage = newProtectionUsageIndex([]protectionUsageSample{{Aliases: []string{"a"}, Tokens: 100}})
	manager.usageCacheMu.Unlock()
	if err := manager.usageMu.lock(context.Background()); err != nil {
		t.Fatal(err)
	}
	advancedSince := since + int64(accountProtectionUsageMaxWindowAdvance/time.Second) + 2
	started := time.Now()
	index, err := manager.loadUsageIndex(context.Background(), db, advancedSince)
	if err != nil {
		manager.usageMu.unlock()
		t.Fatal(err)
	}
	if elapsed := time.Since(started); elapsed > 100*time.Millisecond {
		manager.usageMu.unlock()
		t.Fatalf("old-window usage read waited for refresh for %v", elapsed)
	}
	if len(index.samples) != 1 || index.samples[0].Tokens != 100 {
		manager.usageMu.unlock()
		t.Fatalf("old-window usage=%+v, want conservative cached tokens", index.samples)
	}
	manager.usageMu.unlock()
}

func TestProtectionUsageRefreshPublishesAdvancedWindow(t *testing.T) {
	db := newProtectionTestDB(t)
	var manager accountProtectionManager
	cfg := defaultPluginConfig()
	cfg.AccountProtectionEnabled = true
	manager.configure(cfg)
	t.Cleanup(manager.stop)

	now := time.Now().Unix()
	oldSince := now - 300
	targetSince := now - 60
	if _, err := db.Exec(`INSERT INTO usage_events (requested_at, provider, auth_id, auth_index, total_tokens) VALUES
		(?, 'codex', 'a', 'a', 100),
		(?, 'codex', 'a', 'a', 200)`, targetSince-1, targetSince+1); err != nil {
		t.Fatal(err)
	}
	manager.usageCacheMu.Lock()
	manager.usageDB = db
	manager.usageSince = oldSince
	manager.usageLoadedAt = time.Now()
	manager.usage = newProtectionUsageIndex([]protectionUsageSample{{Aliases: []string{"a"}, Tokens: 300}})
	manager.usageCacheMu.Unlock()

	if err := manager.usageMu.lock(context.Background()); err != nil {
		t.Fatal(err)
	}
	locked := true
	defer func() {
		if locked {
			manager.usageMu.unlock()
		}
	}()

	stale, err := manager.loadUsageIndex(context.Background(), db, targetSince)
	if err != nil {
		t.Fatal(err)
	}
	if len(stale.samples) != 1 || stale.samples[0].Tokens != 300 {
		t.Fatalf("stale advanced-window usage=%+v, want conservative old-window tokens", stale.samples)
	}
	manager.usageCacheMu.RLock()
	done := manager.usageRefreshDone
	refreshing := manager.usageRefreshing
	manager.usageCacheMu.RUnlock()
	if !refreshing || done == nil {
		t.Fatal("advanced-window usage refresh did not start")
	}

	manager.usageMu.unlock()
	locked = false
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("advanced-window usage refresh did not finish")
	}

	manager.usageCacheMu.RLock()
	loadedSince := manager.usageSince
	loaded := manager.usage
	manager.usageCacheMu.RUnlock()
	if loadedSince != targetSince {
		t.Fatalf("published usage window since=%d, want target %d", loadedSince, targetSince)
	}
	if loaded == nil || len(loaded.samples) != 1 || loaded.samples[0].Tokens != 200 {
		t.Fatalf("advanced-window usage=%+v, want only target-window tokens", loaded)
	}
}
