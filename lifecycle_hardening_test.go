package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestPluginLifecycleStoppedInvocationDoesNotReopenStore(t *testing.T) {
	s := newTestStore(t)
	dbPath := filepath.Join(os.Getenv("CPA_TOKEN_USAGE_DIR"), "usage.db")

	pluginLifecycleGate.Lock()
	pluginLifecycleStopped = false
	pluginLifecycleGate.Unlock()
	t.Cleanup(func() {
		pluginLifecycleGate.Lock()
		pluginLifecycleStopped = true
		pluginLifecycleGate.Unlock()
	})

	unlock, running := beginPluginInvocation("scheduler.pick")
	unlock()
	if !running {
		t.Fatal("running lifecycle rejected an invocation before shutdown")
	}

	// This test starts the invocation after shutdown owns the write gate. The
	// separate pending-writer guarantee comes from sync.RWMutex itself; the
	// plugin behavior under test is that the queued invocation observes the
	// published stopped state and therefore cannot reopen SQLite.
	pluginLifecycleGate.Lock()
	writerLocked := true
	defer func() {
		if writerLocked {
			pluginLifecycleGate.Unlock()
		}
	}()
	pluginLifecycleStopped = true

	type invocationResult struct {
		running       bool
		attemptedOpen bool
		openErr       error
	}
	readerAtGate := make(chan struct{})
	readerResult := make(chan invocationResult, 1)
	go func() {
		unlock, running := beginPluginInvocationBefore("scheduler.pick", func() {
			close(readerAtGate)
		})
		result := invocationResult{running: running}
		if running {
			result.attemptedOpen = true
			_, _, result.openErr = s.open(context.Background())
		}
		unlock()
		readerResult <- result
	}()
	select {
	case <-readerAtGate:
	case <-time.After(time.Second):
		t.Fatal("stopped invocation did not reach the lifecycle gate")
	}
	pluginLifecycleGate.Unlock()
	writerLocked = false

	var result invocationResult
	select {
	case result = <-readerResult:
	case <-time.After(time.Second):
		t.Fatal("stopped invocation did not return after the lifecycle gate opened")
	}
	if result.running {
		t.Fatal("invocation queued behind shutdown was admitted")
	}
	if result.attemptedOpen || result.openErr != nil {
		t.Fatalf("stopped invocation attempted to reopen SQLite: attempted=%v err=%v", result.attemptedOpen, result.openErr)
	}
	s.mu.Lock()
	db := s.db
	s.mu.Unlock()
	if db != nil {
		t.Fatal("stopped invocation reopened the SQLite handle")
	}
	if _, err := os.Stat(dbPath); !os.IsNotExist(err) {
		t.Fatalf("stopped invocation created database path %q: %v", dbPath, err)
	}
}

func TestQuotaStateContextOutlivesRequestDeadlineButHonorsManagerCancel(t *testing.T) {
	managerCtx, cancelManager := context.WithCancel(context.Background())
	requestCtx, cancelRequest := context.WithTimeout(managerCtx, time.Nanosecond)
	defer cancelRequest()
	<-requestCtx.Done()

	stateCtx, cancelState := newQuotaTriggerStateContext(managerCtx)
	defer cancelState()
	if stateCtx.Err() != nil {
		t.Fatalf("fresh state-write context inherited the exhausted request deadline: %v", stateCtx.Err())
	}
	cancelManager()
	select {
	case <-stateCtx.Done():
		if stateCtx.Err() != context.Canceled {
			t.Fatalf("state-write context error = %v, want context canceled", stateCtx.Err())
		}
	case <-time.After(time.Second):
		t.Fatal("state-write context did not honor manager cancellation")
	}
}

func TestStoreOpenLockHonorsContextDeadline(t *testing.T) {
	s := newTestStore(t)
	s.mu.Lock()
	locked := true
	defer func() {
		if locked {
			s.mu.Unlock()
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	type openResult struct {
		err     error
		elapsed time.Duration
	}
	resultCh := make(chan openResult, 1)
	started := time.Now()
	go func() {
		_, _, err := s.open(ctx)
		resultCh <- openResult{err: err, elapsed: time.Since(started)}
	}()
	var result openResult
	select {
	case result = <-resultCh:
	case <-time.After(250 * time.Millisecond):
		s.mu.Unlock()
		locked = false
		t.Fatal("store.open did not honor context while waiting for mutex")
	}
	s.mu.Unlock()
	locked = false
	if result.err != context.DeadlineExceeded {
		t.Fatalf("store.open error = %v, want context deadline exceeded", result.err)
	}
	if result.elapsed > 250*time.Millisecond {
		t.Fatalf("store.open ignored context while waiting for mutex: %v", result.elapsed)
	}
	dbPath := filepath.Join(os.Getenv("CPA_TOKEN_USAGE_DIR"), "usage.db")
	if _, statErr := os.Stat(dbPath); !os.IsNotExist(statErr) {
		t.Fatalf("timed-out store.open created database path %q: %v", dbPath, statErr)
	}
}

func TestSchedulerStateRefreshManagerIsAsyncFailClosedAndWaitable(t *testing.T) {
	resetSchedulerStateForTest()
	t.Cleanup(resetSchedulerStateForTest)
	globalSchedulerState.setRestricted("codex", false)
	if _, ok := globalSchedulerState.codex(time.Now().Unix()); !ok {
		t.Fatal("test setup did not publish an initialized scheduler snapshot")
	}

	started := make(chan struct{})
	canceled := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseRefresh := func() { releaseOnce.Do(func() { close(release) }) }
	m := &schedulerStateRefreshManager{
		refresh: func(ctx context.Context, _ *store) error {
			close(started)
			<-ctx.Done()
			close(canceled)
			<-release
			return ctx.Err()
		},
	}
	t.Cleanup(func() {
		releaseRefresh()
		m.stop()
	})

	configured := make(chan struct{})
	go func() {
		m.configure(&store{})
		close(configured)
	}()
	select {
	case <-configured:
	case <-time.After(time.Second):
		t.Fatal("scheduler state refresh blocked plugin configuration")
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("scheduler state refresh did not start")
	}
	if _, ok := globalSchedulerState.codex(time.Now().Unix()); ok {
		t.Fatal("scheduler snapshot remained usable while asynchronous initialization was pending")
	}

	stopped := make(chan struct{})
	go func() {
		m.stop()
		close(stopped)
	}()
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("scheduler state refresh was not canceled")
	}
	select {
	case <-stopped:
		t.Fatal("stop returned before the scheduler refresh goroutine exited")
	default:
	}
	releaseRefresh()
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("stop did not wait for scheduler refresh completion")
	}
}

func TestSchedulerStateRefreshManagerRetriesWithBoundedBackoff(t *testing.T) {
	resetSchedulerStateForTest()
	t.Cleanup(resetSchedulerStateForTest)
	var calls atomic.Int32
	succeeded := make(chan struct{})
	m := &schedulerStateRefreshManager{
		retryInitial: 5 * time.Millisecond,
		retryMax:     10 * time.Millisecond,
		refresh: func(_ context.Context, _ *store) error {
			call := calls.Add(1)
			if call < 3 {
				return errors.New("transient scheduler refresh failure")
			}
			globalSchedulerState.setRestricted("codex", false)
			globalSchedulerState.setRestricted("xai", false)
			close(succeeded)
			return nil
		},
	}
	started := time.Now()
	m.configure(&store{})
	t.Cleanup(m.stop)
	select {
	case <-succeeded:
	case <-time.After(time.Second):
		t.Fatal("scheduler refresh did not retry to success")
	}
	if got := calls.Load(); got != 3 {
		t.Fatalf("refresh calls = %d, want 3", got)
	}
	if elapsed := time.Since(started); elapsed < 10*time.Millisecond || elapsed > time.Second {
		t.Fatalf("retry elapsed time = %v, want bounded non-spinning backoff", elapsed)
	}
}

func TestSchedulerStateRefreshQueuesInvalidationDuringActiveRefresh(t *testing.T) {
	resetSchedulerStateForTest()
	t.Cleanup(resetSchedulerStateForTest)
	previousRefresher := globalSchedulerStateRefresher
	var calls atomic.Int32
	firstStarted := make(chan struct{})
	releaseFirst := make(chan struct{})
	secondDone := make(chan struct{})
	var stalePublished atomic.Bool
	m := &schedulerStateRefreshManager{
		retryInitial: time.Millisecond,
		retryMax:     5 * time.Millisecond,
		refresh: func(ctx context.Context, _ *store) error {
			switch calls.Add(1) {
			case 1:
				generation := globalSchedulerState.providerGeneration("codex")
				close(firstStarted)
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-releaseFirst:
				}
				if globalSchedulerState.publishCodexIfGeneration(generation, newCodexSchedulerSnapshot(nil, nil, time.Now().Unix())) {
					stalePublished.Store(true)
				}
				return nil
			case 2:
				now := time.Now().Unix()
				generation := globalSchedulerState.providerGeneration("codex")
				if !globalSchedulerState.publishCodexIfGeneration(generation, newCodexSchedulerSnapshot([]autobanRow{{
					AuthID: "alice", AuthIndex: "alice", Active: true, ResetAt: now + 3600,
				}}, nil, now)) {
					return errors.New("publish refreshed restriction snapshot")
				}
				close(secondDone)
				return nil
			default:
				return errors.New("unexpected extra scheduler refresh")
			}
		},
	}
	globalSchedulerStateRefresher = m
	t.Cleanup(func() {
		m.stop()
		globalSchedulerStateRefresher = previousRefresher
	})
	m.configure(&store{})
	select {
	case <-firstStarted:
	case <-time.After(time.Second):
		t.Fatal("initial scheduler refresh did not start")
	}
	globalSchedulerState.invalidateProvider("codex")
	close(releaseFirst)
	select {
	case <-secondDone:
	case <-time.After(time.Second):
		t.Fatal("invalidation during refresh was not followed by another refresh")
	}
	if stalePublished.Load() {
		t.Fatal("refresh published a snapshot from before provider invalidation")
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("refresh calls = %d, want 2", got)
	}
	snapshot, ok := globalSchedulerState.codex(time.Now().Unix())
	if !ok {
		t.Fatal("follow-up refresh did not publish the new restriction snapshot")
	}
	matched, _ := snapshot.matchIndexes(schedulerAuthCandidate{ID: "alice", Provider: "codex", Attributes: map[string]string{"auth_index": "alice"}})
	if !matched {
		t.Fatal("follow-up refresh did not retain the invalidated provider restriction")
	}
}

func TestSchedulerStateRefreshAllowsInitializationBeyondFiveSeconds(t *testing.T) {
	type refreshResult struct {
		waited  bool
		elapsed time.Duration
		err     error
	}
	resultCh := make(chan refreshResult, 1)
	var longInitializationOnce sync.Once
	m := &schedulerStateRefreshManager{}
	m.refresh = func(ctx context.Context, _ *store) error {
		if _, hasDeadline := ctx.Deadline(); hasDeadline {
			err := errors.New("scheduler initialization inherited a fixed deadline")
			select {
			case resultCh <- refreshResult{err: err}:
			default:
			}
			return err
		}
		result := refreshResult{}
		longInitializationOnce.Do(func() {
			result.waited = true
			started := time.Now()
			timer := time.NewTimer(5100 * time.Millisecond)
			defer timer.Stop()
			select {
			case <-ctx.Done():
				result.err = ctx.Err()
			case <-timer.C:
			}
			result.elapsed = time.Since(started)
		})
		select {
		case resultCh <- result:
		default:
		}
		return result.err
	}
	m.configure(&store{})
	t.Cleanup(m.stop)
	select {
	case result := <-resultCh:
		if result.err != nil {
			t.Fatal(result.err)
		}
		if result.waited && result.elapsed < 5*time.Second {
			t.Fatalf("long initialization completed after only %v", result.elapsed)
		}
	case <-time.After(7 * time.Second):
		t.Fatal("scheduler initialization did not survive beyond five seconds")
	}
}

func TestSummaryPrecomputeStopWaitsForAsyncRefresh(t *testing.T) {
	s := newTestStore(t)
	cfg := normalizePluginConfig(defaultPluginConfig())
	cfg.SummaryPrecomputeEnabled = true
	cfg.SummaryPrecomputeMode = "active_dirty"
	m := &summaryPrecomputeManager{}
	t.Cleanup(m.stop)
	m.configure(cfg)

	m.refreshMu.Lock()
	key := normalizeSummaryCacheKey(summaryCacheKey{Window: "24h", Limit: 50})
	m.refreshAsync(s, cfg, key)

	stopped := make(chan struct{})
	go func() {
		m.stop()
		close(stopped)
	}()
	select {
	case <-stopped:
		m.refreshMu.Unlock()
		t.Fatal("summary precompute stop returned while an async refresh was still running")
	case <-time.After(50 * time.Millisecond):
	}
	m.refreshMu.Unlock()
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("summary precompute stop did not wait for async refresh completion")
	}

	m.mu.Lock()
	refreshing := len(m.refreshing)
	rootCtx := m.ctx
	stopping := m.stopping
	m.mu.Unlock()
	if refreshing != 0 || rootCtx != nil || !stopping {
		t.Fatalf("summary manager retained work after stop: refreshing=%d ctx=%v stopping=%v", refreshing, rootCtx, stopping)
	}

	m.refreshAsync(s, cfg, summaryCacheKey{Window: "7d", Limit: 50})
	m.mu.Lock()
	refreshing = len(m.refreshing)
	m.mu.Unlock()
	if refreshing != 0 {
		t.Fatal("stopped summary manager accepted new async work")
	}

	s.mu.Lock()
	db := s.db
	s.mu.Unlock()
	if db != nil {
		t.Fatal("canceled summary refresh reopened the database after stop")
	}
	dbPath := filepath.Join(os.Getenv("CPA_TOKEN_USAGE_DIR"), "usage.db")
	if _, err := os.Stat(dbPath); !os.IsNotExist(err) {
		t.Fatalf("canceled summary refresh created database path %q: %v", dbPath, err)
	}
}
