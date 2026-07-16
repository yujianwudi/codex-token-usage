package main

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestPluginLifecycleConcurrentReconfigureShutdownCall(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv("CPA_TOKEN_USAGE_DIR", dataDir)
	t.Setenv("CPA_AUTH_DIR", filepath.Join(dataDir, "auth"))
	t.Setenv("CPA_CONFIG_PATH", filepath.Join(dataDir, "missing-config.yaml"))

	previousStore := globalStore
	testStore := &store{}
	globalStore = testStore
	cliproxyPluginShutdownBestEffort()
	t.Cleanup(func() {
		cliproxyPluginShutdownBestEffort()
		globalStore = previousStore
		pluginLifecycleGate.Lock()
		pluginLifecycleStopped = true
		pluginLifecycleGate.Unlock()
	})

	reconfigureRequest := []byte(`{"config_yaml":"model_price_auto_update_enabled: false\nsummary_precompute_enabled: false\nquota_trigger_enabled: false\naccount_protection_enabled: false"}`)
	schedulerRequest := []byte(`{"provider":"mixed","providers":[],"candidates":[]}`)

	for _, tc := range []struct {
		name    string
		method  string
		request []byte
	}{
		{name: "reconfigure", method: "plugin.reconfigure", request: reconfigureRequest},
		{name: "call", method: "scheduler.pick", request: schedulerRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for iteration := 0; iteration < 4; iteration++ {
				runLifecycleInvocationAgainstShutdown(t, iteration, tc.method, tc.request)
			}
		})
	}
}

func runLifecycleInvocationAgainstShutdown(t *testing.T, iteration int, method string, request []byte) {
	t.Helper()
	pluginLifecycleGate.Lock()
	resetPluginOperationContext()
	pluginLifecycleStopped = false
	pluginLifecycleGate.Unlock()
	operationCtx := currentPluginOperationContext()

	entered := make(chan struct{})
	release := make(chan struct{})
	type invocationResult struct {
		running bool
		err     error
	}
	invocationDone := make(chan invocationResult, 1)
	go func() {
		running, err := invokeLifecycleMethodForStress(method, request, entered, release)
		invocationDone <- invocationResult{running: running, err: err}
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		close(release)
		t.Fatalf("iteration %d %s invocation did not enter the lifecycle gate", iteration, method)
	}

	shutdownDone := make(chan struct{})
	go func() {
		cliproxyPluginShutdownBestEffort()
		close(shutdownDone)
	}()
	// Shutdown cancels the operation context immediately before it waits on the
	// lifecycle write gate, so Done is its deterministic entered signal.
	select {
	case <-operationCtx.Done():
	case <-time.After(time.Second):
		close(release)
		t.Fatalf("iteration %d shutdown did not enter while %s held the lifecycle gate", iteration, method)
	}
	select {
	case <-shutdownDone:
		close(release)
		t.Fatalf("iteration %d shutdown returned before active %s invocation released the lifecycle gate", iteration, method)
	default:
	}

	close(release)
	var result invocationResult
	select {
	case result = <-invocationDone:
	case <-time.After(5 * time.Second):
		t.Fatalf("iteration %d %s invocation did not finish", iteration, method)
	}
	if !result.running {
		t.Fatalf("iteration %d active %s invocation was rejected before shutdown", iteration, method)
	}
	if result.err != nil {
		t.Fatalf("iteration %d %s invocation: %v", iteration, method, result.err)
	}
	select {
	case <-shutdownDone:
	case <-time.After(5 * time.Second):
		t.Fatalf("iteration %d shutdown did not finish after %s released the lifecycle gate", iteration, method)
	}

	pluginLifecycleGate.RLock()
	stopped := pluginLifecycleStopped
	pluginLifecycleGate.RUnlock()
	if !stopped {
		t.Fatalf("iteration %d left the plugin running after shutdown raced with %s", iteration, method)
	}
}

func invokeLifecycleMethodForStress(method string, request []byte, entered chan<- struct{}, release <-chan struct{}) (bool, error) {
	unlock, running := beginPluginInvocation(method)
	defer unlock()
	close(entered)
	<-release
	if !running {
		return false, nil
	}
	_, err := handleMethod(method, request)
	return true, err
}

func TestPrivacyQuarantineSnapshotsConcurrentDatabaseIsolation(t *testing.T) {
	storeA, dbA := newQuarantineStressStore(t, "a")
	storeB, dbB := newQuarantineStressStore(t, "b")
	ctx := context.Background()
	if _, err := dbA.Exec(`INSERT INTO store_state(key,value) VALUES('api_key_privacy_quarantine_codex','a-0')`); err != nil {
		t.Fatal(err)
	}
	if _, err := dbB.Exec(`INSERT INTO store_state(key,value) VALUES('api_key_privacy_quarantine_xai','b-0')`); err != nil {
		t.Fatal(err)
	}
	if err := storeA.refreshAPIKeyPrivacyQuarantine(ctx, dbA, storeA.dbPath); err != nil {
		t.Fatal(err)
	}
	if err := storeB.refreshAPIKeyPrivacyQuarantine(ctx, dbB, storeB.dbPath); err != nil {
		t.Fatal(err)
	}

	const iterations = 100
	start := make(chan struct{})
	errs := make(chan error, 4)
	var wg sync.WaitGroup
	wg.Add(4)
	go func() {
		defer wg.Done()
		<-start
		for i := 1; i <= iterations; i++ {
			if _, err := dbA.Exec(`INSERT INTO store_state(key,value) VALUES('api_key_privacy_quarantine_codex',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, fmt.Sprintf("a-%d", i)); err != nil {
				reportStressError(errs, fmt.Errorf("update database A: %w", err))
				return
			}
			if err := storeA.refreshAPIKeyPrivacyQuarantine(ctx, dbA, storeA.dbPath); err != nil {
				reportStressError(errs, fmt.Errorf("refresh store A: %w", err))
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		<-start
		for i := 1; i <= iterations; i++ {
			if _, err := dbB.Exec(`INSERT INTO store_state(key,value) VALUES('api_key_privacy_quarantine_xai',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, fmt.Sprintf("b-%d", i)); err != nil {
				reportStressError(errs, fmt.Errorf("update database B: %w", err))
				return
			}
			if err := storeB.refreshAPIKeyPrivacyQuarantine(ctx, dbB, storeB.dbPath); err != nil {
				reportStressError(errs, fmt.Errorf("refresh store B: %w", err))
				return
			}
		}
	}()
	for reader := 0; reader < 2; reader++ {
		go func() {
			defer wg.Done()
			<-start
			for i := 0; i < iterations*4; i++ {
				if _, ok := storeA.apiKeyPrivacyQuarantineReason(providerCodex); !ok {
					reportStressError(errs, fmt.Errorf("store A lost Codex quarantine"))
					return
				}
				if _, ok := storeA.apiKeyPrivacyQuarantineReason(providerXAI); ok {
					reportStressError(errs, fmt.Errorf("store A inherited xAI quarantine"))
					return
				}
				if _, ok := storeB.apiKeyPrivacyQuarantineReason(providerXAI); !ok {
					reportStressError(errs, fmt.Errorf("store B lost xAI quarantine"))
					return
				}
				if _, ok := storeB.apiKeyPrivacyQuarantineReason(providerCodex); ok {
					reportStressError(errs, fmt.Errorf("store B inherited Codex quarantine"))
					return
				}
			}
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
}

func newQuarantineStressStore(t *testing.T, name string) (*store, *sql.DB) {
	t.Helper()
	path := filepath.Join(t.TempDir(), name+".db")
	db, err := openSQLiteDB(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := initializeSQLiteStore(context.Background(), db, path); err != nil {
		t.Fatal(err)
	}
	return &store{db: db, dbPath: path}, db
}

func TestReservationReleaseConcurrentWithProviderCleanup(t *testing.T) {
	db := newProtectionTestDB(t)
	previousCfg := globalAccountProtection.config()
	cfg := defaultPluginConfig()
	cfg.AccountProtectionEnabled = true
	globalAccountProtection.configure(cfg)
	t.Cleanup(func() { globalAccountProtection.configure(previousCfg) })

	const iterations = 50
	for i := 0; i < iterations; i++ {
		now := time.Now().Unix()
		activeID := fmt.Sprintf("active-%d", i)
		expiredID := fmt.Sprintf("expired-%d", i)
		foreignID := fmt.Sprintf("foreign-%d", i)
		if _, err := db.Exec(`INSERT INTO account_protection_reservations
			(provider,auth_id,auth_index,source,auth_file,plan_type,created_at,expires_at)
			VALUES
			(?,?,?,?,?,'plus',?,?),
			(?,?,?,?,?,'plus',?,?),
			('future-provider',?,?, '', '', 'plus',?,?)`,
			providerCodex, activeID, activeID, "", activeID+".json", now, now+900,
			providerCodex, expiredID, expiredID, "", expiredID+".json", now-900, now-1,
			foreignID, foreignID, now-900, now-1,
		); err != nil {
			t.Fatal(err)
		}

		start := make(chan struct{})
		errs := make(chan error, 1)
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			matched, err := releaseProtectionReservation(context.Background(), db, usageRecord{
				Provider: providerCodex, AuthID: activeID, AuthIndex: activeID, AuthFile: activeID + ".json",
			})
			if err != nil {
				reportStressError(errs, fmt.Errorf("release %s: %w", activeID, err))
				return
			}
			if !matched {
				reportStressError(errs, fmt.Errorf("release %s did not match a reservation", activeID))
			}
		}()
		go func() {
			defer wg.Done()
			<-start
			applyAccountProtectionState(context.Background(), db, nil)
		}()
		close(start)
		wg.Wait()
		close(errs)
		for err := range errs {
			t.Fatal(err)
		}

		var activeRows, expiredRows, foreignRows int
		if err := db.QueryRow(`SELECT COUNT(*) FROM account_protection_reservations WHERE provider=? AND auth_id=?`, providerCodex, activeID).Scan(&activeRows); err != nil {
			t.Fatal(err)
		}
		if err := db.QueryRow(`SELECT COUNT(*) FROM account_protection_reservations WHERE provider=? AND auth_id=?`, providerCodex, expiredID).Scan(&expiredRows); err != nil {
			t.Fatal(err)
		}
		if err := db.QueryRow(`SELECT COUNT(*) FROM account_protection_reservations WHERE provider='future-provider' AND auth_id=?`, foreignID).Scan(&foreignRows); err != nil {
			t.Fatal(err)
		}
		if activeRows != 0 || expiredRows != 0 || foreignRows != 1 {
			t.Fatalf("iteration %d rows active=%d expired=%d foreign=%d, want 0/0/1", i, activeRows, expiredRows, foreignRows)
		}
	}
}

func reportStressError(errs chan<- error, err error) {
	select {
	case errs <- err:
	default:
	}
}
