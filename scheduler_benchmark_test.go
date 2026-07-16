package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func benchmarkSchedulerCandidates(count int) []schedulerAuthCandidate {
	candidates := make([]schedulerAuthCandidate, count)
	for i := range candidates {
		id := fmt.Sprintf("account-%04d", i)
		candidates[i] = schedulerAuthCandidate{
			ID:         id,
			Provider:   "codex",
			Priority:   1,
			Attributes: map[string]string{"auth_index": id, "source": id},
		}
	}
	return candidates
}

func benchmarkMixedSchedulerCandidates(count int) []schedulerAuthCandidate {
	candidates := make([]schedulerAuthCandidate, count)
	for i := range candidates {
		provider := providerCodex
		if i%2 == 1 {
			provider = providerXAI
		}
		id := fmt.Sprintf("%s-account-%04d", provider, i)
		candidates[i] = schedulerAuthCandidate{
			ID:         id,
			Provider:   provider,
			Priority:   1,
			Status:     "active",
			Attributes: map[string]string{"auth_index": id, "source": id},
		}
	}
	return candidates
}

func TestSchedulerPrivacyQuarantineEmptyFastPathAllocations(t *testing.T) {
	previousStore := globalStore
	s := &store{}
	other := &store{}
	other.setAPIKeyPrivacyQuarantineSnapshot(filepath.Join(t.TempDir(), "other.db"), map[string]string{"codex": "other store quarantine"})
	globalStore = s
	t.Cleanup(func() { globalStore = previousStore })
	req := schedulerPickRequest{
		Provider:   "codex",
		Providers:  []string{"codex"},
		Candidates: benchmarkSchedulerCandidates(100),
	}
	var provider, reason string
	var quarantined bool
	allocs := testing.AllocsPerRun(1000, func() {
		provider, reason, quarantined = s.schedulerRequestPrivacyQuarantine(req)
	})
	if quarantined || provider != "" || reason != "" {
		t.Fatalf("empty quarantine returned provider=%q reason=%q quarantined=%v", provider, reason, quarantined)
	}
	if allocs != 0 {
		t.Fatalf("empty quarantine fast path allocated %.2f objects per pick, want 0", allocs)
	}
}

func BenchmarkSchedulerPrivacyQuarantineEmpty100Accounts(b *testing.B) {
	s := &store{}
	req := schedulerPickRequest{
		Provider:   "codex",
		Providers:  []string{"codex"},
		Candidates: benchmarkSchedulerCandidates(100),
	}
	var provider, reason string
	var quarantined bool
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		provider, reason, quarantined = s.schedulerRequestPrivacyQuarantine(req)
	}
	b.StopTimer()
	if quarantined || provider != "" || reason != "" {
		b.Fatalf("empty quarantine returned provider=%q reason=%q quarantined=%v", provider, reason, quarantined)
	}
}

func BenchmarkSchedulerHealthyFastPath100Accounts(b *testing.B) {
	previousStore := globalStore
	previousCfg := globalAccountProtection.config()
	resetSchedulerStateForTest()
	globalSchedulerRotation.reset()
	globalSchedulerState.setRestricted("codex", false)
	cfg := defaultPluginConfig()
	cfg.AccountProtectionEnabled = false
	globalAccountProtection.configure(cfg)
	s := &store{}
	globalStore = s
	b.Cleanup(func() {
		s.close()
		globalStore = previousStore
		globalAccountProtection.configure(previousCfg)
		globalSchedulerRotation.reset()
		resetSchedulerStateForTest()
	})
	req := schedulerPickRequest{Provider: "codex", Model: "gpt-5.5", Candidates: benchmarkSchedulerCandidates(100)}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := s.pickAuthOnce(context.Background(), req); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSchedulerHealthyPersistentRevision100Accounts(b *testing.B) {
	dir := b.TempDir()
	b.Setenv("CPA_TOKEN_USAGE_DIR", dir)
	b.Setenv("CPA_AUTH_DIR", filepath.Join(dir, "auth"))
	b.Setenv("CPA_CONFIG_PATH", filepath.Join(dir, "missing-config.yaml"))
	previousStore := globalStore
	previousCfg := globalAccountProtection.config()
	resetSchedulerStateForTest()
	globalSchedulerRotation.reset()
	cfg := defaultPluginConfig()
	cfg.AccountProtectionEnabled = false
	globalAccountProtection.configure(cfg)
	s := &store{}
	globalStore = s
	b.Cleanup(func() {
		s.close()
		globalStore = previousStore
		globalAccountProtection.configure(previousCfg)
		globalSchedulerRotation.reset()
		resetSchedulerStateForTest()
	})
	if _, _, err := s.open(context.Background()); err != nil {
		b.Fatal(err)
	}
	now := time.Now().Unix()
	if !globalSchedulerState.publishCodexIfGeneration(globalSchedulerState.providerGeneration(providerCodex), newCodexSchedulerSnapshot(nil, nil, now)) {
		b.Fatal("failed to publish Codex benchmark snapshot")
	}
	req := schedulerPickRequest{Provider: providerCodex, Providers: []string{providerCodex}, Model: "gpt-5.5", Candidates: benchmarkSchedulerCandidates(100)}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := s.pickAuthOnce(context.Background(), req); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSchedulerRestrictedSnapshot100Accounts(b *testing.B) {
	dir := b.TempDir()
	b.Setenv("CPA_TOKEN_USAGE_DIR", dir)
	b.Setenv("CPA_AUTH_DIR", filepath.Join(dir, "auth"))
	previousStore := globalStore
	resetSchedulerStateForTest()
	globalSchedulerRotation.reset()
	previousCfg := globalAccountProtection.config()
	cfg := defaultPluginConfig()
	cfg.AccountProtectionEnabled = false
	globalAccountProtection.configure(cfg)
	s := &store{}
	globalStore = s
	b.Cleanup(func() {
		s.close()
		globalStore = previousStore
		globalAccountProtection.configure(previousCfg)
		globalSchedulerRotation.reset()
		resetSchedulerStateForTest()
	})
	db, _, err := s.open(context.Background())
	if err != nil {
		b.Fatal(err)
	}
	now := time.Now().Unix()
	if _, err := db.Exec(`INSERT INTO autoban_bans
		(auth_id, auth_index, provider, window, reason, banned_at, reset_at, active)
		VALUES ('account-0000', 'account-0000', 'codex', '5h', 'benchmark', ?, ?, 1)`, now, now+3600); err != nil {
		b.Fatal(err)
	}
	if err := globalSchedulerState.refresh(context.Background(), db); err != nil {
		b.Fatal(err)
	}
	globalSchedulerState.mu.Lock()
	globalSchedulerState.codexSnapshot.expiresAt = time.Now().Add(time.Hour)
	globalSchedulerState.mu.Unlock()
	s.close()
	req := schedulerPickRequest{Provider: "codex", Model: "gpt-5.5", Candidates: benchmarkSchedulerCandidates(100)}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp, err := s.pickAuthOnce(context.Background(), req)
		if err != nil {
			b.Fatal(err)
		}
		if !resp.Handled {
			b.Fatal("cached restriction was not applied")
		}
	}
}

func BenchmarkSchedulerMixedFiltering100Accounts(b *testing.B) {
	previousStore := globalStore
	previousCfg := globalAccountProtection.config()
	resetSchedulerStateForTest()
	globalSchedulerRotation.reset()
	cfg := defaultPluginConfig()
	cfg.AccountProtectionEnabled = false
	globalAccountProtection.configure(cfg)
	s := &store{}
	globalStore = s
	b.Cleanup(func() {
		s.close()
		globalStore = previousStore
		globalAccountProtection.configure(previousCfg)
		globalSchedulerRotation.reset()
		resetSchedulerStateForTest()
	})
	now := time.Now().Unix()
	blocked := autobanRow{AuthID: "codex-account-0000", AuthIndex: "codex-account-0000", Provider: providerCodex, Active: true, ResetAt: now + 3600}
	if !globalSchedulerState.publishCodexIfGeneration(globalSchedulerState.providerGeneration(providerCodex), newCodexSchedulerSnapshot([]autobanRow{blocked}, nil, now)) {
		b.Fatal("failed to publish Codex benchmark snapshot")
	}
	if !globalSchedulerState.publishXAIIfGeneration(globalSchedulerState.providerGeneration(providerXAI), newXAISchedulerSnapshot(nil, now)) {
		b.Fatal("failed to publish xAI benchmark snapshot")
	}
	req := schedulerPickRequest{Provider: "mixed", Providers: []string{providerCodex, providerXAI}, Model: "shared-model", Candidates: benchmarkMixedSchedulerCandidates(100)}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp, err := s.pickAuthOnce(context.Background(), req)
		if err != nil || !resp.Handled || resp.AuthID == blocked.AuthID {
			b.Fatalf("response=%+v err=%v", resp, err)
		}
	}
}

func BenchmarkSchedulerProviderQuarantineFiltering100Accounts(b *testing.B) {
	previousStore := globalStore
	previousCfg := globalAccountProtection.config()
	resetSchedulerStateForTest()
	globalSchedulerRotation.reset()
	cfg := defaultPluginConfig()
	cfg.AccountProtectionEnabled = false
	globalAccountProtection.configure(cfg)
	s := &store{}
	s.setAPIKeyPrivacyQuarantineSnapshot("", map[string]string{providerCodex: "legacy identity requires recovery"})
	globalStore = s
	b.Cleanup(func() {
		s.close()
		globalStore = previousStore
		globalAccountProtection.configure(previousCfg)
		globalSchedulerRotation.reset()
		resetSchedulerStateForTest()
	})
	now := time.Now().Unix()
	if !globalSchedulerState.publishXAIIfGeneration(globalSchedulerState.providerGeneration(providerXAI), newXAISchedulerSnapshot(nil, now)) {
		b.Fatal("failed to publish xAI benchmark snapshot")
	}
	req := schedulerPickRequest{Provider: "mixed", Providers: []string{providerCodex, providerXAI}, Model: "shared-model", Candidates: benchmarkMixedSchedulerCandidates(100)}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp, err := s.pickAuthOnce(context.Background(), req)
		if err != nil || !resp.Handled || !strings.HasPrefix(resp.AuthID, providerXAI+"-") {
			b.Fatalf("response=%+v err=%v", resp, err)
		}
	}
}

func BenchmarkProtectedPick100Accounts50kEvents(b *testing.B) {
	dir := b.TempDir()
	authDir := filepath.Join(dir, "auth")
	if err := os.MkdirAll(authDir, 0o755); err != nil {
		b.Fatal(err)
	}
	b.Setenv("CPA_TOKEN_USAGE_DIR", dir)
	b.Setenv("CPA_AUTH_DIR", authDir)
	s := &store{}
	previousCfg := globalAccountProtection.config()
	globalSchedulerRotation.reset()
	b.Cleanup(func() {
		globalAccountProtection.configure(previousCfg)
		s.close()
		globalSchedulerRotation.reset()
	})
	db, _, err := s.open(context.Background())
	if err != nil {
		b.Fatal(err)
	}
	cfg := defaultPluginConfig()
	cfg.AccountProtectionEnabled = true
	// Reservations are part of the measured write path, but this benchmark is
	// intended to run indefinitely without turning its own samples into an
	// artificial hard-limit saturation test.
	cfg.AccountProtectionReservationTTLSeconds = 0
	candidates := benchmarkSchedulerCandidates(100)
	tx, err := db.Begin()
	if err != nil {
		b.Fatal(err)
	}
	stmt, err := tx.Prepare(`INSERT INTO usage_events
		(requested_at, provider, auth_id, auth_index, source, total_tokens)
		VALUES (?, 'codex', ?, ?, ?, ?)`)
	if err != nil {
		b.Fatal(err)
	}
	now := time.Now().Unix()
	eventAgeSpan := int64(cfg.AccountProtectionTokenWindowSeconds / 2)
	if eventAgeSpan < 1 {
		eventAgeSpan = 1
	}
	for i := 0; i < 50_000; i++ {
		account := candidates[i%len(candidates)].ID
		// Keep every fixture well inside the configured token window. Events on
		// the exact lower boundary become nondeterministic if wall-clock seconds
		// advance while the 50k rows are inserted and the async cache is warmed.
		if _, err := stmt.Exec(now-int64(i)%eventAgeSpan, account, account, account, 1000); err != nil {
			b.Fatal(err)
		}
	}
	if err := stmt.Close(); err != nil {
		b.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		b.Fatal(err)
	}
	globalAccountProtection.configure(cfg)
	usageSince := now - int64(cfg.AccountProtectionTokenWindowSeconds)
	if _, err := globalAccountProtection.loadUsageIndex(context.Background(), db, usageSince); err != nil {
		b.Fatal(err)
	}
	usageDeadline := time.Now().Add(10 * time.Second)
	for {
		usage, fresh, _ := globalAccountProtection.cachedUsageIndex(db, usageSince, time.Now())
		if fresh && usage != nil && len(usage.samples) == len(candidates) {
			var tokens int64
			for _, sample := range usage.samples {
				tokens += sample.Tokens
			}
			if tokens != 50_000*1000 {
				b.Fatalf("warmed usage index tokens=%d, want %d", tokens, 50_000*1000)
			}
			break
		}
		if time.Now().After(usageDeadline) {
			b.Fatal("background 50k-event usage index did not become ready before benchmark timing")
		}
		time.Sleep(5 * time.Millisecond)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := s.pickProtectedAuth(context.Background(), db, candidates, cfg, "benchmark"); err != nil {
			b.Fatal(err)
		}
	}
}
