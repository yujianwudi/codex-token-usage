package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
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
		s.close()
		globalAccountProtection.configure(previousCfg)
		globalSchedulerRotation.reset()
	})
	db, _, err := s.open(context.Background())
	if err != nil {
		b.Fatal(err)
	}
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
	for i := 0; i < 50_000; i++ {
		account := candidates[i%len(candidates)].ID
		if _, err := stmt.Exec(now-int64(i%300), account, account, account, 1000); err != nil {
			b.Fatal(err)
		}
	}
	if err := stmt.Close(); err != nil {
		b.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		b.Fatal(err)
	}
	cfg := defaultPluginConfig()
	cfg.AccountProtectionEnabled = true
	// Reservations are part of the measured write path, but this benchmark is
	// intended to run indefinitely without turning its own samples into an
	// artificial hard-limit saturation test.
	cfg.AccountProtectionReservationTTLSeconds = 0
	globalAccountProtection.configure(cfg)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := s.pickProtectedAuth(context.Background(), db, candidates, cfg, "benchmark"); err != nil {
			b.Fatal(err)
		}
	}
}
