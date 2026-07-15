package main

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"
)

func setupMixedSchedulerTest(t *testing.T, s *store, protection bool) {
	t.Helper()
	previousStore := globalStore
	previousCfg := globalAccountProtection.config()
	resetSchedulerStateForTest()
	globalSchedulerRotation.reset()
	globalStore = s
	cfg := defaultPluginConfig()
	cfg.AccountProtectionEnabled = protection
	globalAccountProtection.configure(cfg)
	t.Cleanup(func() {
		globalAccountProtection.configure(previousCfg)
		globalStore = previousStore
		resetSchedulerStateForTest()
		globalSchedulerRotation.reset()
	})
}

func publishCodexSchedulerTestSnapshot(t *testing.T, bans []autobanRow, now int64) {
	t.Helper()
	generation := globalSchedulerState.providerGeneration("codex")
	if !globalSchedulerState.publishCodexIfGeneration(generation, newCodexSchedulerSnapshot(bans, nil, now)) {
		t.Fatal("failed to publish Codex scheduler snapshot")
	}
}

func publishXAISchedulerTestSnapshot(t *testing.T, states []xaiAccountStateRow, now int64) {
	t.Helper()
	generation := globalSchedulerState.providerGeneration("xai")
	if !globalSchedulerState.publishXAIIfGeneration(generation, newXAISchedulerSnapshot(states, now)) {
		t.Fatal("failed to publish xAI scheduler snapshot")
	}
}

func TestMixedSchedulerRequestSingleProviderHasNoAllocations(t *testing.T) {
	req := schedulerPickRequest{
		Providers:  []string{"codex"},
		Candidates: []schedulerAuthCandidate{{ID: "codex-ready", Provider: "codex"}},
	}
	mixed := false
	if allocations := testing.AllocsPerRun(1000, func() {
		mixed = isMixedSchedulerRequest(req)
	}); allocations != 0 {
		t.Fatalf("allocations=%v, want 0", allocations)
	}
	if mixed {
		t.Fatal("single-provider request classified as mixed")
	}
}

func BenchmarkIsMixedSchedulerRequestSingleProvider(b *testing.B) {
	req := schedulerPickRequest{
		Providers:  []string{"codex"},
		Candidates: []schedulerAuthCandidate{{ID: "codex-ready", Provider: "codex"}},
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = isMixedSchedulerRequest(req)
	}
}

func TestMixedSchedulerFiltersCodexAndXAIRestrictions(t *testing.T) {
	s := &store{}
	setupMixedSchedulerTest(t, s, false)
	now := time.Now().Unix()
	publishCodexSchedulerTestSnapshot(t, []autobanRow{{
		AuthID: "codex-blocked", AuthIndex: "codex-blocked", Provider: "codex", Active: true, ResetAt: now + 3600,
	}}, now)
	publishXAISchedulerTestSnapshot(t, []xaiAccountStateRow{{
		StateKey: "xai-blocked", AuthID: "xai-blocked", AuthIndex: "xai-blocked", Provider: "xai", State: xaiStateRateLimited, Active: true, ResetAt: now + 3600,
	}}, now)
	req := schedulerPickRequest{
		Providers: []string{"codex", "xai"},
		Model:     "shared-model",
		Candidates: []schedulerAuthCandidate{
			{ID: "codex-blocked", Provider: "codex", Priority: 10, Attributes: map[string]string{"auth_index": "codex-blocked"}},
			{ID: "codex-ready", Provider: "codex", Priority: 10, Attributes: map[string]string{"auth_index": "codex-ready"}},
			{ID: "xai-blocked", Provider: "xai", Priority: 10, Attributes: map[string]string{"auth_index": "xai-blocked"}},
			{ID: "xai-ready", Provider: "xai", Priority: 10, Attributes: map[string]string{"auth_index": "xai-ready"}},
		},
	}
	seen := map[string]bool{}
	for i := 0; i < 4; i++ {
		resp, err := s.pickAuthOnce(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}
		if !resp.Handled || resp.AuthID == "codex-blocked" || resp.AuthID == "xai-blocked" {
			t.Fatalf("response=%+v, want a handled ready candidate", resp)
		}
		seen[resp.AuthID] = true
	}
	if !seen["codex-ready"] || !seen["xai-ready"] {
		t.Fatalf("ready candidates seen=%v, want both providers retained in rotation", seen)
	}
}

func TestMixedSchedulerFiltersCodexWithOtherProvider(t *testing.T) {
	s := &store{}
	setupMixedSchedulerTest(t, s, false)
	now := time.Now().Unix()
	publishCodexSchedulerTestSnapshot(t, []autobanRow{{
		AuthID: "codex-blocked", AuthIndex: "codex-blocked", Provider: "codex", Active: true, ResetAt: now + 3600,
	}}, now)
	resp, err := s.pickAuthOnce(context.Background(), schedulerPickRequest{
		Providers: []string{"codex", "gemini"},
		Candidates: []schedulerAuthCandidate{
			{ID: "codex-blocked", Provider: "codex", Priority: 1, Attributes: map[string]string{"auth_index": "codex-blocked"}},
			{ID: "gemini-ready", Provider: "gemini", Priority: 1},
		},
	})
	if err != nil || !resp.Handled || resp.AuthID != "gemini-ready" {
		t.Fatalf("response=%+v err=%v, want healthy non-Codex candidate", resp, err)
	}
}

func TestMixedSchedulerFiltersXAIWithOtherProvider(t *testing.T) {
	s := &store{}
	setupMixedSchedulerTest(t, s, false)
	now := time.Now().Unix()
	publishXAISchedulerTestSnapshot(t, []xaiAccountStateRow{{
		StateKey: "xai-blocked", AuthID: "xai-blocked", AuthIndex: "xai-blocked", Provider: "xai", State: xaiStateForbidden, Active: true,
	}}, now)
	resp, err := s.pickAuthOnce(context.Background(), schedulerPickRequest{
		Providers: []string{"xai", "gemini"},
		Candidates: []schedulerAuthCandidate{
			{ID: "xai-blocked", Provider: "xai", Priority: 1, Attributes: map[string]string{"auth_index": "xai-blocked"}},
			{ID: "gemini-ready", Provider: "gemini", Priority: 1},
		},
	})
	if err != nil || !resp.Handled || resp.AuthID != "gemini-ready" {
		t.Fatalf("response=%+v err=%v, want healthy non-xAI candidate", resp, err)
	}
}

func TestMixedSchedulerDelegatesWhenNoCandidateIsRestricted(t *testing.T) {
	s := &store{}
	setupMixedSchedulerTest(t, s, false)
	globalSchedulerState.setRestricted("codex", false)
	globalSchedulerState.setRestricted("xai", false)
	resp, err := s.pickAuthOnce(context.Background(), schedulerPickRequest{
		Providers: []string{"codex", "xai", "gemini"},
		Candidates: []schedulerAuthCandidate{
			{ID: "codex-ready", Provider: "codex", Priority: 1},
			{ID: "xai-ready", Provider: "xai", Priority: 1},
			{ID: "gemini-ready", Provider: "gemini", Priority: 1},
		},
	})
	if err != nil || resp.Handled {
		t.Fatalf("response=%+v err=%v, want native mixed scheduler delegation", resp, err)
	}
	if s.db != nil {
		t.Fatal("healthy mixed fast path opened SQLite")
	}
}

func TestMixedSchedulerExpiredSnapshotUsesStaleWithoutOpeningSQLite(t *testing.T) {
	s := &store{}
	setupMixedSchedulerTest(t, s, false)
	now := time.Now().Unix()
	publishCodexSchedulerTestSnapshot(t, []autobanRow{{
		AuthID: "codex-blocked", AuthIndex: "codex-blocked", Provider: "codex", Active: true, ResetAt: now + 3600,
	}}, now)
	publishXAISchedulerTestSnapshot(t, nil, now)
	globalSchedulerState.mu.Lock()
	globalSchedulerState.codexSnapshot.expiresAt = time.Now().Add(-time.Second)
	globalSchedulerState.xaiSnapshot.expiresAt = time.Now().Add(-time.Second)
	globalSchedulerState.mu.Unlock()

	resp, err := s.pickAuthOnce(context.Background(), schedulerPickRequest{
		Providers: []string{"codex", "xai", "gemini"},
		Candidates: []schedulerAuthCandidate{
			{ID: "codex-blocked", Provider: "codex", Priority: 1, Attributes: map[string]string{"auth_index": "codex-blocked"}},
			{ID: "gemini-ready", Provider: "gemini", Priority: 1},
		},
	})
	if err != nil || !resp.Handled || resp.AuthID != "gemini-ready" {
		t.Fatalf("response=%+v err=%v, want stale mixed filtering to retain the healthy provider", resp, err)
	}
	if s.db != nil {
		t.Fatal("expired mixed scheduler snapshot opened SQLite")
	}
}

func TestMixedSchedulerFilteringStillHonorsHighestPriority(t *testing.T) {
	s := &store{}
	setupMixedSchedulerTest(t, s, false)
	now := time.Now().Unix()
	publishCodexSchedulerTestSnapshot(t, []autobanRow{{
		AuthID: "codex-blocked", AuthIndex: "codex-blocked", Provider: "codex", Active: true, ResetAt: now + 3600,
	}}, now)
	publishXAISchedulerTestSnapshot(t, nil, now)
	resp, err := s.pickAuthOnce(context.Background(), schedulerPickRequest{
		Providers: []string{"codex", "xai", "gemini"},
		Candidates: []schedulerAuthCandidate{
			{ID: "codex-blocked", Provider: "codex", Priority: 1, Attributes: map[string]string{"auth_index": "codex-blocked"}},
			{ID: "gemini-low", Provider: "gemini", Priority: 1},
			{ID: "xai-high", Provider: "xai", Priority: 10},
		},
	})
	if err != nil || !resp.Handled || resp.AuthID != "xai-high" {
		t.Fatalf("response=%+v err=%v, want the remaining highest-priority candidate", resp, err)
	}
}

func TestMixedSchedulerFailsClosedWhenEveryCandidateIsRestricted(t *testing.T) {
	s := &store{}
	setupMixedSchedulerTest(t, s, false)
	now := time.Now().Unix()
	publishCodexSchedulerTestSnapshot(t, []autobanRow{{
		AuthID: "codex-blocked", AuthIndex: "codex-blocked", Provider: "codex", Active: true, ResetAt: now + 3600,
	}}, now)
	publishXAISchedulerTestSnapshot(t, []xaiAccountStateRow{{
		StateKey: "xai-blocked", AuthID: "xai-blocked", AuthIndex: "xai-blocked", Provider: "xai", State: xaiStateRateLimited, Active: true, ResetAt: now + 60,
	}}, now)
	_, err := s.pickAuthOnce(context.Background(), schedulerPickRequest{
		Providers: []string{"codex", "xai"},
		Candidates: []schedulerAuthCandidate{
			{ID: "codex-blocked", Provider: "codex", Priority: 1, Attributes: map[string]string{"auth_index": "codex-blocked"}},
			{ID: "xai-blocked", Provider: "xai", Priority: 1, Attributes: map[string]string{"auth_index": "xai-blocked"}},
		},
	})
	var reject *schedulerRejectError
	if !errors.As(err, &reject) || reject.Code != "auth_unavailable" || reject.HTTPStatus != http.StatusServiceUnavailable {
		t.Fatalf("error=%v, want fail-closed auth_unavailable 503", err)
	}
}

func TestMixedSchedulerProtectsOnlySelectedCodexSlots(t *testing.T) {
	s := newTestStore(t)
	setupMixedSchedulerTest(t, s, true)
	globalSchedulerState.setRestricted("codex", false)
	globalSchedulerState.setRestricted("xai", false)
	req := schedulerPickRequest{
		Providers: []string{"codex", "gemini"},
		Model:     "shared-model",
		Candidates: []schedulerAuthCandidate{
			{ID: "a-gemini", Provider: "gemini", Priority: 1},
			{ID: "b-codex", Provider: "codex", Priority: 1, Attributes: map[string]string{"auth_index": "b-codex"}},
		},
	}
	first, err := s.pickAuthOnce(context.Background(), req)
	if err != nil || first.AuthID != "a-gemini" || !first.Handled {
		t.Fatalf("first response=%+v err=%v, want non-Codex mixed slot", first, err)
	}
	if s.db != nil {
		t.Fatal("non-Codex mixed slot created a Codex protection reservation")
	}
	second, err := s.pickAuthOnce(context.Background(), req)
	if err != nil || second.AuthID != "b-codex" || !second.Handled {
		t.Fatalf("second response=%+v err=%v, want protected Codex mixed slot", second, err)
	}
	db, _, err := s.open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var reservations int
	if err := db.QueryRow(`SELECT COUNT(*) FROM account_protection_reservations`).Scan(&reservations); err != nil {
		t.Fatal(err)
	}
	if reservations != 1 {
		t.Fatalf("reservations=%d, want exactly one selected Codex reservation", reservations)
	}
}
