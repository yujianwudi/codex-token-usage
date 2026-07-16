package main

import (
	"context"
	"errors"
	"net/http"
	"reflect"
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

func TestMixedSchedulerFallsBackWhenProtectedCodexIsSaturated(t *testing.T) {
	s := newTestStore(t)
	setupMixedSchedulerTest(t, s, true)
	cfg := defaultPluginConfig()
	cfg.AccountProtectionEnabled = true
	cfg.AccountProtectionFreeConcurrency = 1
	globalAccountProtection.configure(cfg)
	globalSchedulerState.setRestricted("codex", false)
	globalSchedulerState.setRestricted("xai", false)

	db, _, err := s.open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	if _, err := db.Exec(`INSERT INTO account_protection_reservations
		(auth_id, auth_index, source, plan_type, created_at, expires_at)
		VALUES ('a-codex', 'a-codex', '', 'free', ?, ?)`, now, now+900); err != nil {
		t.Fatal(err)
	}
	req := schedulerPickRequest{
		Providers: []string{"codex", "gemini"},
		Model:     "shared-model",
		Candidates: []schedulerAuthCandidate{
			protectionTestCandidate("a-codex", "free", 10),
			{ID: "b-gemini", Provider: "gemini", Priority: 1},
		},
		Options: schedulerOptions{Headers: map[string][]string{"Session-Id": {"mixed-saturated-session"}}},
	}
	for i := 0; i < 2; i++ {
		resp, err := s.pickAuthOnce(context.Background(), req)
		if err != nil || !resp.Handled || resp.AuthID != "b-gemini" {
			t.Fatalf("pick %d response=%+v err=%v, want non-Codex fallback", i, resp, err)
		}
	}
	var reservations int
	if err := db.QueryRow(`SELECT COUNT(*) FROM account_protection_reservations`).Scan(&reservations); err != nil {
		t.Fatal(err)
	}
	if reservations != 1 {
		t.Fatalf("reservations=%d, want the saturated Codex reservation unchanged", reservations)
	}
}

func TestMixedSchedulerFallsBackToLowerPriorityProtectedCodex(t *testing.T) {
	s := newTestStore(t)
	setupMixedSchedulerTest(t, s, true)
	cfg := defaultPluginConfig()
	cfg.AccountProtectionEnabled = true
	cfg.AccountProtectionFreeConcurrency = 1
	globalAccountProtection.configure(cfg)
	globalSchedulerState.setRestricted(providerCodex, false)
	globalSchedulerState.setRestricted(providerXAI, false)

	db, _, err := s.open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	if _, err := db.Exec(`INSERT INTO account_protection_reservations
		(provider,auth_id,auth_index,source,plan_type,created_at,expires_at)
		VALUES ('codex','high-codex','high-codex','','free',?,?)`, now, now+900); err != nil {
		t.Fatal(err)
	}
	resp, err := s.pickAuthOnce(context.Background(), schedulerPickRequest{
		Provider:  "mixed",
		Providers: []string{providerCodex, providerXAI},
		Candidates: []schedulerAuthCandidate{
			protectionTestCandidate("high-codex", "free", 10),
			protectionTestCandidate("low-codex", "free", 1),
		},
	})
	if err != nil || !resp.Handled || resp.AuthID != "low-codex" {
		t.Fatalf("response=%+v err=%v, want lower-priority protected Codex fallback", resp, err)
	}
	var reservations int
	if err := db.QueryRow(`SELECT COUNT(*) FROM account_protection_reservations WHERE provider='codex'`).Scan(&reservations); err != nil {
		t.Fatal(err)
	}
	if reservations != 2 {
		t.Fatalf("Codex reservations=%d, want existing high tier plus reserved lower tier", reservations)
	}
}

func TestMixedSchedulerUsesSamePriorityHealthyProviderBeforeLowerTier(t *testing.T) {
	s := newTestStore(t)
	setupMixedSchedulerTest(t, s, true)
	cfg := defaultPluginConfig()
	cfg.AccountProtectionEnabled = true
	cfg.AccountProtectionFreeConcurrency = 1
	globalAccountProtection.configure(cfg)
	globalSchedulerState.setRestricted(providerCodex, false)
	globalSchedulerState.setRestricted(providerXAI, false)

	db, _, err := s.open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	if _, err := db.Exec(`INSERT INTO account_protection_reservations
		(provider,auth_id,auth_index,source,plan_type,created_at,expires_at)
		VALUES ('codex','a-codex','a-codex','','free',?,?)`, now, now+900); err != nil {
		t.Fatal(err)
	}
	resp, err := s.pickAuthOnce(context.Background(), schedulerPickRequest{
		Provider:  "mixed",
		Providers: []string{providerCodex, providerXAI, "gemini"},
		Candidates: []schedulerAuthCandidate{
			protectionTestCandidate("a-codex", "free", 10),
			{ID: "b-xai", Provider: providerXAI, Priority: 10, Status: "active"},
			{ID: "c-gemini", Provider: "gemini", Priority: 1, Status: "active"},
		},
	})
	if err != nil || !resp.Handled || resp.AuthID != "b-xai" {
		t.Fatalf("response=%+v err=%v, want same-priority healthy xAI before lower tier", resp, err)
	}
	var reservations int
	if err := db.QueryRow(`SELECT COUNT(*) FROM account_protection_reservations WHERE provider='codex'`).Scan(&reservations); err != nil {
		t.Fatal(err)
	}
	if reservations != 1 {
		t.Fatalf("Codex reservations=%d, want saturated reservation unchanged", reservations)
	}
}

func TestMixedSchedulerQuarantineKeepsHealthyProviderAvailable(t *testing.T) {
	s := &store{}
	setupMixedSchedulerTest(t, s, false)
	now := time.Now().Unix()
	publishCodexSchedulerTestSnapshot(t, nil, now)
	publishXAISchedulerTestSnapshot(t, nil, now)
	s.setAPIKeyPrivacyQuarantineSnapshot("", map[string]string{"codex": "legacy identity requires recovery"})

	resp, err := s.pickAuthOnce(context.Background(), schedulerPickRequest{
		Provider:  "mixed",
		Providers: []string{"codex", "xai"},
		Candidates: []schedulerAuthCandidate{
			{ID: "codex-quarantined", Provider: "codex", Priority: 10, Status: "active"},
			{ID: "xai-ready", Provider: "xai", Priority: 1, Status: "active"},
		},
	})
	if err != nil || !resp.Handled || resp.AuthID != "xai-ready" {
		t.Fatalf("response=%+v err=%v, want healthy xAI fallback", resp, err)
	}
}

func TestMixedSchedulerXAIQuarantineSelectsAndReservesCodex(t *testing.T) {
	s := newTestStore(t)
	setupMixedSchedulerTest(t, s, true)
	now := time.Now().Unix()
	publishCodexSchedulerTestSnapshot(t, nil, now)
	publishXAISchedulerTestSnapshot(t, nil, now)
	s.setAPIKeyPrivacyQuarantineSnapshot("", map[string]string{"xai": "legacy identity requires recovery"})

	resp, err := s.pickAuthOnce(context.Background(), schedulerPickRequest{
		Provider:  "mixed",
		Providers: []string{"codex", "xai"},
		Candidates: []schedulerAuthCandidate{
			{ID: "xai-quarantined", Provider: "xai", Priority: 10, Status: "active"},
			protectionTestCandidate("codex-ready", "free", 1),
		},
	})
	if err != nil || !resp.Handled || resp.AuthID != "codex-ready" {
		t.Fatalf("response=%+v err=%v, want protected Codex fallback", resp, err)
	}
	db, _, err := s.open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var reservations int
	if err := db.QueryRow(`SELECT COUNT(*) FROM account_protection_reservations WHERE provider='codex'`).Scan(&reservations); err != nil {
		t.Fatal(err)
	}
	if reservations != 1 {
		t.Fatalf("Codex reservations=%d, want 1", reservations)
	}
}

func TestMixedSchedulerBothProvidersQuarantinedFailsClosed(t *testing.T) {
	s := &store{}
	setupMixedSchedulerTest(t, s, false)
	s.setAPIKeyPrivacyQuarantineSnapshot("", map[string]string{
		"codex": "legacy codex identity requires recovery",
		"xai":   "legacy xai identity requires recovery",
	})
	_, err := s.pickAuthOnce(context.Background(), schedulerPickRequest{
		Provider:  "mixed",
		Providers: []string{"xai", "codex"},
		Candidates: []schedulerAuthCandidate{
			{ID: "codex", Provider: "codex", Status: "active"},
			{ID: "xai", Provider: "xai", Status: "active"},
		},
	})
	var reject *schedulerRejectError
	if !errors.As(err, &reject) || reject.Code != "privacy_quarantine" || reject.HTTPStatus != http.StatusServiceUnavailable {
		t.Fatalf("error=%#v / %v, want privacy quarantine 503", reject, err)
	}
}

func TestMixedSchedulerAffinityRebindsAfterProviderQuarantine(t *testing.T) {
	s := newTestStore(t)
	setupMixedSchedulerTest(t, s, true)
	now := time.Now().Unix()
	publishCodexSchedulerTestSnapshot(t, nil, now)
	publishXAISchedulerTestSnapshot(t, nil, now)
	req := schedulerPickRequest{
		Provider:  "mixed",
		Providers: []string{"codex", "xai"},
		Options:   schedulerOptions{Headers: map[string][]string{"Session-Id": {"quarantine-rebind"}}},
		Candidates: []schedulerAuthCandidate{
			protectionTestCandidate("a-codex", "free", 1),
			{ID: "b-xai", Provider: "xai", Priority: 1, Status: "active"},
		},
	}
	first, err := s.pickAuthOnce(context.Background(), req)
	if err != nil || !first.Handled || first.AuthID != "a-codex" {
		t.Fatalf("first response=%+v err=%v, want initial Codex affinity", first, err)
	}
	s.setAPIKeyPrivacyQuarantineSnapshot("", map[string]string{"codex": "legacy identity requires recovery"})
	second, err := s.pickAuthOnce(context.Background(), req)
	if err != nil || !second.Handled || second.AuthID != "b-xai" {
		t.Fatalf("second response=%+v err=%v, want affinity rebound to healthy xAI", second, err)
	}
}

func TestMixedSchedulerQuarantineAndRestrictionKeepThirdProviderAvailable(t *testing.T) {
	s := &store{}
	setupMixedSchedulerTest(t, s, false)
	now := time.Now().Unix()
	publishCodexSchedulerTestSnapshot(t, nil, now)
	publishXAISchedulerTestSnapshot(t, []xaiAccountStateRow{{
		StateKey: "xai-blocked", AuthID: "xai-blocked", AuthIndex: "xai-blocked", Provider: "xai", State: xaiStateForbidden, Active: true,
	}}, now)
	s.setAPIKeyPrivacyQuarantineSnapshot("", map[string]string{"codex": "legacy identity requires recovery"})

	resp, err := s.pickAuthOnce(context.Background(), schedulerPickRequest{
		Provider:  "mixed",
		Providers: []string{"codex", "xai", "gemini"},
		Candidates: []schedulerAuthCandidate{
			{ID: "codex-quarantined", Provider: "codex", Priority: 10, Status: "active"},
			{ID: "xai-blocked", Provider: "xai", Priority: 10, Status: "active", Attributes: map[string]string{"auth_index": "xai-blocked"}},
			{ID: "gemini-ready", Provider: "gemini", Priority: 1, Status: "active"},
		},
	})
	if err != nil || !resp.Handled || resp.AuthID != "gemini-ready" {
		t.Fatalf("response=%+v err=%v, want healthy third-provider fallback", resp, err)
	}
}

func TestMixedSchedulerAllUnavailableUsesStablePrivacyPriority(t *testing.T) {
	s := &store{}
	setupMixedSchedulerTest(t, s, false)
	now := time.Now().Unix()
	publishCodexSchedulerTestSnapshot(t, nil, now)
	publishXAISchedulerTestSnapshot(t, []xaiAccountStateRow{{
		StateKey: "xai-blocked", AuthID: "xai-blocked", AuthIndex: "xai-blocked", Provider: "xai", State: xaiStateUnauthorized, Active: true,
	}}, now)
	s.setAPIKeyPrivacyQuarantineSnapshot("", map[string]string{"codex": "legacy identity requires recovery"})

	_, err := s.pickAuthOnce(context.Background(), schedulerPickRequest{
		Provider:  "mixed",
		Providers: []string{"xai", "codex"},
		Candidates: []schedulerAuthCandidate{
			{ID: "codex-quarantined", Provider: "codex", Status: "active"},
			{ID: "xai-blocked", Provider: "xai", Status: "active", Attributes: map[string]string{"auth_index": "xai-blocked"}},
		},
	})
	var reject *schedulerRejectError
	if !errors.As(err, &reject) || reject.Code != "privacy_quarantine" || reject.HTTPStatus != http.StatusServiceUnavailable {
		t.Fatalf("error=%#v / %v, want privacy_quarantine 503", reject, err)
	}
}

func TestSchedulerRouteAllowlistCannotBeExpandedByCandidate(t *testing.T) {
	s := &store{}
	setupMixedSchedulerTest(t, s, false)
	now := time.Now().Unix()
	publishCodexSchedulerTestSnapshot(t, nil, now)

	resp, err := s.pickAuthOnce(context.Background(), schedulerPickRequest{
		Provider: "codex",
		Candidates: []schedulerAuthCandidate{
			{ID: "xai-outside-route", Provider: "xai", Priority: 100, Status: "active"},
			{ID: "codex-ready", Provider: " CODEX ", Priority: 1, Status: "active"},
		},
	})
	if err != nil || !resp.Handled || resp.AuthID != "codex-ready" {
		t.Fatalf("response=%+v err=%v, want only the route-authorized candidate", resp, err)
	}
}

func TestSchedulerConflictingRouteDeclarationsFailClosed(t *testing.T) {
	s := &store{}
	setupMixedSchedulerTest(t, s, false)
	_, err := s.pickAuthOnce(context.Background(), schedulerPickRequest{
		Provider:   "codex",
		Providers:  []string{"xai"},
		Candidates: []schedulerAuthCandidate{{ID: "codex", Provider: "codex", Status: "active"}},
	})
	var reject *schedulerRejectError
	if !errors.As(err, &reject) || reject.Code != "auth_unavailable" {
		t.Fatalf("error=%#v / %v, want route conflict rejection", reject, err)
	}
}

func TestSchedulerFilteringDoesNotMutateInput(t *testing.T) {
	s := &store{}
	setupMixedSchedulerTest(t, s, false)
	now := time.Now().Unix()
	publishCodexSchedulerTestSnapshot(t, nil, now)
	publishXAISchedulerTestSnapshot(t, nil, now)
	s.setAPIKeyPrivacyQuarantineSnapshot("", map[string]string{"codex": "legacy identity requires recovery"})
	req := schedulerPickRequest{
		Provider:  " mixed ",
		Providers: []string{" XAI ", "codex"},
		Options: schedulerOptions{
			Headers:  map[string][]string{"Session-Id": {"immutable", "still-immutable"}},
			Metadata: map[string]any{"nested": map[string]any{"value": "unchanged", "items": []any{"one", "two"}}},
		},
		Candidates: []schedulerAuthCandidate{
			{ID: "codex", Provider: " CODEX ", Status: "active", Attributes: map[string]string{"auth_index": "codex"}},
			{ID: "xai", Provider: " XAI ", Status: "active", Metadata: map[string]any{"file": "xai.json", "nested": map[string]any{"value": "unchanged"}}},
		},
	}
	want := cloneSchedulerRequestForMutationTest(req)
	resp, err := s.pickAuthOnce(context.Background(), req)
	if err != nil || !resp.Handled || resp.AuthID != "xai" {
		t.Fatalf("response=%+v err=%v", resp, err)
	}
	if !reflect.DeepEqual(req, want) {
		t.Fatalf("request mutated:\n got=%#v\nwant=%#v", req, want)
	}
}

func cloneSchedulerRequestForMutationTest(req schedulerPickRequest) schedulerPickRequest {
	cloned := req
	cloned.Providers = append([]string(nil), req.Providers...)
	cloned.Options.Headers = make(map[string][]string, len(req.Options.Headers))
	for key, values := range req.Options.Headers {
		cloned.Options.Headers[key] = append([]string(nil), values...)
	}
	cloned.Options.Metadata = cloneSchedulerMetadataForMutationTest(req.Options.Metadata)
	cloned.Candidates = make([]schedulerAuthCandidate, len(req.Candidates))
	for i, candidate := range req.Candidates {
		cloned.Candidates[i] = candidate
		if candidate.Attributes != nil {
			cloned.Candidates[i].Attributes = make(map[string]string, len(candidate.Attributes))
			for key, value := range candidate.Attributes {
				cloned.Candidates[i].Attributes[key] = value
			}
		}
		cloned.Candidates[i].Metadata = cloneSchedulerMetadataForMutationTest(candidate.Metadata)
	}
	return cloned
}

func cloneSchedulerMetadataForMutationTest(metadata map[string]any) map[string]any {
	if metadata == nil {
		return nil
	}
	cloned := make(map[string]any, len(metadata))
	for key, value := range metadata {
		cloned[key] = cloneSchedulerMetadataValueForMutationTest(value)
	}
	return cloned
}

func cloneSchedulerMetadataValueForMutationTest(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		return cloneSchedulerMetadataForMutationTest(typed)
	case []any:
		cloned := make([]any, len(typed))
		for i, item := range typed {
			cloned[i] = cloneSchedulerMetadataValueForMutationTest(item)
		}
		return cloned
	case []string:
		return append([]string(nil), typed...)
	case map[string]string:
		cloned := make(map[string]string, len(typed))
		for key, item := range typed {
			cloned[key] = item
		}
		return cloned
	case map[string][]string:
		cloned := make(map[string][]string, len(typed))
		for key, items := range typed {
			cloned[key] = append([]string(nil), items...)
		}
		return cloned
	default:
		return typed
	}
}
