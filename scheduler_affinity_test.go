package main

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func affinityTestRequest(sessionID string) schedulerPickRequest {
	return schedulerPickRequest{
		Provider: "codex",
		Model:    "gpt-test",
		Options: schedulerOptions{
			Headers: map[string][]string{"Session-Id": {sessionID}},
		},
	}
}

func affinityTestCandidates() []schedulerAuthCandidate {
	return []schedulerAuthCandidate{
		{ID: "a", Provider: "codex", Priority: 1},
		{ID: "b", Provider: "codex", Priority: 1},
	}
}

func resetSchedulerSelectionState(t *testing.T) {
	t.Helper()
	globalSchedulerRotation.reset()
	globalSchedulerAffinity.reset()
	t.Cleanup(func() {
		globalSchedulerRotation.reset()
		globalSchedulerAffinity.reset()
	})
}

func TestSchedulerAffinityKeepsSameSessionOnSameAuth(t *testing.T) {
	resetSchedulerSelectionState(t)
	candidates := affinityTestCandidates()
	request := affinityTestRequest("session-one")
	rotationKey := schedulerRotationKey(request, "codex")
	affinityKey := schedulerAffinityKey(request, "codex")
	if affinityKey == "" || strings.Contains(affinityKey, "session-one") {
		t.Fatalf("affinity key must be non-empty and hide the raw session: %q", affinityKey)
	}
	first := pickSchedulerCandidate(rotationKey, affinityKey, candidates)
	second := pickSchedulerCandidate(rotationKey, affinityKey, candidates)
	if first.ID != "a" || second.ID != "a" {
		t.Fatalf("same session picks = %q, %q; want a, a", first.ID, second.ID)
	}
	otherRequest := affinityTestRequest("session-two")
	other := pickSchedulerCandidate(rotationKey, schedulerAffinityKey(otherRequest, "codex"), candidates)
	if other.ID != "b" {
		t.Fatalf("new session pick = %q, want b", other.ID)
	}
}

func TestSchedulerRotationKeyCarriesOpaqueAffinity(t *testing.T) {
	request := affinityTestRequest("session-hidden")
	key := schedulerRotationKey(request, "codex")
	rotationKey, affinityKey := splitSchedulerSelectionKey(key)
	if rotationKey != "codex\x00gpt-test" || affinityKey == "" {
		t.Fatalf("selection key split = %q / %q", rotationKey, affinityKey)
	}
	if strings.Contains(key, "session-hidden") || strings.Contains(affinityKey, "session-hidden") {
		t.Fatalf("selection key leaked raw session: %q", key)
	}
}

func TestSchedulerAffinitySerializesConcurrentFirstPick(t *testing.T) {
	resetSchedulerSelectionState(t)
	candidates := affinityTestCandidates()
	key := schedulerRotationKey(affinityTestRequest("concurrent-session"), "codex")
	const workers = 8
	start := make(chan struct{})
	results := make(chan string, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			results <- globalSchedulerRotation.pick(key, candidates).ID
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	for got := range results {
		if got != "a" {
			t.Fatalf("concurrent session pick = %q, want a", got)
		}
	}
}

func TestSchedulerAffinityDistinguishesDuplicateVisibleIDs(t *testing.T) {
	resetSchedulerSelectionState(t)
	candidates := []schedulerAuthCandidate{
		{ID: "shared", Provider: "codex", Priority: 1, Attributes: map[string]string{"auth_file": "a.json"}},
		{ID: "shared", Provider: "codex", Priority: 1, Attributes: map[string]string{"auth_file": "b.json"}},
	}
	request := affinityTestRequest("duplicate-session")
	key := schedulerAffinityKey(request, "codex")
	first := pickSchedulerCandidate(schedulerRotationKey(request, "codex"), key, candidates)
	second := pickSchedulerCandidate(schedulerRotationKey(request, "codex"), key, []schedulerAuthCandidate{candidates[1], candidates[0]})
	if schedulerCandidateRotationIdentity(first) != schedulerCandidateRotationIdentity(second) {
		t.Fatalf("duplicate visible ID lost file-specific affinity: %#v then %#v", first, second)
	}
}

func TestProtectionAffinityPreservesSessionUntilHardLimit(t *testing.T) {
	resetSchedulerSelectionState(t)
	db := newProtectionTestDB(t)
	cfg := defaultPluginConfig()
	cfg.AccountProtectionEnabled = true
	cfg.AccountProtectionFreeConcurrency = 2
	request := affinityTestRequest("protected-session")
	affinityKey := schedulerAffinityKey(request, "codex")
	candidates := []schedulerAuthCandidate{
		protectionTestCandidate("a", "free", 10),
		protectionTestCandidate("b", "free", 1),
	}
	for _, want := range []string{"a", "a", "b"} {
		got, err := (&store{}).pickProtectedAuth(context.Background(), db, candidates, cfg, schedulerRotationKey(request, "codex"), affinityKey)
		if err != nil {
			t.Fatal(err)
		}
		if got.ID != want {
			t.Fatalf("picked %q, want %q", got.ID, want)
		}
	}
}

func TestSchedulerAffinityCannotPinLowerPriorityCandidate(t *testing.T) {
	resetSchedulerSelectionState(t)
	request := affinityTestRequest("priority-session")
	affinityKey := schedulerAffinityKey(request, "codex")
	low := protectionTestCandidate("low", "free", 1)
	high := protectionTestCandidate("high", "free", 10)
	globalSchedulerAffinity.bind(affinityKey, schedulerCandidateRotationIdentity(low))
	got := pickSchedulerCandidate(schedulerRotationKey(request, "codex"), affinityKey, []schedulerAuthCandidate{low, high})
	if got.ID != "high" {
		t.Fatalf("affinity selected %q, want highest-priority candidate high", got.ID)
	}
}

func TestProtectionAffinityCannotPinLowerPriorityCandidate(t *testing.T) {
	resetSchedulerSelectionState(t)
	request := affinityTestRequest("protected-priority-session")
	affinityKey := schedulerAffinityKey(request, "codex")
	low := protectionCandidate{Candidate: protectionTestCandidate("low", "free", 1), Limit: 2}
	high := protectionCandidate{Candidate: protectionTestCandidate("high", "free", 10), Limit: 2}
	globalSchedulerAffinity.bind(affinityKey, schedulerCandidateRotationIdentity(low.Candidate))
	got, err := chooseProtectedCandidate([]protectionCandidate{low, high}, schedulerRotationKey(request, "codex"), affinityKey)
	if err != nil {
		t.Fatal(err)
	}
	if got.Candidate.ID != "high" {
		t.Fatalf("protected affinity selected %q, want highest-priority candidate high", got.Candidate.ID)
	}
}

func TestPickAuthOnceSessionAffinityHonorsProtectionHardLimit(t *testing.T) {
	resetSchedulerSelectionState(t)
	t.Setenv("CPA_AUTH_DIR", t.TempDir())
	previousCfg := globalAccountProtection.config()
	cfg := defaultPluginConfig()
	cfg.AccountProtectionEnabled = true
	cfg.AccountProtectionFreeConcurrency = 2
	globalAccountProtection.configure(cfg)
	t.Cleanup(func() { globalAccountProtection.configure(previousCfg) })

	s := newTestStore(t)
	request := affinityTestRequest("protected-integration-session")
	request.Candidates = []schedulerAuthCandidate{
		{ID: "a", Provider: "codex", Priority: 1, Attributes: map[string]string{"auth_index": "a", "plan_type": "free"}},
		{ID: "b", Provider: "codex", Priority: 1, Attributes: map[string]string{"auth_index": "b", "plan_type": "free"}},
	}
	for _, want := range []string{"a", "a", "b", "b"} {
		got, err := s.pickAuthOnce(context.Background(), request)
		if err != nil {
			t.Fatal(err)
		}
		if !got.Handled || got.AuthID != want {
			t.Fatalf("protected session pick = %#v, want %q", got, want)
		}
	}
	_, err := s.pickAuthOnce(context.Background(), request)
	var reject *schedulerRejectError
	if !errors.As(err, &reject) || reject.Code != "account_protection_saturated" || reject.HTTPStatus != http.StatusServiceUnavailable {
		t.Fatalf("saturated protected session error = %#v / %v", reject, err)
	}
}

func TestSchedulerAffinityExpiresAndStaysBounded(t *testing.T) {
	request := affinityTestRequest("expired-session")
	key := schedulerAffinityKey(request, "codex")
	var manager schedulerAffinityManager
	manager.bindings = map[string]schedulerAffinityBinding{
		key: {CandidateIdentity: schedulerCandidateRotationIdentity(affinityTestCandidates()[1]), ExpiresAt: time.Now().Add(-time.Second)},
	}
	if _, ok := manager.pick(key, affinityTestCandidates()); ok {
		t.Fatal("expired affinity binding was reused")
	}
	for i := 0; i <= schedulerAffinityMaxBindings; i++ {
		manager.bind(strconv.Itoa(i), "auth")
	}
	if got := len(manager.bindings); got != schedulerAffinityMaxBindings {
		t.Fatalf("binding count = %d, want %d", got, schedulerAffinityMaxBindings)
	}
}
