package main

import (
	"context"
	"errors"
	"net/http"
	"path/filepath"
	"testing"
	"time"
)

func TestXAIStateClassification(t *testing.T) {
	now := int64(1_700_000_000)
	tests := []struct {
		name    string
		status  int
		body    string
		state   string
		resetAt int64
	}{
		{name: "unauthorized", status: http.StatusUnauthorized, state: xaiStateUnauthorized},
		{name: "forbidden", status: http.StatusForbidden, state: xaiStateForbidden},
		{name: "free exhausted", status: http.StatusTooManyRequests, body: `{"error":{"code":"subscription:free-usage-exhausted"}}`, state: xaiStateFreeExhausted, resetAt: now + int64((24 * time.Hour).Seconds())},
		{name: "ordinary rate limit", status: http.StatusTooManyRequests, state: xaiStateRateLimited, resetAt: now + int64(time.Minute.Seconds())},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			state, _, resetAt := xaiStateForRecord(usageRecord{Failed: true, Failure: usageFailure{StatusCode: test.status, Body: test.body}}, test.status, now)
			if state != test.state || resetAt != test.resetAt {
				t.Fatalf("state=%q resetAt=%d, want %q %d", state, resetAt, test.state, test.resetAt)
			}
		})
	}
}

func TestXAIOrdinaryRateLimitHonorsShortRetryAfter(t *testing.T) {
	now := int64(1_700_000_000)
	rec := usageRecord{
		Failed:          true,
		Failure:         usageFailure{StatusCode: http.StatusTooManyRequests},
		ResponseHeaders: map[string][]string{"Retry-After": {"120"}},
	}
	state, _, resetAt := xaiStateForRecord(rec, http.StatusTooManyRequests, now)
	if state != xaiStateRateLimited || resetAt != now+120 {
		t.Fatalf("state=%q resetAt=%d, want short rate limit ending at %d", state, resetAt, now+120)
	}
}

func TestXAIUsageScopeIsSeparateFromOtherProviders(t *testing.T) {
	db := newProtectionTestDB(t)
	now := time.Now().Unix()
	for _, provider := range []string{"codex", "xai", "claude"} {
		if _, err := db.Exec(`INSERT INTO usage_events (requested_at, provider, auth_id, auth_index, total_tokens) VALUES (?, ?, ?, ?, 10)`, now, provider, provider, provider); err != nil {
			t.Fatal(err)
		}
	}
	xai, err := queryOneTotals(context.Background(), db, now-1, "xai")
	if err != nil {
		t.Fatal(err)
	}
	other, err := queryOneTotals(context.Background(), db, now-1, "other")
	if err != nil {
		t.Fatal(err)
	}
	if xai.Requests != 1 || other.Requests != 1 {
		t.Fatalf("xai requests=%d other requests=%d, want 1 and 1", xai.Requests, other.Requests)
	}
}

func TestXAIFreeUsageExhaustedStateSurvivesConcurrentSuccess(t *testing.T) {
	db := newProtectionTestDB(t)
	now := time.Now()
	failure := usageRecord{
		Provider:    "xai",
		AuthID:      "xai-account",
		AuthIndex:   "xai-account",
		RequestedAt: now,
		Failed:      true,
		Failure:     usageFailure{StatusCode: http.StatusTooManyRequests, Body: `subscription:free-usage-exhausted`},
	}
	if err := recordXAIStateIfNeeded(context.Background(), db, failure, http.StatusTooManyRequests); err != nil {
		t.Fatal(err)
	}
	states, err := queryActiveXAIStates(context.Background(), db, now.Unix())
	if err != nil {
		t.Fatal(err)
	}
	if len(states) != 1 || states[0].State != xaiStateFreeExhausted {
		t.Fatalf("states=%#v, want one free usage exhausted state", states)
	}
	success := usageRecord{Provider: "xai", AuthID: "xai-account", AuthIndex: "xai-account", RequestedAt: now.Add(time.Second)}
	if err := recordXAIStateIfNeeded(context.Background(), db, success, http.StatusOK); err != nil {
		t.Fatal(err)
	}
	states, err = queryActiveXAIStates(context.Background(), db, now.Add(time.Second).Unix())
	if err != nil {
		t.Fatal(err)
	}
	if len(states) != 1 || states[0].State != xaiStateFreeExhausted {
		t.Fatalf("states=%#v, want free usage exhausted state to remain active", states)
	}
}

func TestXAITransientStateClearsAfterSuccess(t *testing.T) {
	db := newProtectionTestDB(t)
	now := time.Now()
	failure := usageRecord{
		Provider:    "xai",
		AuthID:      "xai-account",
		AuthIndex:   "xai-account",
		RequestedAt: now,
		Failed:      true,
		Failure:     usageFailure{StatusCode: http.StatusTooManyRequests},
	}
	if err := recordXAIStateIfNeeded(context.Background(), db, failure, http.StatusTooManyRequests); err != nil {
		t.Fatal(err)
	}
	success := usageRecord{Provider: "xai", AuthID: "xai-account", AuthIndex: "xai-account", RequestedAt: now.Add(time.Second)}
	if err := recordXAIStateIfNeeded(context.Background(), db, success, http.StatusOK); err != nil {
		t.Fatal(err)
	}
	states, err := queryActiveXAIStates(context.Background(), db, now.Add(time.Second).Unix())
	if err != nil {
		t.Fatal(err)
	}
	if len(states) != 0 {
		t.Fatalf("states=%#v, want transient state cleared after success", states)
	}
}

func TestXAISchedulerFiltersUnavailableCandidate(t *testing.T) {
	t.Setenv("CPA_TOKEN_USAGE_DIR", t.TempDir())
	t.Setenv("CPA_CONFIG_PATH", filepath.Join(t.TempDir(), "missing-config.yaml"))
	s := &store{}
	t.Cleanup(s.close)
	db, _, err := s.open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	if _, err := db.Exec(`
INSERT INTO xai_account_states (state_key, auth_id, auth_index, provider, state, reason, observed_at, reset_at, active, last_status_code)
VALUES ('blocked', 'blocked', 'blocked', 'xai', 'free_usage_exhausted', 'test', ?, ?, 1, 429)`, now, now+3600); err != nil {
		t.Fatal(err)
	}
	req := schedulerPickRequest{Provider: "xai", Candidates: []schedulerAuthCandidate{
		{ID: "blocked", Provider: "xai", Priority: 10, Attributes: map[string]string{"auth_index": "blocked"}},
		{ID: "available", Provider: "xai", Priority: 1, Attributes: map[string]string{"auth_index": "available"}},
	}}
	resp, err := s.pickAuth(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if !resp.Handled || resp.AuthID != "available" {
		t.Fatalf("response=%#v, want available xAI candidate", resp)
	}
	req.Candidates = req.Candidates[:1]
	_, err = s.pickAuth(context.Background(), req)
	var reject *schedulerRejectError
	if !errors.As(err, &reject) || reject.HTTPStatus != http.StatusServiceUnavailable {
		t.Fatalf("error=%v, want scheduler reject for all unavailable xAI candidates", err)
	}
}
