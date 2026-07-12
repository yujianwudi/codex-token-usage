package main

import (
	"context"
	"database/sql"
	"testing"
	"time"
)

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
	db := newProtectionTestDB(t)
	cfg := defaultPluginConfig()
	cfg.AccountProtectionEnabled = true
	cfg.AccountProtectionFreeConcurrency = 2
	s := &store{}
	ctx := context.Background()
	candidates := []schedulerAuthCandidate{protectionTestCandidate("a", "free", 10), protectionTestCandidate("b", "free", 1)}
	for _, want := range []string{"a", "a", "b"} {
		got, err := s.pickProtectedAuth(ctx, db, candidates, cfg)
		if err != nil {
			t.Fatal(err)
		}
		if got.ID != want {
			t.Fatalf("picked %q, want %q", got.ID, want)
		}
	}
}

func TestProtectionTokenDemotionPrefersLowerUsageCandidate(t *testing.T) {
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
	}, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != "b" {
		t.Fatalf("picked %q, want lower-token candidate b", got.ID)
	}
}

func TestProtectionSaturationUsesLeastInFlightCandidate(t *testing.T) {
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
	}, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != "b" {
		t.Fatalf("picked %q, want least-in-flight candidate b", got.ID)
	}
}

func TestProtectionSaturationUsesPriorityBeforeTokenDemotion(t *testing.T) {
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
	if got := chooseProtectedCandidate(states); got.Candidate.ID != "high" {
		t.Fatalf("picked %q, want higher-priority saturated candidate", got.Candidate.ID)
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
	_, err := (&store{}).pickProtectedAuth(context.Background(), db, []schedulerAuthCandidate{protectionTestCandidate("other", "plus", 1)}, cfg)
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
