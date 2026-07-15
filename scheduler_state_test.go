package main

import (
	"context"
	"testing"
	"time"
)

func TestSchedulerStateFastPathAvoidsOpeningDatabase(t *testing.T) {
	resetSchedulerStateForTest()
	t.Cleanup(resetSchedulerStateForTest)
	globalSchedulerState.setRestricted("codex", false)
	cfg := defaultPluginConfig()
	cfg.AccountProtectionEnabled = false
	globalAccountProtection.configure(cfg)

	s := &store{}
	globalStore = s
	t.Cleanup(func() {
		s.close()
		globalStore = &store{}
	})
	resp, err := s.pickAuthOnce(context.Background(), schedulerPickRequest{
		Provider: "codex",
		Model:    "gpt-5.5",
		Candidates: []schedulerAuthCandidate{
			{ID: "alice", Provider: "codex", Priority: 1},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Handled {
		t.Fatalf("response=%+v, want native scheduler delegation", resp)
	}
	if s.db != nil {
		t.Fatal("healthy fast path opened SQLite")
	}
}

func TestSchedulerStateRefreshTracksActiveRestrictions(t *testing.T) {
	resetSchedulerStateForTest()
	t.Cleanup(resetSchedulerStateForTest)
	s := newTestStore(t)
	db, _, err := s.open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	if _, err := db.Exec(`INSERT INTO autoban_bans
		(auth_id, provider, window, reason, banned_at, reset_at, active)
		VALUES ('alice', 'codex', '5h', 'test', ?, ?, 1)`, now, now+3600); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO xai_account_states
		(state_key, provider, state, reason, observed_at, reset_at, active)
		VALUES ('grok', 'xai', 'rate_limited', 'test', ?, ?, 1)`, now, now+60); err != nil {
		t.Fatal(err)
	}
	if err := globalSchedulerState.refresh(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	if !globalSchedulerState.needsDatabase("codex", false) {
		t.Fatal("active Codex ban was not cached")
	}
	if !globalSchedulerState.needsDatabase("xai", false) {
		t.Fatal("active xAI state was not cached")
	}
}

func TestSchedulerStateInitializesProvidersIndependently(t *testing.T) {
	var state schedulerStateCache
	state.setRestricted("codex", false)
	if state.needsDatabase("codex", false) {
		t.Fatal("initialized Codex state unexpectedly needs the database")
	}
	if !state.needsDatabase("xai", false) {
		t.Fatal("setting Codex state incorrectly initialized xAI")
	}

	state.setRestricted("xai", false)
	if state.needsDatabase("xai", false) {
		t.Fatal("initialized xAI state unexpectedly needs the database")
	}
}

func TestSchedulerStateRefreshDoesNotOverwriteNewerRestriction(t *testing.T) {
	var state schedulerStateCache
	generation := state.beginRefresh()

	// Simulate a restriction being recorded after refresh read its generation
	// but before the database snapshot is published.
	state.setRestricted("codex", true)
	state.applyRefresh(generation, false, 0, false, 0)

	if !state.needsDatabase("codex", false) {
		t.Fatal("stale refresh overwrote a newer Codex restriction")
	}
	if state.needsDatabase("xai", false) {
		t.Fatal("uncontended xAI refresh result was not published")
	}
}

func TestSchedulerStateInvalidateRejectsInFlightRefresh(t *testing.T) {
	var state schedulerStateCache
	generation := state.beginRefresh()
	state.invalidate()
	state.applyRefresh(generation, false, 0, false, 0)

	if !state.needsDatabase("codex", false) || !state.needsDatabase("xai", false) {
		t.Fatal("in-flight refresh repopulated invalidated scheduler state")
	}
}

func TestSchedulerStateOlderRefreshCannotOverwriteNewerRefresh(t *testing.T) {
	var state schedulerStateCache
	older := state.beginRefresh()
	newer := state.beginRefresh()

	state.applyRefresh(newer, true, time.Now().Unix()+60, false, 0)
	state.applyRefresh(older, false, 0, true, time.Now().Unix()+60)

	if !state.needsDatabase("codex", false) {
		t.Fatal("older refresh cleared the newer Codex restriction")
	}
	if state.needsDatabase("xai", false) {
		t.Fatal("older refresh overwrote the newer xAI result")
	}
}

func TestSchedulerStateConditionalClearRejectsNewerRestriction(t *testing.T) {
	for _, provider := range []string{"codex", "xai"} {
		t.Run(provider, func(t *testing.T) {
			var state schedulerStateCache
			generation := state.providerGeneration(provider)
			state.setRestricted(provider, true)

			if state.clearRestrictedIfGeneration(provider, generation) {
				t.Fatal("stale empty query cleared a newer restriction")
			}
			if !state.needsDatabase(provider, false) {
				t.Fatal("newer restriction was lost")
			}

			generation = state.providerGeneration(provider)
			if !state.clearRestrictedIfGeneration(provider, generation) {
				t.Fatal("current empty query did not clear restriction")
			}
			if state.needsDatabase(provider, false) {
				t.Fatal("current empty query left restriction active")
			}
		})
	}
}

func TestSchedulerStateConditionalClearIsProviderSpecific(t *testing.T) {
	var state schedulerStateCache
	codexGeneration := state.providerGeneration("codex")
	state.setRestricted("xai", true)
	if !state.clearRestrictedIfGeneration("codex", codexGeneration) {
		t.Fatal("xAI update incorrectly invalidated Codex snapshot")
	}
	if state.needsDatabase("codex", false) {
		t.Fatal("Codex empty result was not cached")
	}
	if !state.needsDatabase("xai", false) {
		t.Fatal("xAI restriction was unexpectedly cleared")
	}
}

func TestQueryActiveAutobansDoesNotRewriteUsageHistory(t *testing.T) {
	s := newTestStore(t)
	db, _, err := s.open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO usage_events
		(requested_at, provider, primary_reset_at, total_tokens)
		VALUES (?, 'codex', ?, 1)`, time.Now().Unix(), int64(1_800_000_000_000)); err != nil {
		t.Fatal(err)
	}
	if _, err := queryActiveAutobans(context.Background(), db, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	var resetAt int64
	if err := db.QueryRow(`SELECT primary_reset_at FROM usage_events LIMIT 1`).Scan(&resetAt); err != nil {
		t.Fatal(err)
	}
	if resetAt != 1_800_000_000_000 {
		t.Fatalf("queryActiveAutobans rewrote usage history: %d", resetAt)
	}
}
