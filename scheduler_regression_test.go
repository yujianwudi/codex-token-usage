package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"
)

func TestUnpersistedForbiddenDoesNotInvalidateHealthySchedulerSnapshot(t *testing.T) {
	resetSchedulerStateForTest()
	t.Cleanup(resetSchedulerStateForTest)
	s := newTestStore(t)
	db, _, err := s.open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := globalSchedulerState.refresh(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	if globalSchedulerState.needsDatabase("codex", false) {
		t.Fatal("healthy Codex snapshot was not initialized")
	}
	rec := usageRecord{
		Provider:    "codex",
		AuthID:      "single-forbidden",
		AuthIndex:   "single-forbidden",
		RequestedAt: time.Now(),
		Failed:      true,
		Failure:     usageFailure{StatusCode: http.StatusForbidden},
	}
	if err := s.recordUsage(context.Background(), rec); err != nil {
		t.Fatal(err)
	}
	var active int
	if err := db.QueryRow(`SELECT COUNT(*) FROM invalid_auths WHERE active=1`).Scan(&active); err != nil {
		t.Fatal(err)
	}
	if active != 0 {
		t.Fatalf("single 403 created %d active restrictions", active)
	}
	if globalSchedulerState.needsDatabase("codex", false) {
		t.Fatal("single unpersisted 403 invalidated the healthy scheduler snapshot")
	}
}

func TestCodexRecoveryDoesNotClearNewerRestriction(t *testing.T) {
	s := newTestStore(t)
	db, _, err := s.open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	base := time.Now().Add(-time.Minute).Truncate(time.Second)
	restrictedAt := base.Add(20 * time.Second).Unix()
	if _, err := db.Exec(`INSERT INTO invalid_auths
		(auth_id, auth_index, provider, reason, invalidated_at, active, last_status_code)
		VALUES ('ordered', 'ordered', 'codex', 'test', ?, 1, 401)`, restrictedAt); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO autoban_bans
		(auth_id, auth_index, provider, window, reason, banned_at, reset_at, active, last_status_code)
		VALUES ('ordered', 'ordered', 'codex', '5h', 'test', ?, ?, 1, 429)`, restrictedAt, restrictedAt+3600); err != nil {
		t.Fatal(err)
	}
	older := usageRecord{Provider: "codex", AuthID: "ordered", AuthIndex: "ordered", RequestedAt: base}
	if err := clearRecoveredAuthStateIfNeeded(context.Background(), db, older, http.StatusOK); err != nil {
		t.Fatal(err)
	}
	assertCodexRestrictionActiveCounts(t, db, 1, 1)

	newer := older
	newer.RequestedAt = base.Add(40 * time.Second)
	if err := clearRecoveredAuthStateIfNeeded(context.Background(), db, newer, http.StatusOK); err != nil {
		t.Fatal(err)
	}
	assertCodexRestrictionActiveCounts(t, db, 0, 0)
}

func assertCodexRestrictionActiveCounts(t *testing.T, db *sql.DB, wantInvalid, wantBan int) {
	t.Helper()
	var invalid, ban int
	if err := db.QueryRow(`SELECT COUNT(*) FROM invalid_auths WHERE active=1`).Scan(&invalid); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM autoban_bans WHERE active=1`).Scan(&ban); err != nil {
		t.Fatal(err)
	}
	if invalid != wantInvalid || ban != wantBan {
		t.Fatalf("active restrictions = invalid:%d ban:%d, want %d/%d", invalid, ban, wantInvalid, wantBan)
	}
}

func TestXAIRecoveryDoesNotClearNewerRestriction(t *testing.T) {
	s := newTestStore(t)
	db, _, err := s.open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	base := time.Now().Add(-time.Minute).Truncate(time.Second)
	restrictedAt := base.Add(20 * time.Second).Unix()
	if _, err := db.Exec(`INSERT INTO xai_account_states
		(state_key, auth_id, auth_index, provider, state, reason, observed_at, reset_at, active, last_status_code)
		VALUES ('ordered', 'ordered', 'ordered', 'xai', ?, 'test', ?, ?, 1, 429)`, xaiStateRateLimited, restrictedAt, restrictedAt+60); err != nil {
		t.Fatal(err)
	}
	older := usageRecord{Provider: "xai", AuthID: "ordered", AuthIndex: "ordered", RequestedAt: base}
	changed, err := clearRecoveredXAIState(context.Background(), db, older)
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Fatal("older success reported clearing a newer xAI restriction")
	}
	var active int
	if err := db.QueryRow(`SELECT active FROM xai_account_states WHERE state_key='ordered'`).Scan(&active); err != nil {
		t.Fatal(err)
	}
	if active != 1 {
		t.Fatal("older success cleared a newer xAI restriction")
	}

	newer := older
	newer.RequestedAt = base.Add(40 * time.Second)
	changed, err = clearRecoveredXAIState(context.Background(), db, newer)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("newer success did not clear the older xAI restriction")
	}
}

func TestSanitizeTriggerErrorRejectsCredentialVariants(t *testing.T) {
	for _, value := range []string{
		"BEARER xai-secret-value",
		"Authorization: Bearer secret",
		"Authorization Basic dXNlcjpwYXNz",
		"Proxy-Authorization Digest dXNlcjpwYXNz",
		"request failed with API_KEY=secret",
		"upstream returned xai-secret-value",
	} {
		if got := sanitizeTriggerError(value); got != "trigger failed" {
			t.Fatalf("sanitizeTriggerError(%q) = %q", value, got)
		}
	}
	if got := sanitizeTriggerError("temporary upstream timeout"); got != "temporary upstream timeout" {
		t.Fatalf("benign diagnostic = %q", got)
	}
}

func TestUsageHandleReportsStoredWhenDerivedStateFails(t *testing.T) {
	s := newTestStore(t)
	db, _, err := s.open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TRIGGER fail_invalid_auth_insert
		BEFORE INSERT ON invalid_auths
		BEGIN SELECT RAISE(ABORT, 'forced derived state failure'); END`); err != nil {
		t.Fatal(err)
	}
	rec := usageRecord{
		Provider:    "codex",
		AuthID:      "partial",
		AuthIndex:   "partial",
		RequestedAt: time.Now(),
		Failed:      true,
		Failure:     usageFailure{StatusCode: http.StatusUnauthorized},
	}
	err = s.recordUsage(context.Background(), rec)
	var postProcessErr *usagePostProcessError
	if !errors.As(err, &postProcessErr) {
		t.Fatalf("recordUsage error = %v, want usagePostProcessError", err)
	}
	var stored int
	if err := db.QueryRow(`SELECT COUNT(*) FROM usage_events WHERE auth_id='partial'`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != 1 {
		t.Fatalf("stored usage rows = %d, want 1", stored)
	}

	previousStore := globalStore
	globalStore = s
	t.Cleanup(func() { globalStore = previousStore })
	raw, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	response, err := handleMethod("usage.handle", raw)
	if err != nil {
		t.Fatal(err)
	}
	var env envelope
	if err := json.Unmarshal(response, &env); err != nil {
		t.Fatal(err)
	}
	var result map[string]any
	if err := json.Unmarshal(env.Result, &result); err != nil {
		t.Fatal(err)
	}
	warning, ok := result["warning"].(string)
	if result["stored"] != true || !ok || warning == "" {
		t.Fatalf("usage.handle result = %#v, want stored=true with warning", result)
	}
}
