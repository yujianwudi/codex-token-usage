package main

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"
)

func TestProviderScopedStateQueriesAndMutations(t *testing.T) {
	resetSchedulerStateForTest()
	t.Cleanup(resetSchedulerStateForTest)
	db := newProtectionTestDB(t)
	now := time.Now().Unix()
	if _, err := db.Exec(`
INSERT INTO invalid_auths(auth_id,provider,reason,invalidated_at,active)
VALUES('shared','codex','codex',?,1),('shared','openai','foreign',?,1);
INSERT INTO autoban_bans(auth_id,provider,window,reason,banned_at,reset_at,active)
VALUES('shared','codex','5h','codex',?,?,1),('shared','openai','5h','foreign',?,?,1);
INSERT INTO xai_account_states(state_key,provider,state,reason,observed_at,reset_at,active)
VALUES('shared','xai','rate_limited','xai',?,?,1),('shared','openai','rate_limited','foreign',?,?,1);`,
		now, now, now, now+60, now, now+60, now, now+60, now, now+60); err != nil {
		t.Fatal(err)
	}

	invalids, err := queryActiveInvalidAuths(context.Background(), db, providerCodex)
	if err != nil {
		t.Fatal(err)
	}
	bans, err := queryActiveAutobans(context.Background(), db, providerCodex, now)
	if err != nil {
		t.Fatal(err)
	}
	states, err := queryActiveXAIStates(context.Background(), db, providerXAI, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(invalids) != 1 || invalids[0].Provider != providerCodex {
		t.Fatalf("Codex invalid query leaked providers: %+v", invalids)
	}
	if len(bans) != 1 || bans[0].Provider != providerCodex {
		t.Fatalf("Codex autoban query leaked providers: %+v", bans)
	}
	if len(states) != 1 || states[0].Provider != providerXAI {
		t.Fatalf("xAI state query leaked providers: %+v", states)
	}

	if err := expireAutobans(context.Background(), db, now+61); err != nil {
		t.Fatal(err)
	}
	if err := expireXAIStates(context.Background(), db, now+61); err != nil {
		t.Fatal(err)
	}
	assertProviderStateActive(t, db, "autoban_bans", "openai", "auth_id", "shared", 1)
	assertProviderStateActive(t, db, "xai_account_states", "openai", "state_key", "shared", 1)

	rec := usageRecord{Provider: providerCodex, AuthID: "shared", RequestedAt: time.Unix(now+120, 0)}
	if err := clearRecoveredAuthStateIfNeeded(context.Background(), db, rec, 200); err != nil {
		t.Fatal(err)
	}
	assertProviderStateActive(t, db, "invalid_auths", "openai", "auth_id", "shared", 1)

	if _, err := db.Exec(`UPDATE autoban_bans SET active=1,reset_at=? WHERE provider='codex' AND auth_id='shared'`, now+3600); err != nil {
		t.Fatal(err)
	}
	changed, err := markAutobanReleased(context.Background(), db, "shared", now+121)
	if err != nil || !changed {
		t.Fatalf("manual Codex release = %v/%v", changed, err)
	}
	assertProviderStateActive(t, db, "autoban_bans", "openai", "auth_id", "shared", 1)
}

func TestProviderScopedManualReleaseIsAtomic(t *testing.T) {
	db := newProtectionTestDB(t)
	now := time.Now().Unix()
	if _, err := db.Exec(`
INSERT INTO autoban_bans(auth_id,provider,window,reason,banned_at,reset_at,active,last_status_code)
VALUES('a','codex','5h','a',?,?,1,429),('b','codex','5h','b',?,?,1,429),('a','openai','5h','foreign',?,?,1,429);
CREATE TRIGGER fail_second_release BEFORE UPDATE OF active ON autoban_bans
WHEN OLD.provider='codex' AND OLD.auth_id='b'
BEGIN SELECT RAISE(ABORT,'forced batch release failure'); END;`,
		now, now+3600, now, now+3600, now, now+3600); err != nil {
		t.Fatal(err)
	}
	if _, err := releaseAutobans(context.Background(), db, autobanReleaseRequest{Scope: "all429"}); err == nil {
		t.Fatal("batch release unexpectedly succeeded")
	}
	assertProviderStateActive(t, db, "autoban_bans", providerCodex, "auth_id", "a", 1)
	assertProviderStateActive(t, db, "autoban_bans", providerCodex, "auth_id", "b", 1)
	assertProviderStateActive(t, db, "autoban_bans", "openai", "auth_id", "a", 1)

	if _, err := db.Exec(`DROP TRIGGER fail_second_release`); err != nil {
		t.Fatal(err)
	}
	result, err := releaseAutobans(context.Background(), db, autobanReleaseRequest{Scope: "all429"})
	if err != nil {
		t.Fatal(err)
	}
	if result.Released != 2 {
		t.Fatalf("released = %d, want 2", result.Released)
	}
	assertProviderStateActive(t, db, "autoban_bans", "openai", "auth_id", "a", 1)
}

func TestUnsupportedProviderRowsAreInertAndDiagnosed(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("CPA_TOKEN_USAGE_DIR", dir)
	t.Setenv("CPA_AUTH_DIR", filepath.Join(dir, "auth"))
	s := &store{}
	db, path, err := s.open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	before, err := s.currentRevision(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`
INSERT INTO invalid_auths(auth_id,provider,reason,invalidated_at,active) VALUES('foreign','custom-ai','foreign',1,1);
INSERT INTO autoban_bans(auth_id,provider,window,reason,banned_at,reset_at,active) VALUES('foreign','custom-ai','5h','foreign',1,9999999999,1);
INSERT INTO xai_account_states(state_key,provider,state,reason,observed_at,active) VALUES('foreign','custom-ai','rate_limited','foreign',1,1);
INSERT INTO account_protection_reservations(provider,created_at,expires_at) VALUES('custom-ai',1,2);
INSERT INTO quota_trigger_runs(provider,started_at,finished_at) VALUES('custom-ai',1,2);
INSERT INTO usage_events(requested_at,provider) VALUES(1,'custom-ai');`); err != nil {
		t.Fatal(err)
	}
	after, err := s.currentRevision(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if before.InvalidActive != after.InvalidActive || before.BanActive != after.BanActive || before.XAIStateActive != after.XAIStateActive {
		t.Fatalf("foreign rows changed supported revisions: before=%+v after=%+v", before, after)
	}
	diagnostics := queryDatabaseDiagnostics(context.Background(), db, path)
	for _, table := range []string{"invalid_auths", "autoban_bans", "xai_account_states", "account_protection_reservations", "quota_trigger_runs"} {
		if diagnostics.UnsupportedProviders[table] != 1 {
			t.Fatalf("unsupported provider diagnostics for %s = %+v", table, diagnostics.UnsupportedProviders)
		}
		if diagnostics.StateProviderRows[table]["custom-ai"] != 1 {
			t.Fatalf("provider distribution for %s = %+v", table, diagnostics.StateProviderRows[table])
		}
	}
	if diagnostics.StateProviderRows["usage_events"]["custom-ai"] != 1 {
		t.Fatalf("usage Provider distribution = %+v", diagnostics.StateProviderRows["usage_events"])
	}
	if diagnostics.UnsupportedProviders["usage_events"] != 0 {
		t.Fatalf("third-party usage rows were misclassified as unsupported: %+v", diagnostics.UnsupportedProviders)
	}
}

func TestCodexQuotaReadsIgnoreForeignProviderRows(t *testing.T) {
	db := newProtectionTestDB(t)
	now := time.Now().Unix()
	resetAt := now + 3600
	if _, err := db.Exec(`
INSERT INTO usage_events
  (requested_at,provider,auth_id,auth_index,source,generate,total_tokens,primary_used_percent,primary_reset_at)
VALUES
  (?, 'codex', 'shared', 'shared', 'shared', 1, 10, 25, ?),
  (?, 'xai',   'shared', 'shared', 'shared', 1, 9999, 100, ?);
INSERT INTO quota_trigger_runs
  (auth_id,auth_index,source,provider,status,started_at,finished_at,secondary_limit_tokens,secondary_remaining_tokens,secondary_reset_at)
VALUES
  ('shared','shared','shared','codex','success',?,?,100,80,?),
  ('shared','shared','shared','xai','success',?,?,999,999,?);`,
		now-10, resetAt, now-5, resetAt,
		now-30, now-20, resetAt, now-10, now-5, resetAt); err != nil {
		t.Fatal(err)
	}

	account := accountRow{AuthID: "shared", AuthIndex: "shared", Source: "shared", Provider: providerCodex}
	primary := queryLatestAccountWindowQuota(context.Background(), db, account, now-100, "primary")
	if !primary.Percent.Valid || primary.Percent.Float64 != 25 {
		t.Fatalf("Codex primary quota snapshot = %+v, want 25%% Codex row", primary)
	}
	if got := queryAccountWindowTokens(context.Background(), db, account, sql.NullInt64{Int64: resetAt, Valid: true}, 5*time.Hour, []string{"shared"}); got != 10 {
		t.Fatalf("Codex window tokens = %d, want 10", got)
	}
	if got := queryAccountTokensBetween(context.Background(), db, account, now-100, now+100, []string{"shared"}); got != 10 {
		t.Fatalf("Codex tokens between = %d, want 10", got)
	}

	latest, ok := latestQuotaTriggerFinishedAt(context.Background(), db, configuredAccount{AuthID: "shared", AuthIndex: "shared", Source: "shared"})
	if !ok || latest != now-20 {
		t.Fatalf("Codex trigger cooldown = %d/%v, want %d/true", latest, ok, now-20)
	}
	runs, err := queryRecentQuotaTriggerRuns(context.Background(), db, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 1 || runs[0].FinishedAt != now-20 {
		t.Fatalf("Codex recent trigger runs = %+v", runs)
	}
	capacities := latestSecondaryQuotaTriggerCapacities(context.Background(), db, []accountRow{account}, now-100)
	capacity, ok := capacities[0]
	if !ok || capacity.Total != 100 || capacity.Remaining != 80 {
		t.Fatalf("Codex secondary capacity = %+v/%v, want 100/80", capacity, ok)
	}
}

func assertProviderStateActive(t *testing.T, db queryRower, table, provider, keyColumn, key string, want int) {
	t.Helper()
	var got int
	query := `SELECT active FROM ` + quoteSQLiteIdentifier(table) + ` WHERE provider=? AND ` + quoteSQLiteIdentifier(keyColumn) + `=?`
	if err := db.QueryRow(query, provider, key).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("%s %s/%s active = %d, want %d", table, provider, key, got, want)
	}
}

type queryRower interface {
	QueryRow(string, ...any) *sql.Row
}
