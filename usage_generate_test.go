package main

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

func explicitGenerateRecord(value bool) usageRecord {
	return usageRecord{Generate: value, generateSet: true}
}

func TestRecordUsageRejectsMissingProviderBeforeOpeningStore(t *testing.T) {
	s := &store{}
	err := s.recordUsage(context.Background(), usageRecord{RequestedAt: time.Now()})
	if err == nil || !strings.Contains(err.Error(), "provider is required") {
		t.Fatalf("recordUsage missing provider error = %v", err)
	}
	if s.db != nil {
		t.Fatal("recordUsage opened SQLite before rejecting a missing provider")
	}
}

func TestUsageGenerateJSONDefaultsOmittedToTrue(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
		want bool
	}{
		{name: "omitted", raw: `{"Provider":"codex"}`, want: true},
		{name: "explicit true", raw: `{"Provider":"codex","Generate":true}`, want: true},
		{name: "explicit false", raw: `{"Provider":"codex","Generate":false}`, want: false},
		{name: "lowercase false", raw: `{"provider":"codex","generate":false}`, want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var rec usageRecord
			if err := json.Unmarshal([]byte(tc.raw), &rec); err != nil {
				t.Fatal(err)
			}
			if got := rec.isGenerated(); got != tc.want {
				t.Fatalf("isGenerated()=%v, want %v for %s", got, tc.want, tc.raw)
			}
		})
	}
	if !(usageRecord{}).isGenerated() {
		t.Fatal("internal legacy usageRecord literals must retain omitted-as-true semantics")
	}
}

func TestUsageGenerateFalseIsAuditedButExcludedFromGenerationAggregates(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	now := time.Now()
	generated := explicitGenerateRecord(true)
	generated.Provider = "anthropic"
	generated.ExecutorType = "AnthropicExecutor"
	generated.Model = "claude-sonnet-4.5"
	generated.AuthID = "generated-account"
	generated.AuthIndex = "generated-account"
	generated.Source = "generated-account"
	generated.RequestedAt = now
	generated.Latency = int64(2 * time.Second)
	generated.TTFT = int64(time.Second)
	generated.Detail = usageDetail{InputTokens: 4, OutputTokens: 6, TotalTokens: 10}
	if err := s.recordUsage(ctx, generated); err != nil {
		t.Fatalf("record generated usage: %v", err)
	}

	auditOnly := explicitGenerateRecord(false)
	auditOnly.Provider = "anthropic"
	auditOnly.ExecutorType = "AnthropicExecutor"
	auditOnly.Model = "claude-sonnet-4.5"
	auditOnly.AuthID = "audit-only-account"
	auditOnly.AuthIndex = "audit-only-account"
	auditOnly.Source = "audit-only-account"
	auditOnly.RequestedAt = now.Add(time.Second)
	auditOnly.Latency = int64(20 * time.Second)
	auditOnly.TTFT = int64(10 * time.Second)
	auditOnly.Detail = usageDetail{InputTokens: 1000, OutputTokens: 1000, TotalTokens: 2000}
	if err := s.recordUsage(ctx, auditOnly); err != nil {
		t.Fatalf("record audit-only usage: %v", err)
	}

	db, _, err := s.open(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var rows, generatedRows, auditedTokens int64
	if err := db.QueryRow(`SELECT COUNT(*), COALESCE(SUM(generate),0), COALESCE(SUM(total_tokens),0) FROM usage_events`).Scan(&rows, &generatedRows, &auditedTokens); err != nil {
		t.Fatal(err)
	}
	if rows != 2 || generatedRows != 1 || auditedTokens != 2010 {
		t.Fatalf("stored audit rows=%d generated=%d tokens=%d, want 2/1/2010", rows, generatedRows, auditedTokens)
	}

	since := now.Add(-time.Minute).Unix()
	totals, err := queryOneTotals(ctx, db, since, "other")
	if err != nil {
		t.Fatal(err)
	}
	if totals.Requests != 1 || totals.TotalTokens != 10 || totals.OutputTokens != 6 || totals.AverageTTFTMs != 1000 {
		t.Fatalf("generation totals include audit-only callback: %+v", totals)
	}

	accounts, err := queryAccounts(ctx, db, since, 20, "other")
	if err != nil {
		t.Fatal(err)
	}
	if len(accounts) != 1 || accounts[0].AuthIndex != "generated-account" || accounts[0].Requests != 1 || accounts[0].TotalTokens != 10 {
		t.Fatalf("account totals include audit-only callback: %+v", accounts)
	}

	providers, err := queryProviders(ctx, db, since, 20, "other")
	if err != nil {
		t.Fatal(err)
	}
	if len(providers) != 1 || providers[0].Requests != 1 || providers[0].TotalTokens != 10 {
		t.Fatalf("provider totals include audit-only callback: %+v", providers)
	}

	models, err := queryModels(ctx, db, since, 20, "other")
	if err != nil {
		t.Fatal(err)
	}
	if len(models) != 1 || models[0].Requests != 1 || models[0].TotalTokens != 10 {
		t.Fatalf("model totals include audit-only callback: %+v", models)
	}

	trend, err := queryTrend(ctx, db, since, "24h", "other")
	if err != nil {
		t.Fatal(err)
	}
	if len(trend) != 1 || trend[0].Requests != 1 || trend[0].TotalTokens != 10 {
		t.Fatalf("trend includes audit-only callback: %+v", trend)
	}

	prices := map[string]modelPrice{
		"claude-sonnet-4.5": {Prompt: 3, Completion: 15},
	}
	if err := applyCosts(ctx, db, since, &totals, prices, "other"); err != nil {
		t.Fatal(err)
	}
	expectedCost, ok := costForTokens(costTokenRow{
		Model: "claude-sonnet-4.5", Provider: "anthropic",
		InputTokens: 4, OutputTokens: 6, TotalTokens: 10,
	}, prices)
	if !ok || math.Abs(totals.CostUSD-expectedCost) > 1e-12 {
		t.Fatalf("generation cost=%g, want %g", totals.CostUSD, expectedCost)
	}

	recent, err := queryRecent(ctx, db, since, 20, "other", prices)
	if err != nil {
		t.Fatal(err)
	}
	if len(recent) != 2 {
		t.Fatalf("recent audit rows=%d, want 2", len(recent))
	}
	foundAudit := false
	for _, row := range recent {
		if row.AuthIndex != "audit-only-account" {
			continue
		}
		foundAudit = true
		if row.Generate || row.CostUSD != 0 || row.CostAvailable || row.UnpricedTokens != 0 {
			t.Fatalf("audit-only recent row was billed: %+v", row)
		}
	}
	if !foundAudit {
		t.Fatalf("audit-only callback missing from recent rows: %+v", recent)
	}

	records, headers, err := exportLogRecords(ctx, db, logExportFilter{Window: "24h", Scope: "providers", Limit: 20}, prices)
	if err != nil {
		t.Fatal(err)
	}
	if !containsString(headers, "generate") || len(records) != 2 {
		t.Fatalf("raw audit export headers=%v records=%d", headers, len(records))
	}
	foundAudit = false
	for _, record := range records {
		if record["auth_index"] != "audit-only-account" {
			continue
		}
		foundAudit = true
		if record["generate"] != "false" || record["cost_usd"] != "0.000000" || record["output_tokens_per_second"] != "" {
			t.Fatalf("audit-only export computed generation economics: %+v", record)
		}
	}
	if !foundAudit {
		t.Fatalf("audit-only callback missing from raw export: %+v", records)
	}
}

func TestUsageGenerateFalseReleasesReservationAndOnlyExplicitSignalsRestrict(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	db, _, err := s.open(ctx)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if _, err := db.Exec(`INSERT INTO account_protection_reservations
		(provider, auth_id, auth_index, source, auth_file, plan_type, created_at, expires_at)
		VALUES ('codex', 'terminal', 'terminal', '', '', 'plus', ?, ?)`, now.Unix(), now.Add(15*time.Minute).Unix()); err != nil {
		t.Fatal(err)
	}

	ordinaryFailure := explicitGenerateRecord(false)
	ordinaryFailure.Provider = "codex"
	ordinaryFailure.AuthID = "terminal"
	ordinaryFailure.AuthIndex = "terminal"
	ordinaryFailure.RequestedAt = now
	ordinaryFailure.Failed = true
	ordinaryFailure.Failure = usageFailure{StatusCode: http.StatusInternalServerError}
	if err := s.recordUsage(ctx, ordinaryFailure); err != nil {
		t.Fatalf("record non-generation terminal failure: %v", err)
	}
	var reservations, restrictions int
	if err := db.QueryRow(`SELECT COUNT(*) FROM account_protection_reservations WHERE provider='codex' AND auth_index='terminal'`).Scan(&reservations); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT
		(SELECT COUNT(*) FROM invalid_auths WHERE provider='codex' AND auth_id='terminal' AND active=1) +
		(SELECT COUNT(*) FROM autoban_bans WHERE provider='codex' AND auth_id='terminal' AND active=1)`).Scan(&restrictions); err != nil {
		t.Fatal(err)
	}
	if reservations != 0 || restrictions != 0 {
		t.Fatalf("ordinary audit failure left reservation/restriction=%d/%d, want 0/0", reservations, restrictions)
	}

	for i := 0; i < forbiddenInvalidAuthThreshold; i++ {
		forbidden := explicitGenerateRecord(false)
		forbidden.Provider = "codex"
		forbidden.AuthID = "audit-403"
		forbidden.AuthIndex = "audit-403"
		forbidden.RequestedAt = now.Add(time.Duration(i+1) * time.Second)
		forbidden.Failed = true
		forbidden.Failure = usageFailure{StatusCode: http.StatusForbidden}
		if err := s.recordUsage(ctx, forbidden); err != nil {
			t.Fatalf("record non-generation 403: %v", err)
		}
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM invalid_auths WHERE provider='codex' AND auth_id='audit-403' AND active=1`).Scan(&restrictions); err != nil {
		t.Fatal(err)
	}
	if restrictions != 0 {
		t.Fatalf("non-generation 403 callbacks created %d credential restrictions", restrictions)
	}

	unauthorized := explicitGenerateRecord(false)
	unauthorized.Provider = "codex"
	unauthorized.AuthID = "audit-401"
	unauthorized.AuthIndex = "audit-401"
	unauthorized.RequestedAt = now.Add(10 * time.Second)
	unauthorized.Failed = true
	unauthorized.Failure = usageFailure{StatusCode: http.StatusUnauthorized}
	if err := s.recordUsage(ctx, unauthorized); err != nil {
		t.Fatalf("record explicit 401 credential signal: %v", err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM invalid_auths WHERE provider='codex' AND auth_id='audit-401' AND active=1`).Scan(&restrictions); err != nil {
		t.Fatal(err)
	}
	if restrictions != 1 {
		t.Fatalf("explicit non-generation 401 restrictions=%d, want 1", restrictions)
	}

	plainRateLimit := explicitGenerateRecord(false)
	plainRateLimit.Provider = "codex"
	plainRateLimit.AuthID = "audit-429-plain"
	plainRateLimit.AuthIndex = "audit-429-plain"
	plainRateLimit.RequestedAt = now.Add(20 * time.Second)
	plainRateLimit.Failed = true
	plainRateLimit.Failure = usageFailure{StatusCode: http.StatusTooManyRequests}
	if err := s.recordUsage(ctx, plainRateLimit); err != nil {
		t.Fatalf("record ordinary non-generation 429: %v", err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM autoban_bans WHERE provider='codex' AND auth_id='audit-429-plain' AND active=1`).Scan(&restrictions); err != nil {
		t.Fatal(err)
	}
	if restrictions != 0 {
		t.Fatalf("non-generation 429 without quota evidence created %d bans", restrictions)
	}

	resetAt := now.Add(time.Hour).Unix()
	explicitQuota := explicitGenerateRecord(false)
	explicitQuota.Provider = "codex"
	explicitQuota.AuthID = "audit-429-quota"
	explicitQuota.AuthIndex = "audit-429-quota"
	explicitQuota.RequestedAt = now.Add(30 * time.Second)
	explicitQuota.Failed = true
	explicitQuota.Failure = usageFailure{StatusCode: http.StatusTooManyRequests}
	explicitQuota.ResponseHeaders = map[string][]string{
		"x-codex-primary-used-percent": {"100"},
		"x-codex-primary-reset-at":     {strconv.FormatInt(resetAt, 10)},
	}
	if err := s.recordUsage(ctx, explicitQuota); err != nil {
		t.Fatalf("record explicit non-generation quota signal: %v", err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM autoban_bans WHERE provider='codex' AND auth_id='audit-429-quota' AND active=1`).Scan(&restrictions); err != nil {
		t.Fatal(err)
	}
	if restrictions != 1 {
		t.Fatalf("explicit non-generation quota signal bans=%d, want 1", restrictions)
	}
}

func TestUsageGenerateFalseSuccessDoesNotClearCodexRestrictions(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	db, _, err := s.open(ctx)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if _, err := db.Exec(`
INSERT INTO invalid_auths(auth_id,auth_index,provider,reason,invalidated_at,active,last_status_code)
VALUES('recovery-account','recovery-account','codex','test invalid',?,1,401);
INSERT INTO autoban_bans(auth_id,auth_index,provider,window,reason,banned_at,reset_at,active,last_status_code)
VALUES('recovery-account','recovery-account','codex','5h','test ban',?,?,1,429);`,
		now.Unix(), now.Unix(), now.Add(time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}

	auditSuccess := explicitGenerateRecord(false)
	auditSuccess.Provider = providerCodex
	auditSuccess.AuthID = "recovery-account"
	auditSuccess.AuthIndex = "recovery-account"
	auditSuccess.RequestedAt = now.Add(time.Second)
	auditSuccess.Failure.StatusCode = http.StatusNoContent
	if err := s.recordUsage(ctx, auditSuccess); err != nil {
		t.Fatalf("record non-generation success: %v", err)
	}
	var invalidActive, banActive int
	if err := db.QueryRow(`SELECT
		(SELECT active FROM invalid_auths WHERE provider='codex' AND auth_id='recovery-account'),
		(SELECT active FROM autoban_bans WHERE provider='codex' AND auth_id='recovery-account')`).Scan(&invalidActive, &banActive); err != nil {
		t.Fatal(err)
	}
	if invalidActive != 1 || banActive != 1 {
		t.Fatalf("non-generation success cleared Codex restrictions: invalid=%d ban=%d", invalidActive, banActive)
	}

	generationSuccess := explicitGenerateRecord(true)
	generationSuccess.Provider = providerCodex
	generationSuccess.AuthID = "recovery-account"
	generationSuccess.AuthIndex = "recovery-account"
	generationSuccess.RequestedAt = now.Add(2 * time.Second)
	generationSuccess.Failure.StatusCode = http.StatusOK
	if err := s.recordUsage(ctx, generationSuccess); err != nil {
		t.Fatalf("record generation success: %v", err)
	}
	if err := db.QueryRow(`SELECT
		(SELECT active FROM invalid_auths WHERE provider='codex' AND auth_id='recovery-account'),
		(SELECT active FROM autoban_bans WHERE provider='codex' AND auth_id='recovery-account')`).Scan(&invalidActive, &banActive); err != nil {
		t.Fatal(err)
	}
	if invalidActive != 0 || banActive != 0 {
		t.Fatalf("generation success did not clear Codex restrictions: invalid=%d ban=%d", invalidActive, banActive)
	}
}

func TestProtectionUsageAndReleaseRespectGenerateAndProvider(t *testing.T) {
	ctx := context.Background()
	db := newProtectionTestDB(t)
	now := time.Now().Unix()
	if _, err := db.Exec(`INSERT INTO usage_events
		(requested_at, provider, auth_id, auth_index, total_tokens, generate)
		VALUES (?, 'codex', 'generated', 'generated', 100, 1),
		       (?, 'codex', 'audit-only', 'audit-only', 900, 0)`, now, now); err != nil {
		t.Fatal(err)
	}
	snapshot, err := loadProtectionUsageSnapshot(ctx, db, now-1)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot) != 1 || snapshot[0].Tokens != 100 || !containsString(snapshot[0].Aliases, "generated") {
		t.Fatalf("protection usage snapshot includes audit-only tokens: %+v", snapshot)
	}

	for _, authFile := range []string{"a.json", "b.json"} {
		if _, err := db.Exec(`INSERT INTO account_protection_reservations
			(provider, auth_id, auth_index, source, auth_file, plan_type, created_at, expires_at)
			VALUES ('codex', 'shared', 'shared', 'shared@example.com', ?, 'plus', ?, ?)`, authFile, now, now+900); err != nil {
			t.Fatal(err)
		}
	}
	matched, err := releaseProtectionReservation(ctx, db, usageRecord{
		Provider: "xai", AuthID: "shared", AuthIndex: "shared", AuthFile: "a.json",
	})
	if err != nil {
		t.Fatal(err)
	}
	if matched {
		t.Fatal("xAI callback released a Codex reservation")
	}
	matched, err = releaseProtectionReservation(ctx, db, usageRecord{
		Provider: "codex", AuthID: "shared", AuthIndex: "shared", AuthFile: "a.json",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !matched {
		t.Fatal("strict Codex auth-file identity did not release its reservation")
	}
	var remaining string
	if err := db.QueryRow(`SELECT auth_file FROM account_protection_reservations WHERE provider='codex'`).Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if remaining != "b.json" {
		t.Fatalf("strict reservation release removed %q sibling, want b.json to remain", remaining)
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
