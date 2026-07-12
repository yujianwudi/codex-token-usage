package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func newTestStore(t *testing.T) *store {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("CPA_TOKEN_USAGE_DIR", dir)
	t.Setenv("CPA_AUTH_DIR", filepath.Join(dir, "auth"))
	s := &store{}
	t.Cleanup(s.close)
	return s
}

func TestSummaryCacheInvalidatesAfterUsageRevisionChange(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	cfg := normalizePluginConfig(defaultPluginConfig())
	cfg.SummaryPrecomputeMode = "active_dirty"

	m := &summaryPrecomputeManager{}
	data, err := m.summary(ctx, s, "24h", 50)
	if err != nil {
		t.Fatalf("first summary: %v", err)
	}
	if totals, ok := data["totals"].(totalsRow); !ok || totals.Requests != 0 {
		t.Fatalf("initial totals = %#v, want 0 requests", data["totals"])
	}
	if _, ok := data["store_revision"]; !ok {
		t.Fatalf("summary missing store_revision")
	}

	if err := s.recordUsage(ctx, usageRecord{
		Provider:     "codex",
		ExecutorType: "CodexExecutor",
		Model:        "gpt-5.5",
		AuthID:       "alice@example.com",
		AuthIndex:    "alice.cpa.json",
		Source:       "alice@example.com",
		RequestedAt:  time.Now(),
		Detail:       usageDetail{InputTokens: 11, OutputTokens: 22, TotalTokens: 33},
	}); err != nil {
		t.Fatalf("record usage: %v", err)
	}

	data, err = m.summary(ctx, s, "24h", 50)
	if err != nil {
		t.Fatalf("second summary: %v", err)
	}
	totals, ok := data["totals"].(totalsRow)
	if !ok {
		t.Fatalf("totals type = %T", data["totals"])
	}
	if totals.Requests != 1 || totals.TotalTokens != 33 {
		t.Fatalf("totals after usage = %+v, want one fresh request", totals)
	}
	if pre, ok := data["precompute"].(summaryPrecomputeInfo); ok && pre.Hit {
		t.Fatalf("summary reused stale cache after usage revision changed: %+v", pre)
	}
}

func TestSummaryMaintenanceSkipsWhenRevisionAndAuthFilesUnchanged(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	globalStore = s
	t.Cleanup(func() { globalStore = &store{} })

	if err := s.recordUsage(ctx, usageRecord{
		Provider:    "codex",
		Model:       "gpt-5.5",
		AuthID:      "alice@example.com",
		AuthIndex:   "alice.cpa.json",
		Source:      "alice@example.com",
		RequestedAt: time.Now(),
		Detail:      usageDetail{TotalTokens: 1},
	}); err != nil {
		t.Fatalf("record usage: %v", err)
	}

	m := &summaryMaintenanceManager{}
	m.run(ctx)
	first := m.status()
	if first.SkippedReason != "" {
		t.Fatalf("first maintenance skipped unexpectedly: %+v", first)
	}
	m.run(ctx)
	second := m.status()
	if second.SkippedReason != "unchanged" {
		t.Fatalf("second maintenance skipped_reason = %q, want unchanged; state=%+v", second.SkippedReason, second)
	}
	if second.LastProcessedUsageEventID == 0 {
		t.Fatalf("maintenance did not record processed usage event id: %+v", second)
	}
}

func TestSummaryMaintenanceUsesLightModeAfterNewUsageWithoutAuthFileChange(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	globalStore = s
	t.Cleanup(func() { globalStore = &store{} })

	m := &summaryMaintenanceManager{}
	m.run(ctx)
	first := m.status()
	if first.LastMode != "full" {
		t.Fatalf("first maintenance mode = %q, want full; state=%+v", first.LastMode, first)
	}

	if err := s.recordUsage(ctx, usageRecord{
		Provider:    "codex",
		Model:       "gpt-5.5",
		AuthID:      "alice@example.com",
		AuthIndex:   "alice.cpa.json",
		Source:      "alice@example.com",
		RequestedAt: time.Now(),
		Detail:      usageDetail{TotalTokens: 2},
	}); err != nil {
		t.Fatalf("record usage: %v", err)
	}

	m.run(ctx)
	second := m.status()
	if second.LastMode != "light" {
		t.Fatalf("maintenance mode after new usage = %q, want light; state=%+v", second.LastMode, second)
	}
	if second.SkippedReason != "" {
		t.Fatalf("light maintenance should run, not skip: %+v", second)
	}
}

func TestParseLowUsageConfigDefaultsAndOverrides(t *testing.T) {
	cfg := normalizePluginConfig(defaultPluginConfig())
	if cfg.SummaryPrecomputeMode != "active_dirty" {
		t.Fatalf("default precompute mode = %q, want active_dirty", cfg.SummaryPrecomputeMode)
	}
	if cfg.SummaryCacheMaxAgeSeconds != 5 {
		t.Fatalf("default cache max age = %d, want 5", cfg.SummaryCacheMaxAgeSeconds)
	}
	if cfg.SummaryMaintenanceIntervalSeconds != 180 {
		t.Fatalf("default maintenance interval = %d, want 180", cfg.SummaryMaintenanceIntervalSeconds)
	}

	cfg = parsePluginConfigYAML([]byte(`
summary_precompute_mode: legacy
summary_cache_max_age_seconds: 9
summary_maintenance_interval_seconds: 240
summary_precompute_active_window_ttl_seconds: 900
`), cfg)
	cfg = normalizePluginConfig(cfg)
	if cfg.SummaryPrecomputeMode != "legacy" || cfg.SummaryCacheMaxAgeSeconds != 9 || cfg.SummaryMaintenanceIntervalSeconds != 240 || cfg.SummaryPrecomputeActiveWindowTTLSeconds != 900 {
		t.Fatalf("overridden config not applied: %+v", cfg)
	}
}

func TestInvalidAuthUsesEventTimeSoNewAuthFileClearsOld401(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	authDir := os.Getenv("CPA_AUTH_DIR")
	if err := os.MkdirAll(authDir, 0755); err != nil {
		t.Fatalf("mkdir auth dir: %v", err)
	}
	authFile := "alice.cpa.json"
	authPath := filepath.Join(authDir, authFile)
	oldFailureAt := time.Now().Add(-10 * time.Minute).Truncate(time.Second)
	newFileAt := oldFailureAt.Add(5 * time.Minute)
	if err := os.WriteFile(authPath, []byte(`{"email":"alice@example.com","provider":"codex","access_token":"token"}`), 0600); err != nil {
		t.Fatalf("write auth file: %v", err)
	}
	if err := os.Chtimes(authPath, newFileAt, newFileAt); err != nil {
		t.Fatalf("chtimes auth file: %v", err)
	}
	db, _, err := s.open(ctx)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}

	err = recordInvalidAuthIfNeeded(ctx, db, usageRecord{
		Provider:    "codex",
		AuthID:      "alice@example.com",
		AuthIndex:   authFile,
		AuthFile:    authFile,
		Source:      "alice@example.com",
		RequestedAt: oldFailureAt,
		Failed:      true,
		Failure:     usageFailure{StatusCode: 401},
	}, 401)
	if err != nil {
		t.Fatalf("record invalid auth: %v", err)
	}
	invalids, err := queryActiveInvalidAuths(ctx, db)
	if err != nil {
		t.Fatalf("query invalids: %v", err)
	}
	if len(invalids) != 1 {
		t.Fatalf("active invalids after record = %d, want 1", len(invalids))
	}
	if invalids[0].InvalidatedAt != oldFailureAt.Unix() {
		t.Fatalf("invalidated_at = %d, want event time %d", invalids[0].InvalidatedAt, oldFailureAt.Unix())
	}
	if err := clearReplacedInvalidAuths(ctx, db); err != nil {
		t.Fatalf("clear replaced invalid auths: %v", err)
	}
	invalids, err = queryActiveInvalidAuths(ctx, db)
	if err != nil {
		t.Fatalf("query invalids after clear: %v", err)
	}
	if len(invalids) != 0 {
		t.Fatalf("old 401 remained active after newer auth file: %+v", invalids)
	}
}

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}
