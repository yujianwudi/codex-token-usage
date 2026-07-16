package main

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestTruncateSummaryResponsePreservesExactRequestedLimit(t *testing.T) {
	data := map[string]any{
		"accounts":   []accountRow{{AuthID: "a"}, {AuthID: "b"}, {AuthID: "c"}},
		"models":     []any{"a", "b", "c"},
		"totals":     map[string]any{"requests": 3},
		"precompute": summaryPrecomputeInfo{Limit: 50},
	}
	truncateSummaryResponse(data, 2)
	if got := len(data["accounts"].([]accountRow)); got != 2 {
		t.Fatalf("accounts length = %d, want 2", got)
	}
	if got := len(data["models"].([]any)); got != 2 {
		t.Fatalf("models length = %d, want 2", got)
	}
	if data["totals"] == nil {
		t.Fatal("non-list summary field was removed")
	}
	if got := data["requested_limit"]; got != 2 {
		t.Fatalf("requested_limit = %v, want 2", got)
	}
	if got := data["precompute"].(summaryPrecomputeInfo).Limit; got != 2 {
		t.Fatalf("precompute limit = %d, want exact requested limit 2", got)
	}
}

func TestSummaryResponseDoesNotExposeDatabasePath(t *testing.T) {
	s := newTestStore(t)
	_, path, err := s.open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	data, err := s.summary(context.Background(), "24h", 50)
	if err != nil {
		t.Fatal(err)
	}
	label, _ := data["db_path"].(string)
	if label == "" || label == path || strings.Contains(label, filepath.Dir(path)) {
		t.Fatalf("summary db_path leaked filesystem layout: %q (raw %q)", label, path)
	}
	diagnostics, ok := data["diagnostics"].(diagnosticsSummary)
	if !ok {
		t.Fatalf("summary diagnostics type = %T", data["diagnostics"])
	}
	if diagnostics.Database.Path == path || strings.Contains(diagnostics.Database.Path, filepath.Dir(path)) {
		t.Fatalf("database diagnostics leaked filesystem layout: %q", diagnostics.Database.Path)
	}
}

func TestCachedSummaryPathSanitizationHandlesLegacyMaps(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "legacy-sensitive-user")
	data := map[string]any{
		"db_path": filepath.Join(dir, "usage.db"),
		"diagnostics": map[string]any{
			"database":     map[string]any{"path": filepath.Join(dir, "usage.db")},
			"model_prices": map[string]any{"path": filepath.Join(dir, "prices.json")},
		},
	}
	sanitizeSummaryDiagnosticPaths(data)
	encoded := fmt.Sprint(data)
	if strings.Contains(encoded, dir) || strings.Contains(encoded, "legacy-sensitive-user") {
		t.Fatalf("legacy cached summary retained raw paths: %s", encoded)
	}
	first := data["db_path"].(string)
	sanitizeSummaryDiagnosticPaths(data)
	if data["db_path"].(string) != first {
		t.Fatalf("opaque path label was not idempotent: %q -> %q", first, data["db_path"])
	}
}

func TestSummaryCacheErrorIsStoredAndReturnedAsFixedCode(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	key := normalizeSummaryCacheKey(summaryCacheKey{Window: "24h", Limit: 50})
	secret := `C:\Users\private\usage.db sk-proj-summary-error-canary-1234567890`
	entry := summaryCacheEntry{
		data:     map[string]any{"totals": totalsRow{}},
		cachedAt: time.Now(),
		err:      secret,
	}
	if err := s.saveSummaryCacheEntry(ctx, key, entry); err != nil {
		t.Fatal(err)
	}
	db, _, err := s.open(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var stored string
	if err := db.QueryRowContext(ctx, `SELECT last_error FROM summary_cache WHERE cache_key=?`, summaryCacheStorageKey(key)).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != "summary_refresh_failed" {
		t.Fatalf("stored summary error=%q, want fixed code", stored)
	}
	loaded, ok, err := s.loadSummaryCacheEntry(ctx, key)
	if err != nil || !ok {
		t.Fatalf("load summary cache ok=%v err=%v", ok, err)
	}
	data := cloneCachedSummary(loaded, key, normalizePluginConfig(defaultPluginConfig()), 0)
	precompute, ok := data["precompute"].(summaryPrecomputeInfo)
	if !ok {
		t.Fatalf("cached summary precompute=%#v, want summaryPrecomputeInfo", data["precompute"])
	}
	if precompute.LastError != "summary_refresh_failed" {
		t.Fatalf("cached summary error=%q, want summary_refresh_failed", precompute.LastError)
	}
	encoded := fmt.Sprint(data)
	if strings.Contains(encoded, "sk-proj-") || strings.Contains(encoded, `C:\Users\private`) {
		t.Fatalf("cached summary exposed legacy error details: %s", encoded)
	}
}
