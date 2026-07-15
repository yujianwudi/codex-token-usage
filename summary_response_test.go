package main

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
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
