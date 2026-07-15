package main

import "testing"

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
