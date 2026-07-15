package main

import (
	"bytes"
	"context"
	"encoding/csv"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestMaskAPIKeyForDisplay(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  string
	}{
		{name: "stored fingerprint v1", value: "keyfp:v1:0123456789abcdef0123456789abcdef:wxyz", want: "key-****wxyz"},
		{name: "stored fingerprint v0", value: "keyfp:v0:ABCDEF0123456789ABCDEF0123456789:9Z_-", want: "key-****9Z_-"},
		{name: "OpenAI project", value: "sk-proj-1234567890abcdef", want: "sk-proj-****cdef"},
		{name: "OpenAI legacy", value: "sk-1234567890abcdef", want: "sk-****cdef"},
		{name: "Anthropic", value: "sk-ant-api03-1234567890abcdef", want: "sk-ant-****cdef"},
		{name: "Gemini", value: "AIzaSy1234567890abcdefghijklmnop", want: "AIza****mnop"},
		{name: "xAI", value: "xai-1234567890abcdef", want: "xai-****cdef"},
		{name: "opaque bearer", value: "bEaReR opaque-1234567890", want: "Bearer ****7890"},
		{name: "known bearer", value: "Bearer sk-1234567890abcdef", want: "Bearer sk-****cdef"},
		{name: "short bearer", value: "Bearer tiny", want: "Bearer ****"},
		{name: "arbitrary API key", value: "opaque-provider-key-1234567890", want: "key-****7890"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := maskAPIKeyForDisplay(tt.value); got != tt.want {
				t.Fatalf("maskAPIKeyForDisplay(%q) = %q, want %q", tt.value, got, tt.want)
			}
		})
	}
}

func TestDiagnosticPathsUseOpaqueLabels(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "sensitive-user-name", "private")
	dbPath := filepath.Join(dir, "usage.db")
	pricePath := filepath.Join(dir, "model_prices.json")
	for name, label := range map[string]string{
		"database": diagnosticPathLabel(dbPath),
		"prices":   buildModelPriceDiagnostics(modelPriceUpdateState{Path: pricePath}).Path,
	} {
		if label == "" || strings.Contains(label, dir) || strings.Contains(label, "sensitive-user-name") || strings.Contains(label, filepath.Base(dbPath)) || strings.Contains(label, filepath.Base(pricePath)) {
			t.Fatalf("%s diagnostic path leaked filesystem layout: %q", name, label)
		}
		if !opaqueDiagnosticPathLabel(label) {
			t.Fatalf("%s diagnostic path is not a strict opaque label: %q", name, label)
		}
	}
	if opaqueDiagnosticPathLabel("secret-name#deadbeef") {
		t.Fatal("legacy basename labels must not bypass path sanitization")
	}
}

func TestDiagnosticPathLabelsFailClosedWithoutRandomKey(t *testing.T) {
	oldKey := diagnosticPathLabelKey
	diagnosticPathLabelKey = nil
	t.Cleanup(func() { diagnosticPathLabelKey = oldKey })
	first := diagnosticPathLabel(filepath.Join(t.TempDir(), "first-secret.db"))
	second := diagnosticPathLabel(filepath.Join(t.TempDir(), "second-secret.db"))
	if first != "path#0000000000000000" || second != first || !opaqueDiagnosticPathLabel(first) {
		t.Fatalf("randomness failure did not produce a constant opaque label: %q / %q", first, second)
	}
}

func TestSafeExportLabelPreservesOrdinaryAccounts(t *testing.T) {
	tests := []string{
		"user@example.com",
		"production-account-01",
		"BearerSmith",
		"codex-account.json",
	}
	for _, value := range tests {
		if got := safeExportLabel(value); got != value {
			t.Errorf("safeExportLabel(%q) = %q, want unchanged", value, got)
		}
	}
	if got := safeExportLabel("Bearer opaque-provider-key"); got == "Bearer opaque-provider-key" {
		t.Fatal("Bearer credentials must be masked even when their token has no known provider prefix")
	}
}

func TestAccountExportMasksFingerprintFields(t *testing.T) {
	fingerprint := "keyfp:v1:0123456789abcdef0123456789abcdef:wxyz"
	rows := accountExportRows([]accountRow{{Email: "user@example.com", AuthIndex: fingerprint}})
	if len(rows) != 1 {
		t.Fatalf("accountExportRows returned %d rows, want 1", len(rows))
	}
	if got := rows[0]["account"]; got != "user@example.com" {
		t.Fatalf("account label = %q, want ordinary email unchanged", got)
	}
	if got := rows[0]["auth_index"]; got != "key-****wxyz" {
		t.Fatalf("auth_index = %q, want fingerprint display mask", got)
	}
}

func TestKeySummaryFilterIDSeparatesMatchingDisplaySuffixes(t *testing.T) {
	first := "keyfp:v1:0123456789abcdef0123456789abcdef:same"
	second := "keyfp:v1:fedcba9876543210fedcba9876543210:same"
	if maskAPIKeyForDisplay(first) != maskAPIKeyForDisplay(second) {
		t.Fatal("test keys must share the same display mask")
	}
	if keySummaryFilterID(first) == keySummaryFilterID(second) {
		t.Fatal("distinct stored keys received the same filter identifier")
	}
}

func TestExportLogRecordsAppliesKeyFilterBeforeLimit(t *testing.T) {
	t.Setenv("CPA_CONFIG_PATH", filepath.Join(t.TempDir(), "missing-config.yaml"))
	db, err := openSQLiteDB(filepath.Join(t.TempDir(), "usage.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Exec(schemaSQL); err != nil {
		t.Fatal(err)
	}

	selectedKey := "keyfp:v1:0123456789abcdef0123456789abcdef:same"
	otherKey := "keyfp:v1:fedcba9876543210fedcba9876543210:same"
	now := time.Now().Unix()
	if _, err := db.Exec(`INSERT INTO usage_events(requested_at,provider,api_key,auth_id,total_tokens) VALUES
		(?, 'codex', ?, 'selected-account', 1),
		(?, 'codex', ?, 'other-account', 1)`, now-10, selectedKey, now, otherKey); err != nil {
		t.Fatal(err)
	}
	summaries, err := queryKeySummaries(context.Background(), db, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(summaries) != 2 {
		t.Fatalf("key summaries = %d, want 2", len(summaries))
	}
	if summaries[0].KeyID == summaries[1].KeyID {
		t.Fatal("key summaries must expose distinct filter identifiers")
	}
	if summaries[0].KeyDisplay != summaries[1].KeyDisplay {
		t.Fatalf("test keys must retain the same display mask: %q != %q", summaries[0].KeyDisplay, summaries[1].KeyDisplay)
	}

	records, _, err := exportLogRecords(context.Background(), db, logExportFilter{
		Window:  "all",
		Scope:   "codex",
		Account: keySummaryFilterID(selectedKey),
		Limit:   1,
	}, defaultModelPrices())
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("filtered export returned %d records, want 1", len(records))
	}
	if got := records[0]["auth_id"]; got != "selected-account" {
		t.Fatalf("filtered export auth_id = %q, want selected-account", got)
	}

	legacyRecords, _, err := exportLogRecords(context.Background(), db, logExportFilter{
		Window:  "all",
		Scope:   "codex",
		Account: maskAPIKeyForDisplay(selectedKey),
		Limit:   10,
	}, defaultModelPrices())
	if err != nil {
		t.Fatal(err)
	}
	if len(legacyRecords) != 0 {
		t.Fatalf("ambiguous display-mask filter returned %d records, want fail-closed empty result", len(legacyRecords))
	}
}

func TestSafeCSVCellPreventsFormulaInjection(t *testing.T) {
	tests := []struct {
		value string
		want  string
	}{
		{value: "=1+1", want: "'=1+1"},
		{value: "+cmd", want: "'+cmd"},
		{value: "-2", want: "'-2"},
		{value: "@SUM(A1:A2)", want: "'@SUM(A1:A2)"},
		{value: "  =1+1", want: "'  =1+1"},
		{value: "\t=1+1", want: "'\t=1+1"},
		{value: "\r=1+1", want: "'\r=1+1"},
		{value: "\n=1+1", want: "'\n=1+1"},
		{value: "42", want: "42"},
		{value: "user@example.com", want: "user@example.com"},
		{value: "text=still-text", want: "text=still-text"},
	}
	for _, tt := range tests {
		if got := safeCSVCell(tt.value); got != tt.want {
			t.Errorf("safeCSVCell(%q) = %q, want %q", tt.value, got, tt.want)
		}
	}
}

func TestRecordsToCSVSanitizesHeadersAndValues(t *testing.T) {
	body, err := recordsToCSV(
		[]string{"value", "+unsafe_header"},
		[]map[string]string{{"value": "=HYPERLINK(\"https://example.invalid\")", "+unsafe_header": "safe"}},
	)
	if err != nil {
		t.Fatal(err)
	}
	body = bytes.TrimPrefix(body, []byte("\xEF\xBB\xBF"))
	rows, err := csv.NewReader(bytes.NewReader(body)).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	want := [][]string{
		{"value", "'+unsafe_header"},
		{"'=HYPERLINK(\"https://example.invalid\")", "safe"},
	}
	if !reflect.DeepEqual(rows, want) {
		t.Fatalf("CSV rows = %#v, want %#v", rows, want)
	}
}
