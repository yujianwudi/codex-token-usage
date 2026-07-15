package main

import (
	"bytes"
	"encoding/csv"
	"reflect"
	"testing"
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
