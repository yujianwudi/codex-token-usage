package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestPublicErrorMessagesAreFixedAndLowSensitivity(t *testing.T) {
	for code, want := range map[string]string{
		"bad_request":        "request body is invalid",
		"summary_failed":     "summary is temporarily unavailable",
		"export_failed":      "export is temporarily unavailable",
		"release_failed":     "account state release could not be completed",
		"usage_invalid":      "usage payload is invalid",
		"usage_store_failed": "usage storage is temporarily unavailable",
	} {
		if got := publicErrorMessage(code); got != want {
			t.Fatalf("publicErrorMessage(%q)=%q, want %q", code, got, want)
		}
	}

	secret := `C:\Users\private\usage.db sk-proj-public-error-canary-1234567890`
	message := publicErrorMessage(secret)
	if message == "" || strings.Contains(message, "sk-proj-") || strings.Contains(message, `C:\Users\private`) {
		t.Fatalf("publicErrorMessage(%q)=%q", secret, message)
	}
}

func TestMalformedABIPayloadsDoNotEchoParserDetails(t *testing.T) {
	for _, method := range []string{"management.handle", "usage.handle"} {
		raw, err := handleMethod(method, []byte(`{"secret":"sk-proj-malformed-canary-1234567890"`))
		if err != nil {
			t.Fatalf("%s returned top-level error: %v", method, err)
		}
		var decoded map[string]any
		if err := json.Unmarshal(raw, &decoded); err != nil {
			t.Fatalf("decode %s response: %v body=%s", method, err, raw)
		}
		if strings.Contains(string(raw), "sk-proj-") || strings.Contains(strings.ToLower(string(raw)), "unexpected end") {
			t.Fatalf("%s exposed parser/input details: %s", method, raw)
		}
	}
}

func TestSafeHostErrorCodeRejectsUntrustedText(t *testing.T) {
	if got := safeHostErrorCode(" AUTH_UNAVAILABLE "); got != "auth_unavailable" {
		t.Fatalf("safe host code=%q", got)
	}
	for _, value := range []string{"", "sqlite C:\\private\\usage.db", "sk-proj-secret", strings.Repeat("a", 65)} {
		if got := safeHostErrorCode(value); got != "host_error" {
			t.Fatalf("safeHostErrorCode(%q)=%q, want host_error", value, got)
		}
	}
}
