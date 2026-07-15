package main

import (
	"strings"
	"testing"
)

func TestDashboardCSPUsesInlineScriptHash(t *testing.T) {
	if strings.Contains(dashboardCSP, "script-src 'self' 'unsafe-inline'") {
		t.Fatal("dashboard script CSP must not allow arbitrary inline JavaScript")
	}
	hash := inlineAssetSHA256(dashboardHTML, "<script>", "</script>")
	if hash == "" || !strings.Contains(dashboardCSP, "'sha256-"+hash+"'") {
		t.Fatalf("dashboard CSP does not contain the rendered inline-script hash: %q", dashboardCSP)
	}
}
