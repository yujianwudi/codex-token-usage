package main

import (
	"strings"
	"testing"
)

func TestDashboardCSPUsesInlineScriptHash(t *testing.T) {
	var scriptSources []string
	for _, directive := range strings.Split(dashboardCSP, ";") {
		fields := strings.Fields(directive)
		if len(fields) > 0 && fields[0] == "script-src" {
			scriptSources = fields[1:]
			break
		}
	}
	if len(scriptSources) == 0 {
		t.Fatalf("dashboard CSP has no script-src directive: %q", dashboardCSP)
	}
	for _, source := range scriptSources {
		if source == "'unsafe-inline'" {
			t.Fatal("dashboard script CSP must not allow arbitrary inline JavaScript")
		}
	}
	hash := inlineAssetSHA256(dashboardHTML, "<script>", "</script>")
	if hash == "" {
		t.Fatal("rendered dashboard has no inline-script hash")
	}
	wantHash := "'sha256-" + hash + "'"
	foundHash := false
	for _, source := range scriptSources {
		if source == wantHash {
			foundHash = true
			break
		}
	}
	if !foundHash {
		t.Fatalf("dashboard CSP does not contain the rendered inline-script hash: %q", dashboardCSP)
	}
}
