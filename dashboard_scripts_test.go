package main

import (
	"strings"
	"testing"
)

func TestPoolTabSwitchReappliesLocale(t *testing.T) {
	start := strings.Index(dashboardScripts, "function switchPage(page){")
	if start < 0 {
		t.Fatal("switchPage function not found")
	}
	end := strings.Index(dashboardScripts[start:], "\nfunction providerStorageKey()")
	if end < 0 {
		t.Fatal("switchPage function end not found")
	}
	switchPage := dashboardScripts[start : start+end]
	renderAt := strings.Index(switchPage, "renderPoolPage(lastData);")
	localeAt := strings.Index(switchPage, "applyLocale();")
	if renderAt < 0 || localeAt < 0 || localeAt < renderAt {
		t.Fatalf("pool tab switch must reapply locale after rendering: %q", switchPage)
	}
}

func TestXAITabRequiresConfiguredAccount(t *testing.T) {
	if !strings.Contains(dashboardBody, `data-target="xai" role="tab" aria-selected="false" hidden`) {
		t.Fatal("xAI tab must start hidden until configured credentials are loaded")
	}
	if !strings.Contains(dashboardScripts, `const xaiVisible=(data.xai_accounts||[]).some(r=>r.configured);`) {
		t.Fatal("xAI tab visibility must depend on configured xAI auth accounts")
	}
	if !strings.Contains(dashboardScripts, `if(!xaiVisible&&activePage==='xai')activePage='codex';`) {
		t.Fatal("removed xAI auth must return the dashboard to Codex")
	}
}
