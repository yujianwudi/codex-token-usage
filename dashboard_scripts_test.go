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

func TestXAITierDisplayUsesMetadataFields(t *testing.T) {
	for _, marker := range []string{"r.xai_tier", "tier-free", "tier-super", "tier-heavy", "套餐分布"} {
		if !strings.Contains(dashboardScripts+dashboardStyles, marker) {
			t.Fatalf("xAI tier display marker %q not found", marker)
		}
	}
}

func TestInvalidAuthManagementUsesUnfilteredCountsAndPartialDeleteResults(t *testing.T) {
	for _, marker := range []string{
		"const allInvalidRows=",
		"const allWorkspaceRows=",
		"parseAuthFileDeleteResult(res,body,names)",
		"HTTP 207 部分删除失败",
		"/\\.json$/i.test(name)?name:''",
	} {
		if !strings.Contains(dashboardScripts, marker) {
			t.Fatalf("401 management marker %q not found", marker)
		}
	}
}

func TestNonStandardAuthImportUIUsesPluginHostSaveFlow(t *testing.T) {
	for _, marker := range []string{
		"账号 JSON 导入",
		"auth-import/preview",
		"auth-import/commit",
		"host.auth.save",
		"无 RT",
	} {
		if !strings.Contains(dashboardBody+dashboardScripts, marker) && !strings.Contains(dashboardBody+dashboardScripts+dashboardStyles, marker) {
			t.Fatalf("auth import UI marker %q not found", marker)
		}
	}
}

func TestEnglishLocaleTranslatesDynamicPhrasesBeforeUnits(t *testing.T) {
	for _, marker := range []string{
		"'账号 JSON 导入':'Import account JSON'",
		"'窗口：':'Window: '",
		"Object.entries(i18nEn).sort((left,right)=>right[0].length-left[0].length).forEach(pair=>exact(pair[0],pair[1]))",
		"'部分模型缺价格':'Some model prices missing'",
		"'管理接口':'Management API'",
		"'显示接入点':'Show endpoints'",
	} {
		if !strings.Contains(dashboardScripts, marker) {
			t.Fatalf("dashboard script missing English dynamic-phrase translation marker %q", marker)
		}
	}
}

func TestRecentRequestFieldsAreEscapedBeforeInnerHTML(t *testing.T) {
	start := strings.Index(dashboardScripts, "function renderRecent(target,rows,mode){")
	if start < 0 {
		t.Fatal("renderRecent function not found")
	}
	end := strings.Index(dashboardScripts[start:], "\napplyLocale();")
	if end < 0 {
		t.Fatal("renderRecent function end not found")
	}
	renderRecent := dashboardScripts[start : start+end]
	for _, marker := range []string{
		"esc(r.reasoning_effort)",
		"esc(detail)",
		"esc(firstText(r.model,model))",
		"esc(model)",
		"esc(who)",
		"esc(r.time||'-')",
		"esc(requestStatusText(r))",
	} {
		if !strings.Contains(renderRecent, marker) {
			t.Fatalf("renderRecent must HTML-escape dynamic marker %q", marker)
		}
	}
	if strings.Contains(renderRecent, "'+r.reasoning_effort+'") {
		t.Fatal("reasoning_effort must not be inserted into innerHTML without escaping")
	}
}

func TestOAuthURLIsValidatedBeforeRenderingOrOpening(t *testing.T) {
	for _, marker := range []string{
		"function safeOAuthURL(value){",
		"u.protocol!=='https:'",
		"!u.hostname",
		"u.username||u.password",
		"const oauthURL=safeOAuthURL(payload.url);",
		"href=\"'+esc(oauthURL)+'\"",
		"data-oauth-copy=\"'+esc(oauthURL)+'\"",
		"window.open(oauthURL,'_blank','noopener,noreferrer')",
	} {
		if !strings.Contains(dashboardScripts, marker) {
			t.Fatalf("dashboard OAuth flow missing safety marker %q", marker)
		}
	}
	if strings.Contains(dashboardScripts, "window.open(payload.url") {
		t.Fatal("raw OAuth response URL must never be opened")
	}
}

func TestInsightRowsEscapeAllInnerHTMLFields(t *testing.T) {
	marker := `items.map(r=>'<div class="insight '+esc(r[3])+'"><span>'+esc(r[0])+'</span><b title="'+esc(r[1])+'">'+esc(r[1])+'</b><span>'+esc(r[2])+'</span></div>')`
	if count := strings.Count(dashboardScripts, marker); count != 2 {
		t.Fatalf("both insight render paths must escape every dynamic field; found %d safe renderers", count)
	}
}
