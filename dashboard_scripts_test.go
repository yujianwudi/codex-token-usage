package main

import (
	"strings"
	"testing"
)

func dashboardScriptSection(t *testing.T, startMarker, endMarker string) string {
	t.Helper()
	start := strings.Index(dashboardScripts, startMarker)
	if start < 0 {
		t.Fatalf("dashboard script section start %q not found", startMarker)
	}
	end := strings.Index(dashboardScripts[start:], endMarker)
	if end < 0 {
		t.Fatalf("dashboard script section end %q not found after %q", endMarker, startMarker)
	}
	return dashboardScripts[start : start+end]
}

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

func TestManagementKeyIsNotCopiedIntoWebStorage(t *testing.T) {
	for _, marker := range []string{
		"safeStorageSet(safeSessionStorage(),'cpa_token_usage_key'",
		"safeStorageSet(safeSessionStorage(),'cpa_token_usage_rejected_key'",
		"safeStorageSet(safeSessionStorage(),'cpa_token_usage_rejected_at'",
	} {
		if strings.Contains(dashboardScripts, marker) {
			t.Fatalf("plugin dashboard must not copy management-key state into Web Storage: %q", marker)
		}
	}
	for _, marker := range []string{"let transientManagementKey=''", "let rejectedManagementKey=''", "transientManagementKey=key"} {
		if !strings.Contains(dashboardScripts, marker) {
			t.Fatalf("dashboard script missing in-memory management-key marker %q", marker)
		}
	}
	for _, marker := range []string{
		"if(firstText(transientManagementKey)===key)transientManagementKey=''",
		"if(firstText(keyEl.value)===key)keyEl.value=''",
	} {
		if !strings.Contains(dashboardScripts, marker) {
			t.Fatalf("stale 401 protection missing marker %q", marker)
		}
	}
	if !strings.Contains(dashboardBody, `id="key" class="fallback-key" type="password" autocomplete="off"`) {
		t.Fatal("management-key input must not opt into browser password persistence")
	}
	for _, legacyName := range []string{"cpa_token_usage_key", "cpa_token_usage_rejected_key", "cpa_token_usage_rejected_at"} {
		if !strings.Contains(dashboardScripts, "safeStorageRemove(storage,'"+legacyName+"')") {
			t.Fatalf("dashboard must scrub legacy session storage entry %q after upgrade", legacyName)
		}
	}
}

func TestDashboardClearsImportedTokensAndProxyCredentials(t *testing.T) {
	for _, fragment := range []string{
		"function wipeAuthImportSecrets(){",
		"authImportReadGeneration++;\n  authImportReadPending=false;\n  authImportTextEl.value='';",
		"function closeAuthImportModal(){wipeAuthImportSecrets();authImportModal.hidden=true}",
		"function clearAuthImport(){\n  wipeAuthImportSecrets();",
		"wipeAuthImportSecrets();\n    setAuthImportStatus(",
		"function closeBatchProxyModal(){batchProxyUrlEl.value='';batchProxyModal.hidden=true}",
		"if(failed===0)batchProxyUrlEl.value='';",
	} {
		if !strings.Contains(dashboardScripts, fragment) {
			t.Fatalf("dashboard secret cleanup missing %q", fragment)
		}
	}
	if !strings.Contains(dashboardBody, `id="batch-proxy-url" autocomplete="off" autocapitalize="none" spellcheck="false"`) {
		t.Fatal("proxy credential input must opt out of browser text persistence features")
	}
}

func TestAuthImportAsyncReadsCannotRestoreWipedSecrets(t *testing.T) {
	if !strings.Contains(dashboardScripts, "let authImportReadGeneration=0;") {
		t.Fatal("auth import file reads must have a cancellation generation")
	}

	start := strings.Index(dashboardScripts, "async function readAuthImportFiles(e){")
	if start < 0 {
		t.Fatal("readAuthImportFiles function not found")
	}
	end := strings.Index(dashboardScripts[start:], "\nfunction authImportKey(){")
	if end < 0 {
		t.Fatal("readAuthImportFiles function end not found")
	}
	readFiles := dashboardScripts[start : start+end]

	generationAt := strings.Index(readFiles, "const generation=++authImportReadGeneration;")
	writeAt := strings.Index(readFiles, "authImportTextEl.value=")
	statusAt := strings.LastIndex(readFiles, "setAuthImportStatus(")
	if generationAt < 0 || writeAt < 0 || statusAt < 0 {
		t.Fatalf("auth import read cancellation markers missing: %q", readFiles)
	}
	awaitCount := 0
	for offset := 0; ; {
		relativeAwait := strings.Index(readFiles[offset:], "await file.text()")
		if relativeAwait < 0 {
			break
		}
		awaitAt := offset + relativeAwait
		nextAwait := strings.Index(readFiles[awaitAt+1:], "await file.text()")
		segmentEnd := writeAt
		if nextAwait >= 0 {
			segmentEnd = awaitAt + 1 + nextAwait
		}
		if segmentEnd <= awaitAt {
			t.Fatalf("file.text await occurs after the final DOM write: %q", readFiles)
		}
		cancelAt := strings.Index(readFiles[awaitAt:segmentEnd], "if(generation!==authImportReadGeneration)return;")
		if cancelAt < 0 {
			t.Fatalf("file.text await at byte %d lacks its own cancellation check before the next await or DOM write: %q", awaitAt, readFiles)
		}
		awaitCount++
		offset = awaitAt + len("await file.text()")
	}
	if awaitCount == 0 || !(generationAt < writeAt && writeAt < statusAt) {
		t.Fatalf("auth import read ordering is incomplete: %q", readFiles)
	}
	if count := strings.Count(readFiles, "if(generation!==authImportReadGeneration)return;"); count < 2 {
		t.Fatalf("auth import reads must recheck cancellation after each file and before final DOM updates; found %d checks", count)
	}
}

func TestAuthImportPendingReadBlocksPreviewAndCommit(t *testing.T) {
	for _, marker := range []string{
		"let authImportReadPending=false;",
		"let authImportRequestBusy=false;",
		"authImportReadPending=files.length>0;",
		"if(generation===authImportReadGeneration){\n      authImportReadPending=false;",
		"document.getElementById('auth-import-preview').disabled=authImportRequestBusy||authImportReadPending;",
		"document.getElementById('auth-import-commit').disabled=authImportRequestBusy||authImportReadPending;",
		"document.getElementById('auth-import-clear').disabled=authImportRequestBusy;",
		"document.getElementById('auth-import-files').disabled=authImportRequestBusy;",
	} {
		if !strings.Contains(dashboardScripts, marker) {
			t.Fatalf("auth import pending-state marker %q not found", marker)
		}
	}

	readFiles := dashboardScriptSection(t, "async function readAuthImportFiles(e){", "\nfunction authImportKey(){")
	pendingAt := strings.Index(readFiles, "authImportReadPending=files.length>0;")
	awaitAt := strings.Index(readFiles, "await file.text()")
	finallyAt := strings.Index(readFiles, "}finally{")
	if pendingAt < 0 || awaitAt < 0 || pendingAt > awaitAt || finallyAt < 0 {
		t.Fatalf("auth import pending lifecycle markers are missing or misordered: %q", readFiles)
	}
	currentAt := strings.Index(readFiles[finallyAt:], "if(generation===authImportReadGeneration){")
	clearAt := strings.Index(readFiles[finallyAt:], "authImportReadPending=false;")
	if currentAt < 0 || clearAt < currentAt {
		t.Fatalf("auth import pending lifecycle is not generation-safe: %q", readFiles)
	}

	for _, tc := range []struct {
		start string
		end   string
		next  string
	}{
		{"async function previewAuthImport(){", "\nasync function commitAuthImport(){", "setAuthImportBusy(true)"},
		{"async function commitAuthImport(){", "\nfunction renderAuthImportResults(result){", "confirm("},
	} {
		section := dashboardScriptSection(t, tc.start, tc.end)
		guardAt := strings.Index(section, "if(authImportReadPending){")
		nextAt := strings.Index(section, tc.next)
		if guardAt < 0 || nextAt < 0 || guardAt > nextAt {
			t.Fatalf("%s must reject programmatic requests while file reads are pending: %q", tc.start, section)
		}
	}

	wipe := dashboardScriptSection(t, "function wipeAuthImportSecrets(){", "\nfunction closeAuthImportModal()")
	generationAt := strings.Index(wipe, "authImportReadGeneration++;")
	pendingClearAt := strings.Index(wipe, "authImportReadPending=false;")
	controlsAt := strings.Index(wipe, "updateAuthImportControls();")
	if generationAt < 0 || pendingClearAt < generationAt || controlsAt < pendingClearAt {
		t.Fatalf("wiping imported secrets must cancel pending reads and refresh controls: %q", wipe)
	}
}

func TestInvalidAuthOAuthPollingIsSingleFlightAndCancelable(t *testing.T) {
	for _, marker := range []string{
		"let invalidAuthOAuthGeneration=0;",
		"function cancelInvalidAuthOAuth(){",
		"function closeInvalidAuthModal(){cancelInvalidAuthOAuth();invalidAuthModal.hidden=true}",
		"invalidAuthOAuthUrlEl.innerHTML='';",
	} {
		if !strings.Contains(dashboardScripts, marker) {
			t.Fatalf("OAuth cancellation marker %q not found", marker)
		}
	}

	start := dashboardScriptSection(t, "async function startInvalidAuthOAuth(key){", "\nfunction pollInvalidAuthOAuth(")
	for _, marker := range []string{
		"cancelInvalidAuthOAuth();\n  const generation=invalidAuthOAuthGeneration;",
		"const before=await fetchAuthFilesForBatch(management);\n    if(generation!==invalidAuthOAuthGeneration)return;",
		"const res=await fetch(managementCodexAuthUrlApi",
		"const body=await readResponseBody(res);\n    if(generation!==invalidAuthOAuthGeneration)return;",
		"pollInvalidAuthOAuth(management,payload.state,row,before,startedAt,oldFile,oldEmail,generation);",
		"}catch(e){\n    if(generation!==invalidAuthOAuthGeneration)return;\n    cancelInvalidAuthOAuth();",
	} {
		if !strings.Contains(start, marker) {
			t.Fatalf("OAuth start flow missing generation guard %q: %q", marker, start)
		}
	}
	fetchAt := strings.Index(start, "const res=await fetch(managementCodexAuthUrlApi")
	if fetchAt < 0 {
		t.Fatalf("OAuth start fetch not found: %q", start)
	}
	fetchGuardAt := strings.Index(start[fetchAt:], "if(generation!==invalidAuthOAuthGeneration)return;")
	bodyAt := strings.Index(start[fetchAt:], "const body=await readResponseBody(res);")
	if fetchAt < 0 || fetchGuardAt < 0 || bodyAt < 0 || fetchGuardAt > bodyAt {
		t.Fatalf("OAuth start fetch must be generation-checked before reading its body: %q", start)
	}

	poll := dashboardScriptSection(t, "function pollInvalidAuthOAuth(", "\nasync function handleInvalidAuthOAuthSuccess(")
	if strings.Contains(poll, "setInterval(") || strings.Contains(poll, "clearInterval(") {
		t.Fatalf("OAuth polling must not use overlapping setInterval callbacks: %q", poll)
	}
	for _, marker := range []string{
		"const poll=async()=>{",
		"if(generation!==invalidAuthOAuthGeneration)return;\n    invalidAuthOAuthTimer=null;",
		"const res=await fetch(managementAuthStatusApi",
		"const body=await readResponseBody(res);\n      if(generation!==invalidAuthOAuthGeneration)return;",
		"invalidAuthOAuthTimer=setTimeout(poll,3000);",
		"await handleInvalidAuthOAuthSuccess(management,row,before,startedAt,oldFile,oldEmail,generation);\n      if(generation!==invalidAuthOAuthGeneration)return;",
		"}catch(e){\n      if(generation!==invalidAuthOAuthGeneration)return;\n      cancelInvalidAuthOAuth();",
	} {
		if !strings.Contains(poll, marker) {
			t.Fatalf("OAuth single-flight polling marker %q not found: %q", marker, poll)
		}
	}
	pollFetchAt := strings.Index(poll, "const res=await fetch(managementAuthStatusApi")
	if pollFetchAt < 0 {
		t.Fatalf("OAuth status fetch not found: %q", poll)
	}
	pollFetchGuardAt := strings.Index(poll[pollFetchAt:], "if(generation!==invalidAuthOAuthGeneration)return;")
	pollBodyAt := strings.Index(poll[pollFetchAt:], "const body=await readResponseBody(res);")
	if pollFetchAt < 0 || pollFetchGuardAt < 0 || pollBodyAt < 0 || pollFetchGuardAt > pollBodyAt {
		t.Fatalf("OAuth poll fetch must be generation-checked before reading its body: %q", poll)
	}

	success := dashboardScriptSection(t, "async function handleInvalidAuthOAuthSuccess(", "\nfunction findNewAuthForEmail(")
	for _, marker := range []string{
		"const after=await fetchAuthFilesForBatch(management);\n  if(generation!==invalidAuthOAuthGeneration)return;",
		"await load();\n  if(generation!==invalidAuthOAuthGeneration)return;",
		"if(match&&oldFile){\n    if(generation!==invalidAuthOAuthGeneration)return;",
		"if(ok){\n      if(generation!==invalidAuthOAuthGeneration)return;",
		"await deleteSelectedInvalidAuths();\n      if(generation!==invalidAuthOAuthGeneration)return;",
	} {
		if !strings.Contains(success, marker) {
			t.Fatalf("OAuth success flow missing stale-generation guard %q: %q", marker, success)
		}
	}
}

func TestBatchProxyNoFilesClearsCredentialURL(t *testing.T) {
	writeProxy := dashboardScriptSection(t, "async function writeBatchProxy(", "\nfunction syncLanguageControl()")
	noFilesAt := strings.Index(writeProxy, "if(!files.length){")
	if noFilesAt < 0 {
		t.Fatalf("batch proxy no-file path not found: %q", writeProxy)
	}
	clearAt := strings.Index(writeProxy[noFilesAt:], "batchProxyUrlEl.value='';")
	returnAt := strings.Index(writeProxy[noFilesAt:], "return}")
	if noFilesAt < 0 || clearAt < 0 || returnAt < 0 || clearAt > returnAt {
		t.Fatalf("batch proxy no-file path must clear the credential-bearing URL before returning: %q", writeProxy)
	}
}

func TestNonGeneratedRecentRowsDoNotReportThroughput(t *testing.T) {
	throughput := dashboardScriptSection(t, "function reliableThroughputSample(r){", "\nfunction avgThroughput(")
	if !strings.Contains(throughput, "if(r&&r.generate===false)return false;") {
		t.Fatalf("non-generated audit rows must not be treated as throughput samples: %q", throughput)
	}
}

func TestKeySummaryUsesFilterIDSeparateFromDisplayMask(t *testing.T) {
	for _, marker := range []string{
		"value:firstText(r.key_id,fallback)",
		"label:firstText(r.key_display,r.key_id,fallback)",
		"esc(r.key_display||r.key_id||'-')",
	} {
		if !strings.Contains(dashboardScripts, marker) {
			t.Fatalf("dashboard key filtering missing marker %q", marker)
		}
	}
}
