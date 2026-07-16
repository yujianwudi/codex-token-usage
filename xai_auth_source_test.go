package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestXAITierCachePrunesExpiredAndBoundsSize(t *testing.T) {
	now := time.Now()
	m := &xaiAuthSourceManager{tierCache: map[string]cachedXAITier{
		"expired": {FetchedAt: now.Add(-xaiTierCacheTTL - time.Second)},
	}}
	for i := 0; i < xaiTierCacheMaxItems; i++ {
		m.tierCache[fmt.Sprintf("key-%04d", i)] = cachedXAITier{FetchedAt: now.Add(time.Duration(i) * time.Millisecond)}
	}
	m.pruneTierCacheLocked(now)
	if _, ok := m.tierCache["expired"]; ok {
		t.Fatal("expired xAI tier cache entry was retained")
	}
	if len(m.tierCache) >= xaiTierCacheMaxItems {
		t.Fatalf("tier cache size = %d, want room for a new entry", len(m.tierCache))
	}
}

func TestXAITierCacheTTLAppliesWhenVersionIsUnchanged(t *testing.T) {
	oldCaller := hostAuthCaller
	t.Cleanup(func() { hostAuthCaller = oldCaller })

	const authIndex = "xai-stable-version"
	m := &xaiAuthSourceManager{tierCache: map[string]cachedXAITier{
		authIndex: {
			Version:   "unchanged",
			FetchedAt: time.Now().Add(-xaiTierCacheTTL - time.Second),
			Value:     xaiTierClassification{Tier: xaiTierFree, Source: "cached"},
		},
	}}
	calls := 0
	hostAuthCaller = func(method string, payload any) (json.RawMessage, error) {
		if method != "host.auth.get" {
			return nil, os.ErrNotExist
		}
		calls++
		return json.Marshal(hostAuthGetResponse{AuthIndex: authIndex, JSON: json.RawMessage(`{"tier":"heavy"}`)})
	}

	classification, err := m.classifyHostEntry(hostAuthFileEntry{AuthIndex: authIndex, UpdatedAt: "unchanged"})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 || classification.Tier != xaiTierHeavy {
		t.Fatalf("calls=%d classification=%+v, want one refresh to heavy", calls, classification)
	}
}

func TestXAITierClassificationMatchesGrokSignals(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{name: "free default", raw: `{}`, want: xaiTierFree},
		{name: "super subscription", raw: `{"subscription":{"plan":"SuperGrok"}}`, want: xaiTierSuper},
		{name: "heavy tier", raw: `{"account_tier":"heavy"}`, want: xaiTierHeavy},
		{name: "pro maps to heavy", raw: `{"subscription":{"tier":"SUBSCRIPTION_TIER_SUPER_GROK_PRO"}}`, want: xaiTierHeavy},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := classifyXAITierJSON(json.RawMessage(test.raw), xaiTierClassification{Tier: xaiTierFree, Source: "default", Detail: "default"})
			if got.Tier != test.want {
				t.Fatalf("tier=%q want %q (%+v)", got.Tier, test.want, got)
			}
		})
	}
}

func TestXAITierClassificationDoesNotRetainRawSignalOrPath(t *testing.T) {
	secret := "sk-proj-tier-canary-1234567890"
	classification := classifyXAITierSignals([]xaiTierSignal{{
		Path:  "root." + secret + ".note",
		Value: "heavy " + secret,
	}})
	if classification.Tier != xaiTierHeavy {
		t.Fatalf("classification=%+v, want heavy", classification)
	}
	encoded := fmt.Sprintf("%+v", classification)
	if strings.Contains(encoded, secret) || classification.Source != "metadata.note" {
		t.Fatalf("classification retained untrusted metadata: %+v", classification)
	}
}

func TestXAITierSignalSecretDoesNotReachSummaryOrCache(t *testing.T) {
	oldCaller := hostAuthCaller
	oldSource := globalXAIAuthSource
	t.Cleanup(func() { hostAuthCaller = oldCaller; globalXAIAuthSource = oldSource })
	t.Setenv("CPA_AUTH_DIR", filepath.Join(t.TempDir(), "missing-auth"))
	globalXAIAuthSource = &xaiAuthSourceManager{}
	secret := "sk-proj-summary-tier-canary-1234567890"
	listCalled := false
	hostAuthCaller = func(method string, payload any) (json.RawMessage, error) {
		switch method {
		case "host.auth.list":
			listCalled = true
			return json.Marshal(hostAuthListResponse{Files: []hostAuthFileEntry{{
				AuthIndex: "xai-secret-tier", Provider: "xai", Note: "heavy " + secret,
			}}})
		default:
			return nil, os.ErrNotExist
		}
	}

	s := newTestStore(t)
	ctx := context.Background()
	data, err := s.summary(ctx, "24h", 50)
	if err != nil {
		t.Fatal(err)
	}
	if !listCalled {
		t.Fatal("summary did not invoke host.auth.list")
	}
	accounts, ok := data["xai_accounts"].([]accountRow)
	if !ok {
		t.Fatalf("summary xai_accounts type=%T", data["xai_accounts"])
	}
	foundHeavy := false
	for _, account := range accounts {
		if account.AuthIndex == "xai-secret-tier" && account.XAITier == xaiTierHeavy && account.XAITierDetail == xaiTierDetail(xaiTierHeavy) {
			foundHeavy = true
			break
		}
	}
	if !foundHeavy {
		t.Fatalf("summary accounts do not contain sanitized heavy xAI tier: %+v", accounts)
	}
	payload, err := json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(payload), secret) {
		t.Fatalf("summary retained xAI tier signal secret: %s", payload)
	}
	key := normalizeSummaryCacheKey(summaryCacheKey{Window: "24h", Limit: 50})
	if err := s.saveSummaryCacheEntry(ctx, key, summaryCacheEntry{data: data, cachedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	db, _, err := s.open(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var cached string
	if err := db.QueryRowContext(ctx, `SELECT data_json FROM summary_cache WHERE cache_key=?`, summaryCacheStorageKey(key)).Scan(&cached); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(cached, secret) {
		t.Fatalf("summary cache retained xAI tier signal secret: %s", cached)
	}
}

func TestXAIHostAuthSourceIsAuthoritativeAndFiltersProvider(t *testing.T) {
	oldCaller := hostAuthCaller
	oldSource := globalXAIAuthSource
	t.Cleanup(func() { hostAuthCaller = oldCaller; globalXAIAuthSource = oldSource })
	globalXAIAuthSource = &xaiAuthSourceManager{}
	hostAuthCaller = func(method string, payload any) (json.RawMessage, error) {
		switch method {
		case "host.auth.list":
			return json.Marshal(hostAuthListResponse{Files: []hostAuthFileEntry{
				{AuthIndex: "xai-super", Provider: "xai", Email: "super@example.com", Note: "supergrok"},
				{AuthIndex: "codex-one", Provider: "codex", Email: "codex@example.com"},
			}})
		case "host.auth.get":
			return json.Marshal(hostAuthGetResponse{AuthIndex: "xai-super", JSON: json.RawMessage(`{"subscription":{"plan":"SuperGrok"}}`)})
		default:
			return nil, os.ErrNotExist
		}
	}
	accounts, err := globalXAIAuthSource.hostAccounts()
	if err != nil {
		t.Fatal(err)
	}
	if len(accounts) != 1 || accounts[0].Provider != "xai" || accounts[0].XAITier != xaiTierSuper {
		t.Fatalf("accounts=%+v, want one authoritative Super xAI account", accounts)
	}
	if !globalXAIAuthSource.authoritative() || globalXAIAuthSource.status().Source != "host_callback" {
		t.Fatalf("source status=%+v, want authoritative host_callback", globalXAIAuthSource.status())
	}
}

func TestXAIHostAuthSourceDoesNotExposeAPIKeyAccount(t *testing.T) {
	oldCaller := hostAuthCaller
	t.Cleanup(func() { hostAuthCaller = oldCaller })
	secret := "xai-secret-account-value-1234567890"
	m := &xaiAuthSourceManager{}
	hostAuthCaller = func(method string, payload any) (json.RawMessage, error) {
		switch method {
		case "host.auth.list":
			return json.Marshal(hostAuthListResponse{Files: []hostAuthFileEntry{{
				AuthIndex: "xai-key", Provider: "xai", AccountType: "api_key", Account: secret, Source: secret,
			}}})
		case "host.auth.get_runtime":
			return json.Marshal(hostAuthRuntimeResponse{Auth: hostAuthFileEntry{AuthIndex: "xai-key", Status: "ready"}})
		case "host.auth.get":
			return json.Marshal(hostAuthGetResponse{AuthIndex: "xai-key", JSON: json.RawMessage(`{}`)})
		default:
			return nil, os.ErrNotExist
		}
	}
	accounts, err := m.hostAccounts()
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(accounts)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), secret) {
		t.Fatalf("xAI host auth identity exposed an API key account: %s", encoded)
	}
}

func TestXAIHostAuthSourceFallsBackToFiles(t *testing.T) {
	oldCaller := hostAuthCaller
	oldSource := globalXAIAuthSource
	t.Cleanup(func() { hostAuthCaller = oldCaller; globalXAIAuthSource = oldSource })
	dir := t.TempDir()
	t.Setenv("CPA_AUTH_DIR", dir)
	if err := os.WriteFile(filepath.Join(dir, "xai-free.json"), []byte(`{"provider":"xai","email":"free@example.com","note":"free"}`), 0600); err != nil {
		t.Fatal(err)
	}
	globalXAIAuthSource = &xaiAuthSourceManager{}
	hostAuthCaller = func(string, any) (json.RawMessage, error) { return nil, os.ErrNotExist }
	accounts := readConfiguredXAIAccounts()
	if len(accounts) != 1 || accounts[0].XAITier != xaiTierFree {
		t.Fatalf("accounts=%+v, want filesystem fallback Free account", accounts)
	}
	status := globalXAIAuthSource.status()
	if status.Source != "filesystem_fallback" || status.Authoritative {
		t.Fatalf("source status=%+v, want non-authoritative filesystem fallback", status)
	}
}

func TestXAIHostAuthSourceCachesInvalidResponseClassification(t *testing.T) {
	oldCaller := hostAuthCaller
	t.Cleanup(func() { hostAuthCaller = oldCaller })
	var calls int
	m := &xaiAuthSourceManager{}
	hostAuthCaller = func(string, any) (json.RawMessage, error) {
		calls++
		return json.RawMessage(`{"files":`), nil
	}
	for i := 0; i < 2; i++ {
		if _, err := m.hostAccounts(); !errors.Is(err, errXAIHostAuthListInvalid) {
			t.Fatalf("call %d error = %v, want invalid response", i+1, err)
		}
	}
	if calls != 1 {
		t.Fatalf("host callback calls = %d, want cached invalid result", calls)
	}
}

func TestXAIHostAuthSourceFallbackPreservesLastHostSnapshot(t *testing.T) {
	oldCaller := hostAuthCaller
	oldSource := globalXAIAuthSource
	t.Cleanup(func() { hostAuthCaller = oldCaller; globalXAIAuthSource = oldSource })
	dir := t.TempDir()
	t.Setenv("CPA_AUTH_DIR", dir)
	if err := os.WriteFile(filepath.Join(dir, "xai-file.json"), []byte(`{"provider":"xai","email":"file@example.com","note":"free"}`), 0600); err != nil {
		t.Fatal(err)
	}
	globalXAIAuthSource = &xaiAuthSourceManager{}
	hostAuthCaller = func(method string, payload any) (json.RawMessage, error) {
		if method != "host.auth.list" {
			return nil, os.ErrNotExist
		}
		return json.Marshal(hostAuthListResponse{Files: []hostAuthFileEntry{{
			AuthIndex: "runtime-only",
			Provider:  "xai",
			Email:     "runtime@example.com",
			Note:      "heavy",
		}}})
	}
	accounts, err := globalXAIAuthSource.hostAccounts()
	if err != nil || len(accounts) != 1 {
		t.Fatalf("initial host accounts=%+v err=%v", accounts, err)
	}
	initialStatus := globalXAIAuthSource.status()
	if initialStatus.LastSuccessAt == "" {
		t.Fatal("initial host success did not publish a success timestamp")
	}
	globalXAIAuthSource.mu.Lock()
	globalXAIAuthSource.fetchedAt = time.Now().Add(-4 * time.Second)
	globalXAIAuthSource.mu.Unlock()
	hostAuthCaller = func(string, any) (json.RawMessage, error) { return nil, os.ErrNotExist }

	accounts = readConfiguredXAIAccounts()
	if len(accounts) != 2 {
		t.Fatalf("fallback accounts=%+v, want retained host account plus filesystem account", accounts)
	}
	seen := map[string]bool{}
	for _, account := range accounts {
		seen[account.Email] = true
	}
	if !seen["runtime@example.com"] || !seen["file@example.com"] {
		t.Fatalf("fallback accounts=%+v, want both host and filesystem identities", accounts)
	}
	status := globalXAIAuthSource.status()
	if status.Authoritative || status.Source != "filesystem_fallback" || status.LastSuccessAt != initialStatus.LastSuccessAt {
		t.Fatalf("fallback status=%+v, want non-authoritative view retaining last host success", status)
	}
}

func TestXAIHostAuthSourceStaleFallbackCannotOverrideNewHostSuccess(t *testing.T) {
	oldCaller := hostAuthCaller
	t.Cleanup(func() { hostAuthCaller = oldCaller })
	m := &xaiAuthSourceManager{}
	hostAuthCaller = func(method string, payload any) (json.RawMessage, error) {
		if method != "host.auth.list" {
			return nil, os.ErrNotExist
		}
		return json.Marshal(hostAuthListResponse{Files: []hostAuthFileEntry{{
			ID: "fresh", AuthIndex: "fresh", Provider: "xai", Email: "fresh@example.com", Note: "heavy",
		}}})
	}
	if _, err := m.hostAccounts(); err != nil {
		t.Fatal(err)
	}
	merged := m.markFilesystemFallback([]configuredAccount{{
		AuthID: "stale", AuthIndex: "stale.json", AuthFile: "stale.json", Provider: "xai",
	}}, errXAIHostAuthListUnavailable)
	if !m.authoritative() || m.status().Source != "host_callback" {
		t.Fatalf("stale fallback downgraded a newer host success: %+v", m.status())
	}
	if len(merged) != 1 || merged[0].AuthID != "fresh" {
		t.Fatalf("stale fallback reintroduced file-only rows: %+v", merged)
	}
}

func TestXAIHostAuthSourceFallbackReportsHostCallbackFailure(t *testing.T) {
	t.Setenv("CPA_AUTH_DIR", t.TempDir())
	m := &xaiAuthSourceManager{
		callbackErr: errXAIHostAuthListInvalid,
		hostSnapshot: []configuredAccount{{
			AuthID: "host", AuthIndex: "host.json", AuthFile: "host.json", Provider: providerXAI,
		}},
		diagnostics: xaiAuthSourceDiagnostics{LastSuccessAt: "2026-07-16T00:00:00Z"},
	}

	merged := m.markFilesystemFallback(nil, nil)
	if len(merged) != 1 || merged[0].AuthID != "host" {
		t.Fatalf("fallback accounts=%+v, want retained host snapshot", merged)
	}
	status := m.status()
	if status.HostStatus != "invalid_response" {
		t.Fatalf("fallback host status=%q, want invalid_response", status.HostStatus)
	}
	if !strings.Contains(status.LastError, "host_invalid_response") {
		t.Fatalf("fallback last error=%q, want host callback diagnostic", status.LastError)
	}
}

func TestMergeXAIAccountSnapshotsUsesOnlyStableIdentityAliases(t *testing.T) {
	host := configuredAccount{
		AuthID: "host-id", AuthIndex: "host-index", AuthFile: "host.json", Email: "host@example.com",
		Name: "shared-display", Source: "shared-source", Provider: "xai",
	}
	filesystem := configuredAccount{
		AuthID: "file-id", AuthIndex: "file-index", AuthFile: "file.json", Email: "file@example.com",
		Name: "shared-display", Source: "shared-source", Provider: "xai",
	}
	if merged := mergeXAIAccountSnapshots([]configuredAccount{host}, []configuredAccount{filesystem}); len(merged) != 2 {
		t.Fatalf("display metadata incorrectly deduplicated distinct accounts: %+v", merged)
	}
	filesystem.AuthIndex = host.AuthIndex
	if merged := mergeXAIAccountSnapshots([]configuredAccount{host}, []configuredAccount{filesystem}); len(merged) != 1 {
		t.Fatalf("stable auth index did not deduplicate the same account: %+v", merged)
	}
}

func TestXAIHostAuthSourceEmptyListIsAuthoritative(t *testing.T) {
	oldCaller := hostAuthCaller
	oldSource := globalXAIAuthSource
	t.Cleanup(func() { hostAuthCaller = oldCaller; globalXAIAuthSource = oldSource })
	globalXAIAuthSource = &xaiAuthSourceManager{}
	hostAuthCaller = func(method string, payload any) (json.RawMessage, error) {
		if method != "host.auth.list" {
			return nil, os.ErrNotExist
		}
		return json.Marshal(hostAuthListResponse{})
	}
	accounts, err := globalXAIAuthSource.hostAccounts()
	if err != nil {
		t.Fatal(err)
	}
	if len(accounts) != 0 || !globalXAIAuthSource.authoritative() {
		t.Fatalf("accounts=%+v status=%+v, want authoritative empty list", accounts, globalXAIAuthSource.status())
	}
}

func TestXAIHostAuthSourceMergesRuntimeStatus(t *testing.T) {
	oldCaller := hostAuthCaller
	oldSource := globalXAIAuthSource
	t.Cleanup(func() { hostAuthCaller = oldCaller; globalXAIAuthSource = oldSource })
	globalXAIAuthSource = &xaiAuthSourceManager{}
	hostAuthCaller = func(method string, payload any) (json.RawMessage, error) {
		switch method {
		case "host.auth.list":
			return json.Marshal(hostAuthListResponse{Files: []hostAuthFileEntry{{AuthIndex: "xai-runtime", Provider: "xai"}}})
		case "host.auth.get_runtime":
			return json.Marshal(hostAuthRuntimeResponse{Auth: hostAuthFileEntry{
				Status:        "error",
				StatusMessage: "credential unavailable",
				Unavailable:   true,
				UpdatedAt:     "2026-07-12T10:20:30Z",
			}})
		case "host.auth.get":
			return json.Marshal(hostAuthGetResponse{AuthIndex: "xai-runtime", JSON: json.RawMessage(`{"tier":"heavy"}`)})
		default:
			return nil, os.ErrNotExist
		}
	}
	accounts, err := globalXAIAuthSource.hostAccounts()
	if err != nil {
		t.Fatal(err)
	}
	if len(accounts) != 1 {
		t.Fatalf("accounts=%+v, want one account", accounts)
	}
	account := accounts[0]
	if account.RuntimeStatus != "error" || account.RuntimeMessage != "credential unavailable" || !account.RuntimeUnavailable {
		t.Fatalf("runtime fields=%+v, want merged runtime state", account)
	}
	if account.XAITier != xaiTierHeavy {
		t.Fatalf("tier=%q, want heavy", account.XAITier)
	}
	wantTime := time.Date(2026, 7, 12, 10, 20, 30, 0, time.UTC).Unix()
	if account.AuthFileMTime != wantTime {
		t.Fatalf("updated_at=%d, want %d", account.AuthFileMTime, wantTime)
	}
}

func TestParseHostAuthUpdatedAtUnixMilliseconds(t *testing.T) {
	want := int64(1_752_317_230)
	if got := parseHostAuthUpdatedAt("1752317230000"); got != want {
		t.Fatalf("parseHostAuthUpdatedAt()=%d, want %d", got, want)
	}
}
