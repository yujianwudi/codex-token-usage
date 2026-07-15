package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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
	if status.Source != "filesystem_fallback" || !status.Authoritative {
		t.Fatalf("source status=%+v, want authoritative filesystem fallback", status)
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
