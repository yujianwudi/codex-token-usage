package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func withCodexHostAuthSource(t *testing.T, caller hostCallFunc) *codexAuthSourceManager {
	t.Helper()
	oldCaller := hostAuthCaller
	oldSource := globalCodexAuthSource
	m := &codexAuthSourceManager{}
	hostAuthCaller = caller
	globalCodexAuthSource = m
	t.Cleanup(func() {
		hostAuthCaller = oldCaller
		globalCodexAuthSource = oldSource
	})
	return m
}

func TestCodexHostAuthSourceParsesCurrentCPAFieldsWithoutSecrets(t *testing.T) {
	modTime := time.Date(2026, 7, 16, 1, 2, 3, 0, time.UTC)
	updatedAt := modTime.Add(time.Minute)
	secret := "sk-secret-account-value"
	m := withCodexHostAuthSource(t, func(method string, payload any) (json.RawMessage, error) {
		if method != "host.auth.list" {
			t.Fatalf("method = %q", method)
		}
		return json.Marshal(codexHostAuthListResponse{Files: []codexHostAuthFileEntry{
			{
				ID: "codex-id", AuthIndex: "codex-index", Name: "codex.json",
				Provider: "codex", Type: "codex", Email: "user@example.com",
				AccountType: "api_key", Account: secret, Label: secret, Note: secret,
				Status: "ready", StatusMessage: "Bearer " + secret,
				ModTime: modTime, UpdatedAt: updatedAt,
			},
			{ID: "xai-id", AuthIndex: "xai-index", Name: "xai.json", Provider: "xai"},
		}})
	})

	accounts, err := m.hostAccounts()
	if err != nil {
		t.Fatal(err)
	}
	if len(accounts) != 1 {
		t.Fatalf("accounts = %+v, want one Codex account", accounts)
	}
	got := accounts[0]
	if got.AuthIndex != "codex-index" || got.AuthID != "codex-id" || got.AuthFile != "codex.json" {
		t.Fatalf("identity = %+v", got)
	}
	if got.AuthFileMTime != modTime.Unix() {
		t.Fatalf("mtime = %d, want %d", got.AuthFileMTime, modTime.Unix())
	}
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), secret) || got.AccessToken != "" {
		t.Fatalf("configured account retained host secret: %s", encoded)
	}
	status := m.status()
	if !status.Authoritative || status.Source != "host_callback" || status.Accounts != 1 {
		t.Fatalf("status = %+v", status)
	}
}

func TestCodexHostAuthSourceUsesUpdatedAtWhenModTimeMissing(t *testing.T) {
	updatedAt := time.Date(2026, 7, 16, 4, 5, 6, 0, time.UTC)
	m := withCodexHostAuthSource(t, func(string, any) (json.RawMessage, error) {
		return json.Marshal(codexHostAuthListResponse{Files: []codexHostAuthFileEntry{{
			ID: "id", AuthIndex: "index", Name: "runtime-only", Provider: "codex",
			RuntimeOnly: true, UpdatedAt: updatedAt,
		}}})
	})
	accounts, err := m.hostAccounts()
	if err != nil {
		t.Fatal(err)
	}
	if len(accounts) != 1 || accounts[0].AuthFileMTime != updatedAt.Unix() {
		t.Fatalf("accounts = %+v", accounts)
	}
}

func TestCodexHostAuthSourceFailureIsNonAuthoritativeAndAllowsFallback(t *testing.T) {
	secret := "sk-callback-error-secret"
	m := withCodexHostAuthSource(t, func(string, any) (json.RawMessage, error) {
		return nil, errors.New("upstream failed with " + secret)
	})
	if _, err := m.hostAccounts(); !errors.Is(err, errCodexHostAuthListUnavailable) {
		t.Fatalf("error = %v", err)
	}
	status := m.status()
	if status.Authoritative || status.Source != "host_callback_error" || strings.Contains(status.LastError, secret) {
		t.Fatalf("status = %+v", status)
	}
	fallback := []configuredAccount{{AuthIndex: "fallback", AuthID: "fallback", Provider: "codex"}}
	merged := m.markFilesystemFallback(fallback, errors.New(secret))
	if len(merged) != 1 || merged[0].AuthID != "fallback" {
		t.Fatalf("fallback accounts = %+v", merged)
	}
	status = m.status()
	if status.Authoritative || status.Source != "filesystem_fallback" || strings.Contains(status.LastError, secret) {
		t.Fatalf("fallback status = %+v", status)
	}
}

func TestCodexHostAuthSourceCachesInvalidResponseClassification(t *testing.T) {
	var calls atomic.Int32
	m := withCodexHostAuthSource(t, func(string, any) (json.RawMessage, error) {
		calls.Add(1)
		return json.RawMessage(`{"files":`), nil
	})
	for i := 0; i < 2; i++ {
		if _, err := m.hostAccounts(); !errors.Is(err, errCodexHostAuthListInvalid) {
			t.Fatalf("call %d error = %v, want invalid response", i+1, err)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("host callback calls = %d, want cached invalid result", got)
	}
}

func TestCodexHostAuthSourceFallbackPreservesRuntimeHostAccounts(t *testing.T) {
	m := withCodexHostAuthSource(t, func(string, any) (json.RawMessage, error) {
		return json.Marshal(codexHostAuthListResponse{Files: []codexHostAuthFileEntry{{
			ID: "runtime", AuthIndex: "runtime", Name: "runtime", Provider: "codex", RuntimeOnly: true,
		}}})
	})
	if accounts, err := m.hostAccounts(); err != nil || len(accounts) != 1 {
		t.Fatalf("host accounts = %+v err=%v", accounts, err)
	}
	m.recordHostFailure(errCodexHostAuthListUnavailable)
	merged := m.markFilesystemFallback([]configuredAccount{{
		AuthID: "file.json", AuthIndex: "file.json", AuthFile: "file.json", Provider: "codex",
	}}, errCodexHostAuthListUnavailable)
	if len(merged) != 2 {
		t.Fatalf("merged fallback accounts = %+v, want runtime and file accounts", merged)
	}
	if m.authoritative() {
		t.Fatal("merged fallback was treated as authoritative")
	}
}

func TestCodexHostAuthSourceStaleFallbackCannotOverrideNewHostSuccess(t *testing.T) {
	m := withCodexHostAuthSource(t, func(string, any) (json.RawMessage, error) {
		return json.Marshal(codexHostAuthListResponse{Files: []codexHostAuthFileEntry{{
			ID: "fresh", AuthIndex: "fresh", Name: "fresh", Provider: "codex", RuntimeOnly: true,
		}}})
	})
	if _, err := m.hostAccounts(); err != nil {
		t.Fatal(err)
	}
	merged := m.markFilesystemFallback([]configuredAccount{{
		AuthID: "stale.json", AuthIndex: "stale.json", AuthFile: "stale.json", Provider: "codex",
	}}, errCodexHostAuthListUnavailable)
	if !m.authoritative() || m.status().Source != "host_callback" {
		t.Fatalf("stale fallback downgraded a newer host success: %+v", m.status())
	}
	if len(merged) != 1 || merged[0].AuthID != "fresh" {
		t.Fatalf("stale fallback reintroduced file-only rows: %+v", merged)
	}
}

func TestCodexHostAuthSourceConcurrentMissUsesSingleCallback(t *testing.T) {
	var calls atomic.Int32
	release := make(chan struct{})
	m := withCodexHostAuthSource(t, func(string, any) (json.RawMessage, error) {
		calls.Add(1)
		<-release
		return json.Marshal(codexHostAuthListResponse{Files: []codexHostAuthFileEntry{{
			ID: "id", AuthIndex: "index", Name: "codex.json", Provider: "codex",
		}}})
	})

	const workers = 16
	start := make(chan struct{})
	results := make(chan error, workers)
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			<-start
			accounts, err := m.hostAccounts()
			if err == nil && len(accounts) != 1 {
				err = errors.New("unexpected account count")
			}
			results <- err
		}()
	}
	close(start)
	deadline := time.Now().Add(time.Second)
	for calls.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	close(release)
	wg.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatal(err)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("host callback calls = %d, want 1", got)
	}
}

func TestMergeConfiguredAccountMetadataNeverCopiesAccessToken(t *testing.T) {
	accounts := []configuredAccount{{AuthIndex: "index", Provider: "codex"}}
	metadata := []configuredAccount{{
		AuthIndex: "index", Provider: "codex", Email: "user@example.com",
		AccessToken: "sk-secret", ChatGPTAccountID: "account-id",
	}}
	merged := mergeConfiguredAccountMetadata(accounts, metadata)
	if len(merged) != 1 || merged[0].Email != "user@example.com" || merged[0].ChatGPTAccountID != "account-id" {
		t.Fatalf("merged = %+v", merged)
	}
	if merged[0].AccessToken != "" {
		t.Fatal("metadata merge copied an access token")
	}
}

func TestConfiguredAccountListRevisionIsStableAndSensitiveToHostChanges(t *testing.T) {
	a := []configuredAccount{
		{Provider: "codex", AuthIndex: "b", AuthID: "b"},
		{Provider: "codex", AuthIndex: "a", AuthID: "a"},
	}
	b := []configuredAccount{a[1], a[0]}
	if configuredAccountListRevision(a) != configuredAccountListRevision(b) {
		t.Fatal("revision depends on host list order")
	}
	b[0].Disabled = true
	if configuredAccountListRevision(a) == configuredAccountListRevision(b) {
		t.Fatal("revision ignored a host account state change")
	}
}

func TestAuthFilesRevisionIncludesFilesystemMetadataWithAuthoritativeHost(t *testing.T) {
	authDir := t.TempDir()
	t.Setenv("CPA_AUTH_DIR", authDir)
	withCodexHostAuthSource(t, func(string, any) (json.RawMessage, error) {
		return json.Marshal(codexHostAuthListResponse{Files: []codexHostAuthFileEntry{{
			ID: "codex-id", AuthIndex: "codex.json", Name: "codex.json", Provider: "codex",
		}}})
	})
	authPath := authDir + string(os.PathSeparator) + "codex.json"
	if err := os.WriteFile(authPath, []byte(`{"type":"codex","email":"first@example.com"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	first := authFilesRevision()
	if !strings.HasPrefix(first, "host:") || !strings.Contains(first, "|files:") {
		t.Fatalf("combined revision = %q", first)
	}
	if err := os.WriteFile(authPath, []byte(`{"type":"codex","email":"second-longer@example.com"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	second := authFilesRevision()
	if first == second {
		t.Fatalf("filesystem metadata change did not update authoritative host revision: %q", first)
	}
}

func TestConfiguredAuthFilesDoNotExposeAPIKeyAccountAsIdentity(t *testing.T) {
	authDir := t.TempDir()
	t.Setenv("CPA_AUTH_DIR", authDir)
	secret := "sk-secret-account-value-1234567890"
	if err := os.WriteFile(authDir+string(os.PathSeparator)+"codex.json", []byte(`{"provider":"codex","account_type":"api_key","account":"`+secret+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	accounts := readConfiguredAuthFiles()
	encoded, err := json.Marshal(accounts)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), secret) {
		t.Fatalf("configured auth identity exposed an API key account: %s", encoded)
	}
}

func TestConfiguredAuthFileSnapshotDetectsInPlaceChanges(t *testing.T) {
	path := t.TempDir() + string(os.PathSeparator) + "codex.json"
	if err := os.WriteFile(path, []byte(`{"type":"codex"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !configuredAuthFileSnapshotStable(before, before, before.Size()) {
		t.Fatal("unchanged auth file snapshot was rejected")
	}
	if err := os.WriteFile(path, []byte(`{"type":"codex","email":"changed@example.com"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if configuredAuthFileSnapshotStable(before, after, after.Size()) {
		t.Fatal("changed auth file snapshot was accepted")
	}
}

func TestSummaryIncludesZeroUsageRuntimeCodexHostAuth(t *testing.T) {
	authDir := t.TempDir()
	t.Setenv("CPA_AUTH_DIR", authDir)
	withCodexHostAuthSource(t, func(method string, payload any) (json.RawMessage, error) {
		if method != "host.auth.list" {
			t.Fatalf("method = %q", method)
		}
		return json.Marshal(codexHostAuthListResponse{Files: []codexHostAuthFileEntry{{
			ID: "runtime-codex-id", AuthIndex: "runtime-codex-index", Name: "runtime-codex",
			Provider: "codex", RuntimeOnly: true, Email: "runtime-codex@example.com", Status: "ready",
		}}})
	})
	s := newTestStore(t)
	data, err := s.summary(context.Background(), "24h", 50)
	if err != nil {
		t.Fatal(err)
	}
	accounts, ok := data["accounts"].([]accountRow)
	if !ok {
		t.Fatalf("accounts type = %T", data["accounts"])
	}
	for _, account := range accounts {
		if account.AuthIndex == "runtime-codex-index" && account.Email == "runtime-codex@example.com" && account.Configured && account.Requests == 0 {
			if account.AuthFile != "" {
				t.Fatalf("runtime-only account unexpectedly has a file: %+v", account)
			}
			return
		}
	}
	t.Fatalf("runtime Codex host auth missing from summary: %+v", accounts)
}
