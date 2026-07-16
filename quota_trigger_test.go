package main

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestNormalizePluginConfigPreservesQuotaMode(t *testing.T) {
	tests := []struct {
		name string
		mode string
		want string
	}{
		{name: "canonical quota", mode: "quota", want: "quota"},
		{name: "english quota alias", mode: "Quota Mode", want: "quota"},
		{name: "chinese quota alias", mode: "查询额度", want: "quota"},
		{name: "probe alias", mode: "真实探测", want: "probe"},
		{name: "unknown", mode: "unexpected", want: "probe"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := defaultPluginConfig()
			cfg.QuotaTriggerMode = tt.mode
			if got := normalizePluginConfig(cfg).QuotaTriggerMode; got != tt.want {
				t.Fatalf("QuotaTriggerMode = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestQuotaTriggerHTTPClientRefusesRedirectsBeforeForwardingHeaders(t *testing.T) {
	var redirected atomic.Int64
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirected.Add(1)
		if r.Header.Get("Authorization") != "" || r.Header.Get("Chatgpt-Account-Id") != "" {
			t.Errorf("sensitive quota headers reached redirect target: %v", r.Header)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer sink.Close()
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, sink.URL, http.StatusTemporaryRedirect)
	}))
	defer redirector.Close()

	_, _, err := doQuotaTriggerHTTPRequest(context.Background(), http.MethodGet, redirector.URL, map[string][]string{
		"Authorization":      {"Bearer secret"},
		"Chatgpt-Account-Id": {"account-secret"},
	}, nil)
	if err == nil || !strings.Contains(err.Error(), "redirects are not allowed") {
		t.Fatalf("redirect error=%v, want strict redirect rejection", err)
	}
	if redirected.Load() != 0 {
		t.Fatalf("redirect target received %d requests", redirected.Load())
	}
}

func TestExecuteQuotaTriggerUsesQuotaEndpoint(t *testing.T) {
	s := newTestStore(t)
	db, dbPath, err := s.open(context.Background())
	if err != nil {
		t.Fatalf("open store: %v", err)
	}

	observed := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		observed <- r.Method + " " + r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()
	setQuotaTriggerURLOverrides(t, server.URL+"/quota", server.URL+"/probe")

	cfg := normalizePluginConfig(defaultPluginConfig())
	cfg.QuotaTriggerMode = "quota"
	run := executeQuotaTrigger(context.Background(), db, dbPath, quotaTestAccount("one"), cfg)
	if run.Mode != "quota" || run.Status != "success" {
		t.Fatalf("run = %+v, want successful quota run", run)
	}
	select {
	case got := <-observed:
		if got != http.MethodGet+" /quota" {
			t.Fatalf("request = %q, want GET /quota", got)
		}
	case <-time.After(time.Second):
		t.Fatal("quota endpoint was not called")
	}
}

func TestExecuteQuotaTriggerReportsAuthStateWriteErrors(t *testing.T) {
	for _, mode := range []string{"probe", "quota"} {
		t.Run(mode, func(t *testing.T) {
			s := newTestStore(t)
			db, dbPath, err := s.open(context.Background())
			if err != nil {
				t.Fatalf("open store: %v", err)
			}
			if _, err := db.Exec(`DROP TABLE invalid_auths`); err != nil {
				t.Fatalf("drop invalid auth table: %v", err)
			}

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{}`))
			}))
			defer server.Close()
			setQuotaTriggerURLOverrides(t, server.URL, server.URL)

			cfg := normalizePluginConfig(defaultPluginConfig())
			cfg.QuotaTriggerMode = mode
			run := executeQuotaTrigger(context.Background(), db, dbPath, quotaTestAccount(mode), cfg)
			if run.Status != "failed" {
				t.Fatalf("run status = %q, want failed after auth-state write error", run.Status)
			}
			if run.Error != "quota auth state write failed: trigger failed" {
				t.Fatalf("run error = %q, want fixed low-sensitivity write failure", run.Error)
			}
		})
	}
}

func TestRunQuotaTriggerCandidatesFlushesCompletedResultsOnCancel(t *testing.T) {
	s := newTestStore(t)
	db, dbPath, err := s.open(context.Background())
	if err != nil {
		t.Fatalf("open store: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var calls atomic.Int32
	executor := func(_ context.Context, _ *sql.DB, _ string, account triggerAuthAccount, cfg pluginConfig) quotaTriggerRun {
		calls.Add(1)
		run := quotaTriggerRunFromAccount(account, cfg.QuotaTriggerMode, "success", http.StatusOK, "")
		cancel()
		return run
	}
	candidates := []triggerAuthAccount{
		quotaTestAccount("one"),
		quotaTestAccount("two"),
		quotaTestAccount("three"),
	}
	cfg := normalizePluginConfig(defaultPluginConfig())
	cfg.QuotaTriggerMaxConcurrency = 1

	success, failed, skipped, attempted, err := runQuotaTriggerCandidates(ctx, db, dbPath, candidates, 2, cfg, executor)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("round error = %v, want context canceled", err)
	}
	if success != 1 || failed != 0 || skipped != 2 || attempted != 1 {
		t.Fatalf("round counts = success:%d failed:%d skipped:%d attempted:%d, want 1,0,2,1", success, failed, skipped, attempted)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("executor calls = %d, want 1", got)
	}
	var count int
	var status string
	if err := db.QueryRowContext(context.Background(), `SELECT COUNT(*), COALESCE(MAX(status), '') FROM quota_trigger_runs`).Scan(&count, &status); err != nil {
		t.Fatalf("query recorded quota runs: %v", err)
	}
	if count != 1 || status != "success" {
		t.Fatalf("recorded quota runs = count:%d status:%q, want 1 successful run", count, status)
	}
}

func setQuotaTriggerURLOverrides(t *testing.T, quotaURL, responsesURL string) {
	t.Helper()
	oldQuotaURL := codexQuotaURLOverrideForTest
	oldResponsesURL := codexResponsesURLOverrideForTest
	codexQuotaURLOverrideForTest = quotaURL
	codexResponsesURLOverrideForTest = responsesURL
	t.Cleanup(func() {
		codexQuotaURLOverrideForTest = oldQuotaURL
		codexResponsesURLOverrideForTest = oldResponsesURL
	})
}

func quotaTestAccount(name string) triggerAuthAccount {
	file := name + ".cpa.json"
	return triggerAuthAccount{
		configuredAccount: configuredAccount{
			AuthID:    name + "@example.com",
			AuthIndex: file,
			Source:    name + "@example.com",
			Provider:  "codex",
			AuthFile:  file,
		},
		AccessToken:      "test-token-" + name,
		ChatGPTAccountID: "workspace-" + name,
	}
}
