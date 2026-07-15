package main

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"math"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func openLegacyHardeningDB(t *testing.T) (*sql.DB, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "usage.db")
	db, err := openSQLiteDB(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Exec(schemaSQL); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`PRAGMA user_version=1`); err != nil {
		t.Fatal(err)
	}
	return db, path
}

func TestPrivacySafeAPIKeyIsStableAndDoesNotContainRawSecret(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "usage.db")
	raw := "sk-proj-example-secret-ABC12345"
	first := privacySafeAPIKey(dbPath, raw)
	second := privacySafeAPIKey(dbPath, "Bearer "+raw)
	if first != second {
		t.Fatalf("fingerprints differ: %q != %q", first, second)
	}
	if !strings.HasPrefix(first, "keyfp:v1:") {
		t.Fatalf("fingerprint = %q, want keyfp:v1", first)
	}
	if strings.Contains(first, raw) || strings.Contains(first, "example-secret") {
		t.Fatalf("fingerprint leaked raw key: %q", first)
	}
	if got := maskAPIKeyForDisplay(first); got != "key-****2345" {
		t.Fatalf("display label = %q", got)
	}
}

func TestLoadOrCreateAPIKeySecretUsesCacheBeforeFilesystem(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "cached-secret")
	want := bytes.Repeat([]byte{0x5a}, 32)
	key := filepath.Clean(dir)
	if runtime.GOOS == "windows" {
		key = strings.ToLower(key)
	}
	apiKeySecrets.Lock()
	apiKeySecrets.byDir[key] = append([]byte(nil), want...)
	apiKeySecrets.Unlock()
	got, err := loadOrCreateAPIKeySecret(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("cached secret = %x, want %x", got, want)
	}
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cache hit touched filesystem: %v", err)
	}
}

func TestPrivacySafeAPIKeyConcurrentColdStartIsStable(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "usage.db")
	raw := "sk-proj-concurrent-secret-ABC12345"
	const callers = 32
	results := make([]string, callers)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range results {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			<-start
			results[index] = privacySafeAPIKey(dbPath, raw)
		}(i)
	}
	close(start)
	wg.Wait()
	for i, fingerprint := range results {
		if fingerprint != results[0] {
			t.Fatalf("fingerprint %d differs: %q != %q", i, fingerprint, results[0])
		}
		if !strings.HasPrefix(fingerprint, "keyfp:v1:") || strings.Contains(fingerprint, raw) {
			t.Fatalf("unsafe concurrent fingerprint: %q", fingerprint)
		}
	}
}

func TestMalformedStoredFingerprintIsReprotected(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "usage.db")
	malformed := "keyfp:v1:not-a-valid-digest:ABCD"
	got := privacySafeAPIKey(dbPath, malformed)
	if got == malformed || !isAPIKeyFingerprint(got) {
		t.Fatalf("malformed fingerprint was trusted: %q", got)
	}
}

func TestSQLiteMigrationFingerprintsLegacyAPIKeysAndClearsSummaryCache(t *testing.T) {
	db, path := openLegacyHardeningDB(t)
	raw := "tenant-secret-1234567890"
	if _, err := db.Exec(`INSERT INTO usage_events
		(requested_at, api_key, auth_id, auth_index, source)
		VALUES (1, ?, ?, ?, ?)`, raw, "prefix:"+raw, raw, "Bearer "+raw); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO summary_cache
		(cache_key, window, limit_count, cached_at, data_json)
		VALUES ('random|1','random',1,1,'{}')`); err != nil {
		t.Fatal(err)
	}
	if err := initializeSQLiteStore(context.Background(), db, path); err != nil {
		t.Fatal(err)
	}
	var apiKey, authID, authIndex, source string
	if err := db.QueryRow(`SELECT api_key, auth_id, auth_index, source FROM usage_events`).Scan(&apiKey, &authID, &authIndex, &source); err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]string{"api_key": apiKey, "auth_id": authID, "auth_index": authIndex, "source": source} {
		if strings.Contains(value, raw) {
			t.Fatalf("%s still contains raw key: %q", name, value)
		}
	}
	if !isAPIKeyFingerprint(apiKey) {
		t.Fatalf("api_key = %q, want fingerprint", apiKey)
	}
	if authID != "prefix:"+apiKey {
		t.Fatalf("auth_id = %q, want fingerprint substitution", authID)
	}
	if authIndex != apiKey {
		t.Fatalf("auth_index = %q, want fingerprint", authIndex)
	}
	if source != apiKey {
		t.Fatalf("source = %q, want normalized fingerprint", source)
	}
	var cacheRows int
	if err := db.QueryRow(`SELECT COUNT(*) FROM summary_cache`).Scan(&cacheRows); err != nil {
		t.Fatal(err)
	}
	if cacheRows != 0 {
		t.Fatalf("summary cache rows = %d, want 0", cacheRows)
	}
	var version int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != currentSQLiteSchemaVersion {
		t.Fatalf("schema version = %d", version)
	}
}

func TestSQLiteInitializationPreservesLegitimateSlowLatency(t *testing.T) {
	db, path := openLegacyHardeningDB(t)
	if _, err := db.Exec(`INSERT INTO usage_events (requested_at, latency_ms, ttft_ms) VALUES (1, 12000, 30000)`); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := initializeSQLiteStore(context.Background(), db, path); err != nil {
			t.Fatal(err)
		}
	}
	var latency, ttft int64
	if err := db.QueryRow(`SELECT latency_ms, ttft_ms FROM usage_events`).Scan(&latency, &ttft); err != nil {
		t.Fatal(err)
	}
	if latency != 12000 || ttft != 30000 {
		t.Fatalf("latency/ttft = %d/%d, want 12000/30000", latency, ttft)
	}
}

func TestSummaryCacheKeyCardinalityIsBounded(t *testing.T) {
	invalid := normalizeSummaryCacheKey(summaryCacheKey{Window: "random-window", Limit: 123})
	if invalid.Window != "24h" || invalid.Limit != 500 {
		t.Fatalf("normalized key = %#v", invalid)
	}
	for _, window := range []string{"today", "24h", "7d", "30d", "all"} {
		if normalized, ok := normalizeSummaryWindow(window); !ok || normalized != window {
			t.Fatalf("window %q normalized to %q/%v", window, normalized, ok)
		}
	}
	if _, ok := normalizeSummaryWindow("attacker-controlled"); ok {
		t.Fatal("unknown summary window was accepted")
	}
}

func TestModelPriceValidationRejectsNonFiniteValues(t *testing.T) {
	if _, ok := modelPriceFromJSON(map[string]any{"prompt": "Inf", "completion": 1}); ok {
		t.Fatal("infinite model price was accepted")
	}
	if validModelPrice(modelPrice{Prompt: math.NaN(), Completion: 1}) {
		t.Fatal("NaN model price was accepted")
	}
	if _, ok := modelPriceFromJSON(map[string]any{"prompt": 1, "completion": 2, "cache": "not-a-number"}); ok {
		t.Fatal("malformed cache price was accepted")
	}
}

func TestModelPriceURLRejectsUnsafeTargets(t *testing.T) {
	ctx := context.Background()
	for _, raw := range []string{
		"http://example.com/prices.json",
		"https://localhost/prices.json",
		"https://127.0.0.1/prices.json",
		"https://169.254.169.254/latest/meta-data",
		"https://user:pass@example.com/prices.json",
	} {
		if _, err := validatePublicModelPriceURL(ctx, raw); err == nil {
			t.Fatalf("unsafe URL accepted: %s", raw)
		}
	}
}

func TestModelPricePublicIPRejectsSpecialPurposeNetworks(t *testing.T) {
	for _, raw := range []string{
		"0.1.2.3",
		"100.64.0.1",
		"192.0.2.1",
		"198.18.0.1",
		"203.0.113.1",
		"64:ff9b:1::1",
		"2001:db8::1",
	} {
		if publicModelPriceIP(net.ParseIP(raw)) {
			t.Fatalf("special-purpose address accepted: %s", raw)
		}
	}
	for _, raw := range []string{"1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"} {
		if !publicModelPriceIP(net.ParseIP(raw)) {
			t.Fatalf("public address rejected: %s", raw)
		}
	}
	if transport := publicModelPriceTransport(); transport.Proxy != nil {
		t.Fatal("price update transport unexpectedly honors an environment proxy")
	}
}

func TestEnsureFreshHonorsFailedUpdateBackoff(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cfg := defaultPluginConfig()
	cfg.ModelPriceAutoUpdateEnabled = true
	m := modelPriceUpdateManager{
		cfg: cfg,
		ctx: ctx,
		state: modelPriceUpdateState{
			LastCheckedAt: time.Now().Format(time.RFC3339),
			LastError:     "temporary failure",
		},
	}
	m.ensureFresh()
	m.mu.Lock()
	updating := m.updating
	m.mu.Unlock()
	if updating {
		t.Fatal("ensureFresh retried during the failed-update cooldown")
	}
}
