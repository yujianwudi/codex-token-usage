package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func resetAPIKeySecretCacheForTest(dir string) {
	key := apiKeySecretCacheKey(filepath.Join(dir, "usage.db"))
	apiKeySecrets.Lock()
	delete(apiKeySecrets.byDB, key)
	apiKeySecrets.Unlock()
	apiKeyFallbackWarnings.Lock()
	delete(apiKeyFallbackWarnings.byDB, key)
	apiKeyFallbackWarnings.Unlock()
	apiKeyFingerprintHealth.Lock()
	delete(apiKeyFingerprintHealth.byDB, key)
	apiKeyFingerprintHealth.Unlock()
}

func TestRuntimeFingerprintLikeCredentialIsReboundToLocalSecret(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "usage.db")
	external := "keyfp:v1:0123456789abcdef0123456789abcdef:ABCD"
	got, err := privacySafeAPIKeyWithError(dbPath, external)
	if err != nil {
		t.Fatal(err)
	}
	if got == external || !strings.HasPrefix(got, "keyfp:v1:") {
		t.Fatalf("external fingerprint-like credential was trusted: %q", got)
	}
	if again := privacySafeAPIKey(dbPath, external); again != got {
		t.Fatalf("locally rebound fingerprint is unstable: %q != %q", again, got)
	}
}

func TestAPIKeyFingerprintHealthIsIsolatedByDatabase(t *testing.T) {
	firstPath := filepath.Join(t.TempDir(), "first.db")
	secondPath := filepath.Join(t.TempDir(), "second.db")
	recordAPIKeyFingerprintError(firstPath, &os.PathError{Op: "open", Path: apiKeySecretPath(firstPath), Err: os.ErrPermission})
	recordAPIKeyFingerprintSuccess(secondPath)
	first := apiKeyFingerprintStatus(context.Background(), nil, firstPath)
	second := apiKeyFingerprintStatus(context.Background(), nil, secondPath)
	if !first.Checked || first.Available || first.LastError == "" {
		t.Fatalf("first database health=%+v, want isolated failure", first)
	}
	if !second.Checked || !second.Available || second.LastError != "" {
		t.Fatalf("second database health=%+v, want isolated success", second)
	}
}

func TestFingerprintingDoesNotClearUnverifiedBindingFailure(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "usage.db")
	if _, err := privacySafeAPIKeyWithError(dbPath, "sk-initial-secret-1234567890"); err != nil {
		t.Fatal(err)
	}
	recordAPIKeyFingerprintError(dbPath, errors.New("binding verification failed"))
	if _, err := privacySafeAPIKeyWithError(dbPath, "sk-next-secret-1234567890"); err != nil {
		t.Fatal(err)
	}
	status := apiKeyFingerprintStatus(context.Background(), nil, dbPath)
	if !status.Checked || status.Available || status.LastError == "" {
		t.Fatalf("fingerprinting cleared an unverified binding failure: %+v", status)
	}
}

func TestPersistentIdentityScannerReloadsRowsMutatedWithinBatch(t *testing.T) {
	db := newProtectionTestDB(t)
	firstResult, err := db.Exec(`INSERT INTO usage_events(requested_at,provider,auth_id) VALUES(1,'codex','first')`)
	if err != nil {
		t.Fatal(err)
	}
	firstID, err := firstResult.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	secondResult, err := db.Exec(`INSERT INTO usage_events(requested_at,provider,auth_id) VALUES(2,'codex','stale')`)
	if err != nil {
		t.Fatal(err)
	}
	secondID, err := secondResult.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	seenSecond := ""
	err = scanPersistentIdentityRows(context.Background(), db, persistentIdentitySpec{
		table: "usage_events", columns: []string{"api_key", "auth_id", "auth_index", "source"},
	}, func(row storedIdentityRow) error {
		switch row.rowID {
		case firstID:
			_, err := db.Exec(`UPDATE usage_events SET auth_id='fresh' WHERE id=?`, secondID)
			return err
		case secondID:
			seenSecond = row.values[1]
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if seenSecond != "fresh" {
		t.Fatalf("scanner visited stale batch snapshot %q, want fresh", seenSecond)
	}
}

func isolateAPIKeyPrivacyQuarantineForTest(t *testing.T) {
	t.Helper()
}

func TestPrivacySafeUsageRecordProtectsAuthFile(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "usage.db")
	raw := "sk-proj-auth-file-secret-1234567890"
	rec, err := privacySafeUsageRecord(dbPath, usageRecord{
		APIKey:   raw,
		AuthFile: "codex-" + raw + ".json",
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(rec.AuthFile, raw) {
		t.Fatalf("AuthFile retained raw credential: %q", rec.AuthFile)
	}
	if !strings.Contains(rec.AuthFile, rec.APIKey) {
		t.Fatalf("AuthFile = %q, want protected fingerprint %q", rec.AuthFile, rec.APIKey)
	}
}

func TestStoredCredentialBearerRequiresSpaceDelimiter(t *testing.T) {
	ordinary := "bearer-account-1"
	if got := storedCredentialAlias(ordinary); got != "" {
		t.Fatalf("storedCredentialAlias(%q) = %q, want ordinary alias", ordinary, got)
	}
	if got := configuredCredentialWholeValue(ordinary); got != ordinary {
		t.Fatalf("configuredCredentialWholeValue(%q) = %q", ordinary, got)
	}
	if credential, whole := credentialFromStoredIdentity(ordinary, nil); credential != "" || whole {
		t.Fatalf("credentialFromStoredIdentity(%q) = %q/%v", ordinary, credential, whole)
	}

	credential := "opaque-provider-key-1234567890"
	if got := configuredCredentialWholeValue("bEaReR " + credential); got != credential {
		t.Fatalf("valid Bearer credential = %q, want %q", got, credential)
	}
	if got, whole := credentialFromStoredIdentity("bEaReR "+credential, nil); got != credential || !whole {
		t.Fatalf("valid Bearer identity = %q/%v, want %q/true", got, whole, credential)
	}
}

func TestSanitizeTriggerErrorFailsClosedWhenFingerprintSidecarUnavailable(t *testing.T) {
	blocked := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blocked, []byte("blocked"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CPA_TOKEN_USAGE_DIR", blocked)
	resetAPIKeySecretCacheForTest(blocked)
	if got := storedCredentialAlias("xai-short-secret"); got != "" {
		t.Fatalf("stored credential alias unexpectedly succeeded: %q", got)
	}
	if got := sanitizeTriggerError("upstream returned xai-short-secret"); got != "trigger failed" {
		t.Fatalf("sanitizeTriggerError failed open: %q", got)
	}
}

func refreshAPIKeyPrivacyQuarantineForTest(t *testing.T, s *store, db *sql.DB, path string) {
	t.Helper()
	if err := s.refreshAPIKeyPrivacyQuarantine(context.Background(), db, path); err != nil {
		t.Fatal(err)
	}
}

func writeConfiguredAPIKeyForTest(t *testing.T, raw string) string {
	return writeConfiguredAPIKeysForTest(t, raw)
}

func writeConfiguredAPIKeysForTest(t *testing.T, raws ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	var contents strings.Builder
	contents.WriteString("codex-api-key:\n")
	for i, raw := range raws {
		fmt.Fprintf(&contents, "  - name: privacy-test-%d\n    api-key: %q\n", i, raw)
	}
	if err := os.WriteFile(path, []byte(contents.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CPA_CONFIG_PATH", path)
	configuredProviderEntriesCache.mu.Lock()
	configuredProviderEntriesCache.path = ""
	configuredProviderEntriesCache.modTime = 0
	configuredProviderEntriesCache.size = 0
	configuredProviderEntriesCache.entries = nil
	configuredProviderEntriesCache.mu.Unlock()
	return path
}

func writeAPIKeySecretForTest(t *testing.T, dir string, secret []byte) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	encoded := make([]byte, hex.EncodedLen(len(secret)))
	hex.Encode(encoded, secret)
	if err := os.WriteFile(filepath.Join(dir, apiKeyFingerprintSecretFile), encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	resetAPIKeySecretCacheForTest(dir)
}

func TestRecordUsageSanitizesAllDerivedAuthStateTables(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("CPA_TOKEN_USAGE_DIR", dir)
	path := filepath.Join(dir, "usage.db")
	db, err := openSQLiteDB(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := initializeSQLiteStore(context.Background(), db, path); err != nil {
		t.Fatal(err)
	}
	s := &store{db: db, dbPath: path}
	raw := "opaque-provider-key-1234567890-SECRET"
	now := time.Now()
	base := usageRecord{
		APIKey:      raw,
		AuthID:      raw,
		AuthIndex:   "Bearer " + raw,
		Source:      "codex:apikey:" + raw,
		RequestedAt: now,
		Failed:      true,
	}
	invalid := base
	invalid.Provider = "codex"
	invalid.Failure.StatusCode = 401
	if err := s.recordUsage(context.Background(), invalid); err != nil {
		t.Fatal(err)
	}
	ban := base
	ban.Provider = "codex"
	ban.RequestedAt = now.Add(time.Second)
	ban.Failure.StatusCode = 429
	ban.ResponseHeaders = map[string][]string{
		"x-codex-primary-used-percent": {"100"},
		"x-codex-primary-reset-at":     {strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10)},
	}
	if err := s.recordUsage(context.Background(), ban); err != nil {
		t.Fatal(err)
	}
	xai := base
	xai.Provider = "xai"
	xai.RequestedAt = now.Add(2 * time.Second)
	xai.Failure.StatusCode = 401
	if err := s.recordUsage(context.Background(), xai); err != nil {
		t.Fatal(err)
	}

	for _, query := range []string{
		`SELECT api_key || auth_id || auth_index || source FROM usage_events`,
		`SELECT auth_id || auth_index || source FROM invalid_auths`,
		`SELECT auth_id || auth_index || source FROM autoban_bans`,
		`SELECT state_key || auth_id || auth_index || source FROM xai_account_states`,
	} {
		rows, err := db.Query(query)
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			var stored string
			if err := rows.Scan(&stored); err != nil {
				_ = rows.Close()
				t.Fatal(err)
			}
			if strings.Contains(stored, raw) {
				_ = rows.Close()
				t.Fatalf("raw API key persisted by %q: %q", query, stored)
			}
		}
		if err := rows.Close(); err != nil {
			t.Fatal(err)
		}
	}

	candidate := schedulerAuthCandidate{ID: raw, Provider: "codex", Attributes: map[string]string{"auth_index": raw, "source": "Bearer " + raw}}
	invalids, err := queryActiveInvalidAuths(context.Background(), db, providerCodex)
	if err != nil {
		t.Fatal(err)
	}
	if !candidateMatchesInvalidAuth(candidate, invalids) {
		t.Fatal("sanitized invalid-auth state no longer matches the raw scheduler candidate")
	}
	bans, err := queryActiveAutobans(context.Background(), db, providerCodex, time.Now().Unix())
	if err != nil {
		t.Fatal(err)
	}
	if !candidateMatchesActiveBan(candidate, bans) {
		t.Fatal("sanitized autoban state no longer matches the raw scheduler candidate")
	}
}

func TestV3MigrationPreservesSafeActiveStatesAndSanitizesCredentials(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("CPA_TOKEN_USAGE_DIR", dir)
	path := filepath.Join(dir, "usage.db")
	db, err := openSQLiteDB(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Exec(schemaSQL); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`PRAGMA user_version=2`); err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	raw := "opaque-provider-key-1234567890-SECRET"
	if _, err := db.Exec(`INSERT INTO invalid_auths(auth_id,auth_index,source,provider,reason,invalidated_at,active) VALUES(?,?,?,?,?,?,1)`, "user@example.com", "account.json", "user@example.com", "codex", "test", now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO autoban_bans(auth_id,auth_index,source,provider,window,reason,banned_at,reset_at,active) VALUES(?,?,?,?,?,?,?,?,1)`, "account.json", "account.json", "user@example.com", "codex", "5h", "test", now, now+3600); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO xai_account_states(state_key,auth_id,auth_index,source,provider,state,reason,observed_at,reset_at,active) VALUES(?,?,?,?,?,?,?,?,?,1)`, "user@example.com", "user@example.com", "account.json", "user@example.com", "xai", xaiStateUnauthorized, "test", now, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO invalid_auths(auth_id,auth_index,source,provider,reason,invalidated_at,active) VALUES(?,?,?,?,?,?,1)`, raw, "Bearer "+raw, raw, "codex", "credential", now+1); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO usage_events(requested_at,provider,api_key,auth_id,auth_index,source) VALUES(?,'codex','',?,?,?)`, now, raw, "Bearer "+raw, raw); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO account_protection_reservations(auth_id,auth_index,source,plan_type,created_at,expires_at) VALUES(?,?,?,'plus',?,?)`, raw, "Bearer "+raw, raw, now, now+900); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO quota_trigger_runs(auth_id,auth_index,source,provider,auth_file,status,started_at,finished_at) VALUES(?,?,?,'codex',?,'failed',?,?)`, raw, "Bearer "+raw, raw, raw, now, now+1); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO summary_cache(cache_key,window,limit_count,cached_at,data_json) VALUES('24h|50','24h',50,1,?)`, `{"secret":"`+raw+`"}`); err != nil {
		t.Fatal(err)
	}
	if err := initializeSQLiteStore(context.Background(), db, path); err != nil {
		t.Fatal(err)
	}
	var safeInvalid, safeBan, safeXAI int
	if err := db.QueryRow(`SELECT COUNT(*) FROM invalid_auths WHERE auth_id='user@example.com' AND active=1`).Scan(&safeInvalid); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM autoban_bans WHERE auth_id='account.json' AND active=1`).Scan(&safeBan); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM xai_account_states WHERE state_key='user@example.com' AND active=1`).Scan(&safeXAI); err != nil {
		t.Fatal(err)
	}
	if safeInvalid != 1 || safeBan != 1 || safeXAI != 1 {
		t.Fatalf("safe active states lost during migration: invalid=%d ban=%d xai=%d", safeInvalid, safeBan, safeXAI)
	}
	safeCandidate := schedulerAuthCandidate{ID: "user@example.com", Provider: "codex", Attributes: map[string]string{"auth_index": "account.json", "source": "user@example.com"}}
	activeInvalids, err := queryActiveInvalidAuths(context.Background(), db, providerCodex)
	if err != nil {
		t.Fatal(err)
	}
	if !candidateMatchesInvalidAuth(safeCandidate, activeInvalids) {
		t.Fatal("ordinary active invalid-auth state stopped filtering after migration")
	}
	activeBans, err := queryActiveAutobans(context.Background(), db, providerCodex, now)
	if err != nil {
		t.Fatal(err)
	}
	if !candidateMatchesActiveBan(safeCandidate, activeBans) {
		t.Fatal("ordinary active autoban state stopped filtering after migration")
	}
	activeXAI, err := queryActiveXAIStates(context.Background(), db, providerXAI, now)
	if err != nil {
		t.Fatal(err)
	}
	if !candidateMatchesXAIState(safeCandidate, activeXAI) {
		t.Fatal("ordinary active xAI state stopped filtering after migration")
	}
	var authID, authIndex, source string
	if err := db.QueryRow(`SELECT auth_id,auth_index,source FROM invalid_auths WHERE reason='credential'`).Scan(&authID, &authIndex, &source); err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]string{"auth_id": authID, "auth_index": authIndex, "source": source} {
		if strings.Contains(value, raw) || !isAPIKeyFingerprint(value) {
			t.Fatalf("%s was not safely migrated: %q", name, value)
		}
	}
	for _, query := range []string{
		`SELECT auth_id||auth_index||source FROM usage_events WHERE api_key=''`,
		`SELECT auth_id||auth_index||source||auth_file FROM quota_trigger_runs`,
	} {
		var value string
		if err := db.QueryRow(query).Scan(&value); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(value, raw) || !strings.Contains(value, "keyfp:v1:") {
			t.Fatalf("derived identity migration left an unsafe value for %q: %q", query, value)
		}
	}
	var reservations int
	if err := db.QueryRow(`SELECT COUNT(*) FROM account_protection_reservations`).Scan(&reservations); err != nil {
		t.Fatal(err)
	}
	if reservations != 0 {
		t.Fatalf("ephemeral reservations retained during v5 migration: %d", reservations)
	}
	var cacheRows int
	if err := db.QueryRow(`SELECT COUNT(*) FROM summary_cache`).Scan(&cacheRows); err != nil {
		t.Fatal(err)
	}
	if cacheRows != 0 {
		t.Fatalf("summary cache retained %d rows", cacheRows)
	}
	candidate := schedulerAuthCandidate{ID: raw, Provider: "codex", Attributes: map[string]string{"auth_index": raw}}
	invalids, err := queryActiveInvalidAuths(context.Background(), db, providerCodex)
	if err != nil {
		t.Fatal(err)
	}
	if !candidateMatchesInvalidAuth(candidate, invalids) {
		t.Fatal("migrated sensitive active state stopped filtering its raw scheduler candidate")
	}
}

func TestReservationsAndQuotaRunsNeverPersistRawCredentialIdentities(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("CPA_TOKEN_USAGE_DIR", dir)
	path := filepath.Join(dir, "usage.db")
	db, err := openSQLiteDB(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := initializeSQLiteStore(context.Background(), db, path); err != nil {
		t.Fatal(err)
	}
	s := &store{db: db, dbPath: path}
	t.Cleanup(s.close)
	raw := "123e4567-e89b-12d3-a456-426614174000"
	candidate := schedulerAuthCandidate{
		ID:       raw,
		Provider: "codex",
		Priority: 1,
		Attributes: map[string]string{
			"auth_index": raw,
			"source":     "Bearer " + raw,
			"api_key":    raw,
			"plan_type":  "plus",
		},
	}
	cfg := defaultPluginConfig()
	cfg.AccountProtectionEnabled = true
	if _, err := s.pickProtectedAuth(context.Background(), db, []schedulerAuthCandidate{candidate}, cfg, "privacy-test"); err != nil {
		t.Fatal(err)
	}
	var reservation string
	if err := db.QueryRow(`SELECT auth_id||auth_index||source FROM account_protection_reservations`).Scan(&reservation); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(reservation, raw) || !strings.Contains(reservation, "keyfp:v1:") {
		t.Fatalf("reservation persisted raw identity: %q", reservation)
	}
	if err := s.recordUsage(context.Background(), usageRecord{
		Provider:    "codex",
		APIKey:      raw,
		AuthID:      raw,
		AuthIndex:   raw,
		Source:      "Bearer " + raw,
		RequestedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	var reservations int
	if err := db.QueryRow(`SELECT COUNT(*) FROM account_protection_reservations`).Scan(&reservations); err != nil {
		t.Fatal(err)
	}
	if reservations != 0 {
		t.Fatalf("sanitized usage did not release sanitized reservation: %d remain", reservations)
	}
	opaque := "opaque-provider-key-1234567890-QUOTA"
	if err := recordQuotaTriggerRun(context.Background(), db, path, quotaTriggerRun{
		AuthID:     opaque,
		AuthIndex:  "Bearer " + opaque,
		Source:     opaque,
		AuthFile:   opaque,
		Provider:   "codex",
		Status:     "failed",
		StartedAt:  time.Now().Unix(),
		FinishedAt: time.Now().Unix(),
	}); err != nil {
		t.Fatal(err)
	}
	var quotaIdentity string
	if err := db.QueryRow(`SELECT auth_id||auth_index||source||auth_file FROM quota_trigger_runs ORDER BY id DESC LIMIT 1`).Scan(&quotaIdentity); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(quotaIdentity, opaque) || !strings.Contains(quotaIdentity, "keyfp:v1:") {
		t.Fatalf("quota-trigger run persisted raw identity: %q", quotaIdentity)
	}
}

func TestV3StateIdentityCollisionKeepsTheMostRestrictiveState(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("CPA_TOKEN_USAGE_DIR", dir)
	path := filepath.Join(dir, "usage.db")
	writeAPIKeySecretForTest(t, dir, bytes.Repeat([]byte{0x33}, 32))
	raw := "opaque-provider-key-1234567890-COLLISION"
	fingerprint := privacySafeAPIKey(path, raw)
	if fingerprint == "" {
		t.Fatal("failed to create test fingerprint")
	}
	db, err := openSQLiteDB(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Exec(schemaSQL); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`PRAGMA user_version=2`); err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	if _, err := db.Exec(`INSERT INTO invalid_auths(auth_id,auth_index,source,provider,reason,invalidated_at,active) VALUES(?,?,?,'codex','raw',?,1)`, raw, raw, raw, now+20); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO invalid_auths(auth_id,auth_index,source,provider,reason,invalidated_at,active) VALUES(?,?,?,'codex','existing',?,0)`, fingerprint, fingerprint, fingerprint, now+10); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO autoban_bans(auth_id,auth_index,source,provider,window,reason,banned_at,reset_at,active,released_at) VALUES(?,?,?,'codex','week','raw',?,?,1,0)`, raw, raw, raw, now+20, now+7200); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO autoban_bans(auth_id,auth_index,source,provider,window,reason,banned_at,reset_at,active,released_at) VALUES(?,?,?,'codex','5h','existing',?,?,0,?)`, fingerprint, fingerprint, fingerprint, now+10, now+3600, now+30); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO xai_account_states(state_key,auth_id,auth_index,source,provider,state,reason,observed_at,reset_at,active) VALUES(?,?,?,?,'xai','unauthorized','raw',?,0,1)`, raw, raw, raw, raw, now+20); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO xai_account_states(state_key,auth_id,auth_index,source,provider,state,reason,observed_at,reset_at,active) VALUES(?,?,?,?,'xai','rate_limited','existing',?,?,0)`, fingerprint, fingerprint, fingerprint, fingerprint, now+10, now+3600); err != nil {
		t.Fatal(err)
	}
	if err := initializeSQLiteStore(context.Background(), db, path); err != nil {
		t.Fatal(err)
	}
	var invalidCount, invalidActive int
	var invalidatedAt int64
	if err := db.QueryRow(`SELECT COUNT(*),MAX(active),MAX(invalidated_at) FROM invalid_auths WHERE auth_id=?`, fingerprint).Scan(&invalidCount, &invalidActive, &invalidatedAt); err != nil {
		t.Fatal(err)
	}
	if invalidCount != 1 || invalidActive != 1 || invalidatedAt != now+20 {
		t.Fatalf("invalid collision weakened state: count=%d active=%d invalidated=%d", invalidCount, invalidActive, invalidatedAt)
	}
	var banCount, banActive int
	var banReset, releasedAt int64
	var banWindow, banReason string
	if err := db.QueryRow(`SELECT COUNT(*),MAX(active),MAX(reset_at),MAX(released_at),MAX(window),MAX(reason) FROM autoban_bans WHERE auth_id=?`, fingerprint).Scan(&banCount, &banActive, &banReset, &releasedAt, &banWindow, &banReason); err != nil {
		t.Fatal(err)
	}
	if banCount != 1 || banActive != 0 || banReset != now+3600 || releasedAt != now+30 || banWindow != "5h" || banReason != "existing" {
		t.Fatalf("autoban collision mixed rows: count=%d active=%d reset=%d released=%d window=%q reason=%q", banCount, banActive, banReset, releasedAt, banWindow, banReason)
	}
	var xaiCount, xaiActive int
	var xaiObserved, xaiReset int64
	if err := db.QueryRow(`SELECT COUNT(*),MAX(active),MAX(observed_at),MIN(reset_at) FROM xai_account_states WHERE state_key=?`, fingerprint).Scan(&xaiCount, &xaiActive, &xaiObserved, &xaiReset); err != nil {
		t.Fatal(err)
	}
	if xaiCount != 1 || xaiActive != 1 || xaiObserved != now+20 || xaiReset != 0 {
		t.Fatalf("xAI collision weakened state: count=%d active=%d observed=%d reset=%d", xaiCount, xaiActive, xaiObserved, xaiReset)
	}
}

func TestV3CollisionWinnerKeepsWholeRowAndDiagnosesTies(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("CPA_TOKEN_USAGE_DIR", dir)
	path := filepath.Join(dir, "usage.db")
	writeAPIKeySecretForTest(t, dir, bytes.Repeat([]byte{0x44}, 32))
	db, err := openSQLiteDB(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Exec(schemaSQL); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`PRAGMA user_version=2`); err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()

	activeRaw := "opaque-provider-key-COLLISION-ACTIVE-0001"
	activeFingerprint := privacySafeAPIKey(path, activeRaw)
	if _, err := db.Exec(`INSERT INTO invalid_auths(auth_id,auth_index,source,provider,reason,invalidated_at,active,last_status_code,auth_file,auth_file_mtime) VALUES(?,?,?,'codex','source-active',?,1,401,'source-active.json',?)`, activeRaw, activeRaw, activeRaw, now+20, now+20); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO invalid_auths(auth_id,auth_index,source,provider,reason,invalidated_at,active,last_status_code,auth_file,auth_file_mtime) VALUES(?,?,?,'codex','target-active',?,1,402,'target-active.json',?)`, activeFingerprint, activeFingerprint, activeFingerprint, now+10, now+10); err != nil {
		t.Fatal(err)
	}

	inactiveRaw := "opaque-provider-key-COLLISION-INACTIVE-02"
	inactiveFingerprint := privacySafeAPIKey(path, inactiveRaw)
	if _, err := db.Exec(`INSERT INTO xai_account_states(state_key,auth_id,auth_index,source,provider,state,reason,observed_at,reset_at,active,last_status_code,auth_file,auth_file_mtime) VALUES(?,?,?,?,'xai','unauthorized','source-inactive',?,0,0,401,'source-inactive.json',?)`, inactiveRaw, inactiveRaw, inactiveRaw, inactiveRaw, now+40, now+40); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO xai_account_states(state_key,auth_id,auth_index,source,provider,state,reason,observed_at,reset_at,active,last_status_code,auth_file,auth_file_mtime) VALUES(?,?,?,?,'xai','rate_limited','target-inactive',?,?,0,429,'target-inactive.json',?)`, inactiveFingerprint, inactiveFingerprint, inactiveFingerprint, inactiveFingerprint, now+30, now+3600, now+30); err != nil {
		t.Fatal(err)
	}

	tieRaw := "opaque-provider-key-COLLISION-TIE-000003"
	tieFingerprint := privacySafeAPIKey(path, tieRaw)
	if _, err := db.Exec(`INSERT INTO invalid_auths(auth_id,auth_index,source,provider,reason,invalidated_at,active,last_status_code,auth_file,auth_file_mtime) VALUES(?,?,?,'codex','active-tie',?,1,401,'active-tie.json',?)`, tieRaw, tieRaw, tieRaw, now+60, now+60); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO invalid_auths(auth_id,auth_index,source,provider,reason,invalidated_at,active,last_status_code,auth_file,auth_file_mtime) VALUES(?,?,?,'codex','recovered-tie',?,0,204,'recovered-tie.json',?)`, tieFingerprint, tieFingerprint, tieFingerprint, now+60, now+55); err != nil {
		t.Fatal(err)
	}

	if err := initializeSQLiteStore(context.Background(), db, path); err != nil {
		t.Fatal(err)
	}
	var reason, authFile string
	var invalidatedAt, mtime int64
	var active, status int
	if err := db.QueryRow(`SELECT reason,invalidated_at,active,last_status_code,auth_file,auth_file_mtime FROM invalid_auths WHERE auth_id=?`, activeFingerprint).Scan(&reason, &invalidatedAt, &active, &status, &authFile, &mtime); err != nil {
		t.Fatal(err)
	}
	if reason != "source-active" || invalidatedAt != now+20 || active != 1 || status != 401 || authFile != "source-active.json" || mtime != now+20 {
		t.Fatalf("active/active collision mixed rows: reason=%q invalidated=%d active=%d status=%d file=%q mtime=%d", reason, invalidatedAt, active, status, authFile, mtime)
	}
	var state string
	var observedAt, resetAt int64
	if err := db.QueryRow(`SELECT state,reason,observed_at,reset_at,active,last_status_code,auth_file,auth_file_mtime FROM xai_account_states WHERE state_key=?`, inactiveFingerprint).Scan(&state, &reason, &observedAt, &resetAt, &active, &status, &authFile, &mtime); err != nil {
		t.Fatal(err)
	}
	if state != "unauthorized" || reason != "source-inactive" || observedAt != now+40 || resetAt != 0 || active != 0 || status != 401 || authFile != "source-inactive.json" || mtime != now+40 {
		t.Fatalf("inactive/inactive collision mixed rows: state=%q reason=%q observed=%d reset=%d active=%d status=%d file=%q mtime=%d", state, reason, observedAt, resetAt, active, status, authFile, mtime)
	}
	if err := db.QueryRow(`SELECT reason,invalidated_at,active,last_status_code,auth_file,auth_file_mtime FROM invalid_auths WHERE auth_id=?`, tieFingerprint).Scan(&reason, &invalidatedAt, &active, &status, &authFile, &mtime); err != nil {
		t.Fatal(err)
	}
	if reason != "active-tie" || invalidatedAt != now+60 || active != 1 || status != 401 || authFile != "active-tie.json" || mtime != now+60 {
		t.Fatalf("active/inactive tie mixed rows: reason=%q invalidated=%d active=%d status=%d file=%q mtime=%d", reason, invalidatedAt, active, status, authFile, mtime)
	}
	statusView := apiKeyFingerprintStatus(context.Background(), db)
	if statusView.IdentityCollisionTies == 0 || !strings.Contains(statusView.CollisionTiePolicy, "documented total order") {
		t.Fatalf("tie diagnostics = %+v", statusView)
	}
}

func TestV3MigrationFailsClosedWhenExistingV1SecretIsMissing(t *testing.T) {
	existing := "keyfp:v1:0123456789abcdef0123456789abcdef:ABCD"
	tests := []struct {
		name  string
		query string
		args  []any
	}{
		{name: "usage api_key", query: `INSERT INTO usage_events(requested_at,provider,api_key) VALUES(1,'codex',?)`, args: []any{existing}},
		{name: "usage embedded auth_id", query: `INSERT INTO usage_events(requested_at,provider,auth_id) VALUES(1,'codex',?)`, args: []any{"codex:apikey:" + existing}},
		{name: "third-party usage api_key", query: `INSERT INTO usage_events(requested_at,provider,api_key) VALUES(1,'anthropic',?)`, args: []any{existing}},
		{name: "third-party usage embedded auth_id", query: `INSERT INTO usage_events(requested_at,provider,auth_id) VALUES(1,'gemini',?)`, args: []any{"gemini:apikey:" + existing}},
		{name: "invalid state", query: `INSERT INTO invalid_auths(auth_id,provider,reason,invalidated_at,active) VALUES(?,'codex','test',1,1)`, args: []any{existing}},
		{name: "autoban state", query: `INSERT INTO autoban_bans(auth_id,provider,window,reason,banned_at,reset_at,active) VALUES(?,'codex','5h','test',1,9999999999,1)`, args: []any{existing}},
		{name: "xai state", query: `INSERT INTO xai_account_states(state_key,auth_id,provider,state,reason,observed_at,active) VALUES(?,?,'xai','unauthorized','test',1,1)`, args: []any{existing, existing}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "usage.db")
			db, err := openSQLiteDB(path)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			if _, err := db.Exec(schemaSQL); err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec(`PRAGMA user_version=2`); err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec(test.query, test.args...); err != nil {
				t.Fatal(err)
			}
			resetAPIKeySecretCacheForTest(dir)
			err = initializeSQLiteStore(context.Background(), db, path)
			if err == nil || !strings.Contains(strings.ToLower(err.Error()), "missing") {
				t.Fatalf("migration error = %v, want missing-secret failure", err)
			}
			if _, statErr := os.Stat(filepath.Join(dir, apiKeyFingerprintSecretFile)); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("missing secret was silently recreated: %v", statErr)
			}
			var version int
			if err := db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
				t.Fatal(err)
			}
			if version != 2 {
				t.Fatalf("failed migration advanced schema to %d", version)
			}
		})
	}
}

func TestV3MigrationFailsClosedWhenExistingV1SecretIsCorrupt(t *testing.T) {
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
	if _, err := db.Exec(`PRAGMA user_version=2`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO usage_events(requested_at,provider,api_key) VALUES(1,'anthropic','keyfp:v1:0123456789abcdef0123456789abcdef:ABCD')`); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, apiKeyFingerprintSecretFile), []byte("corrupt"), 0o600); err != nil {
		t.Fatal(err)
	}
	resetAPIKeySecretCacheForTest(dir)
	if err := initializeSQLiteStore(context.Background(), db, path); err == nil {
		t.Fatal("migration accepted a corrupt secret for existing v1 fingerprints")
	}
	var version int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != 2 {
		t.Fatalf("failed corrupt-secret migration advanced schema to %d", version)
	}
}

func TestV3SecretBindingRejectsReplacementSecret(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "usage.db")
	writeAPIKeySecretForTest(t, dir, bytes.Repeat([]byte{0x11}, 32))
	db, err := openSQLiteDB(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := initializeSQLiteStore(context.Background(), db, path); err != nil {
		t.Fatal(err)
	}
	writeAPIKeySecretForTest(t, dir, bytes.Repeat([]byte{0x22}, 32))
	err = initializeSQLiteStore(context.Background(), db, path)
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "does not match") {
		t.Fatalf("replacement-secret validation error = %v", err)
	}
}

func TestRuntimeFingerprintFailureDoesNotPersistV0(t *testing.T) {
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
	if err := os.WriteFile(filepath.Join(dir, apiKeyFingerprintSecretFile), []byte("corrupt"), 0o600); err != nil {
		t.Fatal(err)
	}
	resetAPIKeySecretCacheForTest(dir)
	s := &store{db: db, dbPath: path}
	err = s.recordUsage(context.Background(), usageRecord{APIKey: "opaque-secret-1234567890-ABCDE", Provider: "codex", RequestedAt: time.Now()})
	if err == nil {
		t.Fatal("usage record succeeded with a corrupt fingerprint secret")
	}
	var rows int
	if err := db.QueryRow(`SELECT COUNT(*) FROM usage_events`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 0 {
		t.Fatalf("runtime persisted %d rows after fingerprint failure", rows)
	}
	if got := privacySafeAPIKey(path, "opaque-secret-1234567890-ABCDE"); got != "" || strings.HasPrefix(got, "keyfp:v0:") {
		t.Fatalf("fallback fingerprint = %q, want empty and never v0", got)
	}
}

func TestLegacyV0IsLocallyRekeyedAndDiagnosedAsUnlinkable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "usage.db")
	writeAPIKeySecretForTest(t, dir, bytes.Repeat([]byte{0x5a}, 32))
	db, err := openSQLiteDB(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Exec(schemaSQL); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`PRAGMA user_version=2`); err != nil {
		t.Fatal(err)
	}
	legacy := "keyfp:v0:0123456789abcdef0123456789abcdef:9Z_-"
	if _, err := db.Exec(`INSERT INTO usage_events(requested_at,provider,api_key,auth_id) VALUES(1,'codex',?,?)`, legacy, legacy); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO invalid_auths(auth_id,provider,reason,invalidated_at,active) VALUES(?,'codex','legacy-inactive',1,0)`, legacy); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO account_protection_reservations(auth_id,created_at,expires_at) VALUES(?,1,2)`, legacy); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO quota_trigger_runs(auth_file,provider,status,started_at,finished_at) VALUES(?,'codex','failed',1,2)`, legacy); err != nil {
		t.Fatal(err)
	}
	if err := initializeSQLiteStore(context.Background(), db, path); err != nil {
		t.Fatal(err)
	}
	var migrated, authID string
	if err := db.QueryRow(`SELECT api_key,auth_id FROM usage_events`).Scan(&migrated, &authID); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(migrated, "keyfp:v1:") || migrated == legacy || authID != migrated {
		t.Fatalf("legacy fingerprint migration = %q / %q", migrated, authID)
	}
	status := apiKeyFingerprintStatus(context.Background(), db)
	if status.LegacyUnlinkableRows != 3 || !strings.Contains(status.Compatibility, "cannot be linked") {
		t.Fatalf("privacy diagnostics = %+v", status)
	}
	for _, query := range []string{
		`SELECT auth_id FROM invalid_auths`,
		`SELECT auth_file FROM quota_trigger_runs`,
	} {
		var value string
		if err := db.QueryRow(query).Scan(&value); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(strings.ToLower(value), "keyfp:v0:") || !strings.Contains(strings.ToLower(value), "keyfp:v1:") {
			t.Fatalf("legacy identity was not locally re-keyed for %q: %q", query, value)
		}
	}
	var reservations int
	if err := db.QueryRow(`SELECT COUNT(*) FROM account_protection_reservations`).Scan(&reservations); err != nil {
		t.Fatal(err)
	}
	if reservations != 0 {
		t.Fatalf("legacy reservations retained during v5 migration: %d", reservations)
	}
}

func TestUnknownActiveV0QuarantinesOnlyItsProviderAndReleaseClearsOnRestart(t *testing.T) {
	isolateAPIKeyPrivacyQuarantineForTest(t)
	dir := t.TempDir()
	t.Setenv("CPA_TOKEN_USAGE_DIR", dir)
	t.Setenv("CPA_CONFIG_PATH", filepath.Join(t.TempDir(), "missing-config.yaml"))
	path := filepath.Join(dir, "usage.db")
	db, err := openSQLiteDB(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(schemaSQL); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`PRAGMA user_version=2`); err != nil {
		t.Fatal(err)
	}
	raw := "sk-proj-quarantine-release-1234567890"
	legacy := legacyV0Fingerprint(raw)
	if _, err := db.Exec(`INSERT INTO invalid_auths(auth_id,auth_index,source,provider,reason,invalidated_at,active) VALUES(?,?,?,'codex','legacy-v0',?,1)`, legacy, legacy, legacy, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	if err := initializeSQLiteStore(context.Background(), db, path); err != nil {
		t.Fatal(err)
	}
	s := &store{db: db, dbPath: path}
	refreshAPIKeyPrivacyQuarantineForTest(t, s, db, path)
	if reason, ok := s.apiKeyPrivacyQuarantineReason("codex"); !ok || reason == "" {
		t.Fatalf("codex quarantine = %q, %v", reason, ok)
	}
	if _, ok := s.apiKeyPrivacyQuarantineReason("xai"); ok {
		t.Fatal("unaffected xai provider was quarantined")
	}
	_, err = s.pickAuthOnce(context.Background(), schedulerPickRequest{Provider: "codex", Candidates: []schedulerAuthCandidate{{ID: raw, Provider: "codex"}}})
	var reject *schedulerRejectError
	if !errors.As(err, &reject) || reject.Code != "privacy_quarantine" || reject.HTTPStatus != 503 {
		t.Fatalf("scheduler error = %#v / %v", reject, err)
	}
	if _, err := s.summary(context.Background(), "24h", 50); err != nil {
		t.Fatalf("summary unavailable during provider quarantine: %v", err)
	}
	if _, err := db.Exec(`UPDATE invalid_auths SET active=0 WHERE reason='legacy-v0'`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	resetAPIKeySecretCacheForTest(dir)
	db, err = openSQLiteDB(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := initializeSQLiteStore(context.Background(), db, path); err != nil {
		t.Fatal(err)
	}
	s = &store{db: db, dbPath: path}
	refreshAPIKeyPrivacyQuarantineForTest(t, s, db, path)
	if _, ok := s.apiKeyPrivacyQuarantineReason("codex"); ok {
		t.Fatal("released legacy restriction remained quarantined after restart")
	}
	var markerRows int
	if err := db.QueryRow(`SELECT COUNT(*) FROM store_state WHERE key='api_key_privacy_quarantine_codex'`).Scan(&markerRows); err != nil {
		t.Fatal(err)
	}
	if markerRows != 0 {
		t.Fatalf("release left %d quarantine markers", markerRows)
	}
}

func TestExplicitForeignProvidersRemainInertDuringPrivacyMigration(t *testing.T) {
	isolateAPIKeyPrivacyQuarantineForTest(t)
	dir := t.TempDir()
	t.Setenv("CPA_TOKEN_USAGE_DIR", dir)
	t.Setenv("CPA_CONFIG_PATH", filepath.Join(t.TempDir(), "missing-config.yaml"))
	path := filepath.Join(dir, "usage.db")
	db, err := openSQLiteDB(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Exec(schemaSQL); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`PRAGMA user_version=2`); err != nil {
		t.Fatal(err)
	}
	codexLegacy := legacyV0Fingerprint("sk-proj-dirty-codex-provider-123456")
	xaiLegacy := legacyV0Fingerprint("xai-dirty-provider-credential-123456789")
	if _, err := db.Exec(`INSERT INTO invalid_auths(auth_id,auth_index,source,provider,reason,invalidated_at,active) VALUES(?,?,?,'openai','dirty-provider',1,1)`, codexLegacy, codexLegacy, codexLegacy); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO xai_account_states(state_key,auth_id,auth_index,source,provider,state,reason,observed_at,reset_at,active) VALUES(?,?,?,?,'grok','unauthorized','dirty-provider',1,0,1)`, xaiLegacy, xaiLegacy, xaiLegacy, xaiLegacy); err != nil {
		t.Fatal(err)
	}
	if err := initializeSQLiteStore(context.Background(), db, path); err != nil {
		t.Fatal(err)
	}
	s := &store{db: db, dbPath: path}
	refreshAPIKeyPrivacyQuarantineForTest(t, s, db, path)
	for _, provider := range []string{"codex", "xai", "openai", "grok"} {
		if _, ok := s.apiKeyPrivacyQuarantineReason(provider); ok {
			t.Fatalf("explicit foreign Provider %q unexpectedly entered privacy quarantine", provider)
		}
	}
	for _, check := range []struct {
		query string
		want  string
	}{
		{query: `SELECT provider FROM invalid_auths WHERE reason='dirty-provider'`, want: "openai"},
		{query: `SELECT provider FROM xai_account_states WHERE reason='dirty-provider'`, want: "grok"},
	} {
		var got string
		if err := db.QueryRow(check.query).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != check.want {
			t.Fatalf("foreign Provider after migration = %q, want %q", got, check.want)
		}
	}
}

func TestActiveQuarantineReferencesAreProviderScoped(t *testing.T) {
	db := newProtectionTestDB(t)
	now := time.Now().Unix()
	foreign := legacyV0Fingerprint("foreign-provider-quarantine-reference")
	codex := legacyV0Fingerprint("codex-provider-quarantine-reference")
	xai := legacyV0Fingerprint("xai-provider-quarantine-reference")
	if _, err := db.Exec(`
INSERT INTO invalid_auths(auth_id,provider,reason,invalidated_at,active)
VALUES(?, 'openai', 'foreign', ?, 1), (?, 'codex', 'codex', ?, 1);
INSERT INTO xai_account_states(state_key,provider,state,reason,observed_at,active)
VALUES(?, 'codex', 'unauthorized', 'wrong-table', ?, 1), (?, 'xai', 'unauthorized', 'xai', ?, 1);`,
		foreign, now, codex, now, foreign, now, xai, now); err != nil {
		t.Fatal(err)
	}
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()

	foreignRefs, err := activeQuarantineReferences(context.Background(), tx, providerCodex, map[string]struct{}{foreign: {}})
	if err != nil {
		t.Fatal(err)
	}
	if len(foreignRefs) != 0 {
		t.Fatalf("foreign/wrong-table rows kept Codex quarantine active: %+v", foreignRefs)
	}
	codexRefs, err := activeQuarantineReferences(context.Background(), tx, providerCodex, map[string]struct{}{codex: {}})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := codexRefs[codex]; !ok || len(codexRefs) != 1 {
		t.Fatalf("Codex quarantine references = %+v", codexRefs)
	}
	xaiRefs, err := activeQuarantineReferences(context.Background(), tx, providerXAI, map[string]struct{}{xai: {}})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := xaiRefs[xai]; !ok || len(xaiRefs) != 1 {
		t.Fatalf("xAI quarantine references = %+v", xaiRefs)
	}
}

func TestMalformedQuarantineMarkerAndMixedCandidatesRemainFailClosed(t *testing.T) {
	isolateAPIKeyPrivacyQuarantineForTest(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "usage.db")
	db, err := openSQLiteDB(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := initializeSQLiteStore(context.Background(), db, path); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO store_state(key,value) VALUES('api_key_privacy_quarantine_codex','truncated-marker')`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	resetAPIKeySecretCacheForTest(dir)
	db, err = openSQLiteDB(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := initializeSQLiteStore(context.Background(), db, path); err != nil {
		t.Fatal(err)
	}
	s := &store{db: db, dbPath: path}
	refreshAPIKeyPrivacyQuarantineForTest(t, s, db, path)
	reason, ok := s.apiKeyPrivacyQuarantineReason("codex")
	if !ok || !strings.Contains(reason, "malformed") {
		t.Fatalf("malformed marker quarantine = %q, %v", reason, ok)
	}
	req := schedulerPickRequest{
		Provider:  "mixed",
		Providers: []string{"xai", "codex"},
		Candidates: []schedulerAuthCandidate{
			{ID: "xai-candidate", Provider: "xai"},
			{ID: "codex-candidate", Provider: "codex"},
		},
	}
	resp, err := s.pickAuthOnce(context.Background(), req)
	if err != nil || !resp.Handled || resp.AuthID != "xai-candidate" {
		t.Fatalf("mixed quarantine response = %#v / %v, want healthy xAI candidate", resp, err)
	}
	var value string
	if err := db.QueryRow(`SELECT value FROM store_state WHERE key='api_key_privacy_quarantine_codex'`).Scan(&value); err != nil {
		t.Fatal(err)
	}
	if value != "truncated-marker" {
		t.Fatalf("malformed marker was silently rewritten or cleared: %q", value)
	}
}

func TestPartiallyMalformedQuarantineMarkerCannotBeReconciledOpen(t *testing.T) {
	isolateAPIKeyPrivacyQuarantineForTest(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "usage.db")
	db, err := openSQLiteDB(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := initializeSQLiteStore(context.Background(), db, path); err != nil {
		t.Fatal(err)
	}
	valid := "keyfp:v1:0123456789abcdef0123456789abcdef:ABCD"
	marker := valid + ",truncated-marker"
	if _, err := db.Exec(`INSERT INTO store_state(key,value) VALUES('api_key_privacy_quarantine_codex',?)`, marker); err != nil {
		t.Fatal(err)
	}
	reasons, fingerprints, err := loadAPIKeyPrivacyQuarantine(context.Background(), db)
	if err != nil {
		t.Fatal(err)
	}
	if reason := reasons[providerCodex]; !strings.Contains(reason, "malformed") || fingerprints[providerCodex] != nil {
		t.Fatalf("partially malformed marker loaded as reason=%q fingerprints=%+v", reason, fingerprints[providerCodex])
	}
	secret, err := loadExistingAPIKeySecret(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := reconcileAPIKeyPrivacyQuarantine(context.Background(), db, path, secret); err != nil {
		t.Fatal(err)
	}
	var retained string
	if err := db.QueryRow(`SELECT value FROM store_state WHERE key='api_key_privacy_quarantine_codex'`).Scan(&retained); err != nil {
		t.Fatal(err)
	}
	if retained != marker {
		t.Fatalf("partially malformed marker was rewritten or cleared: %q", retained)
	}
}

func TestPrivacyQuarantineSnapshotsAreStoreAndDatabaseScoped(t *testing.T) {
	quarantinedDir := t.TempDir()
	quarantinedPath := filepath.Join(quarantinedDir, "usage.db")
	quarantinedDB, err := openSQLiteDB(quarantinedPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := initializeSQLiteStore(context.Background(), quarantinedDB, quarantinedPath); err != nil {
		t.Fatal(err)
	}
	if _, err := quarantinedDB.Exec(`INSERT INTO store_state(key,value) VALUES('api_key_privacy_quarantine_codex','malformed-store-a')`); err != nil {
		t.Fatal(err)
	}
	if err := quarantinedDB.Close(); err != nil {
		t.Fatal(err)
	}
	resetAPIKeySecretCacheForTest(quarantinedDir)
	quarantinedDB, err = openSQLiteDB(quarantinedPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = quarantinedDB.Close() })
	if err := initializeSQLiteStore(context.Background(), quarantinedDB, quarantinedPath); err != nil {
		t.Fatal(err)
	}
	quarantinedStore := &store{db: quarantinedDB, dbPath: quarantinedPath}
	refreshAPIKeyPrivacyQuarantineForTest(t, quarantinedStore, quarantinedDB, quarantinedPath)

	cleanDir := t.TempDir()
	cleanPath := filepath.Join(cleanDir, "usage.db")
	cleanDB, err := openSQLiteDB(cleanPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cleanDB.Close() })
	if err := initializeSQLiteStore(context.Background(), cleanDB, cleanPath); err != nil {
		t.Fatal(err)
	}
	cleanStore := &store{db: cleanDB, dbPath: cleanPath}
	refreshAPIKeyPrivacyQuarantineForTest(t, cleanStore, cleanDB, cleanPath)

	req := schedulerPickRequest{Provider: "codex", Candidates: []schedulerAuthCandidate{{ID: "candidate", Provider: "codex"}}}
	if _, _, quarantined := quarantinedStore.schedulerRequestPrivacyQuarantine(req); !quarantined {
		t.Fatal("quarantined store lost its marker after a clean database initialized")
	}
	if provider, reason, quarantined := cleanStore.schedulerRequestPrivacyQuarantine(req); quarantined {
		t.Fatalf("clean store inherited another database quarantine: provider=%q reason=%q", provider, reason)
	}
	snapshot := quarantinedStore.privacyQuarantine.snapshot.Load()
	if snapshot == nil || snapshot.dbKey != canonicalAPIKeyDatabasePath(quarantinedPath) {
		t.Fatalf("quarantine snapshot database key = %#v, want %q", snapshot, canonicalAPIKeyDatabasePath(quarantinedPath))
	}
	if cleanStore.privacyQuarantine.snapshot.Load() != nil {
		t.Fatal("clean store retained a non-empty quarantine snapshot")
	}
}

func TestRestoringConfiguredKeyRekeysAndClearsV0Quarantine(t *testing.T) {
	isolateAPIKeyPrivacyQuarantineForTest(t)
	dir := t.TempDir()
	t.Setenv("CPA_TOKEN_USAGE_DIR", dir)
	t.Setenv("CPA_CONFIG_PATH", filepath.Join(t.TempDir(), "missing-config.yaml"))
	path := filepath.Join(dir, "usage.db")
	db, err := openSQLiteDB(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(schemaSQL); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`PRAGMA user_version=2`); err != nil {
		t.Fatal(err)
	}
	raw := "sk-proj-quarantine-restore-1234567890"
	legacy := legacyV0Fingerprint(raw)
	if _, err := db.Exec(`INSERT INTO invalid_auths(auth_id,auth_index,source,provider,reason,invalidated_at,active) VALUES(?,?,?,'codex','legacy-v0',?,1)`, legacy, legacy, legacy, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	if err := initializeSQLiteStore(context.Background(), db, path); err != nil {
		t.Fatal(err)
	}
	s := &store{db: db, dbPath: path}
	refreshAPIKeyPrivacyQuarantineForTest(t, s, db, path)
	if _, ok := s.apiKeyPrivacyQuarantineReason("codex"); !ok {
		t.Fatal("missing initial codex quarantine")
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	writeConfiguredAPIKeyForTest(t, raw)
	resetAPIKeySecretCacheForTest(dir)
	db, err = openSQLiteDB(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := initializeSQLiteStore(context.Background(), db, path); err != nil {
		t.Fatal(err)
	}
	s = &store{db: db, dbPath: path}
	refreshAPIKeyPrivacyQuarantineForTest(t, s, db, path)
	if _, ok := s.apiKeyPrivacyQuarantineReason("codex"); ok {
		t.Fatal("restored configured key did not clear quarantine")
	}
	want := privacySafeAPIKey(path, raw)
	var authID string
	if err := db.QueryRow(`SELECT auth_id FROM invalid_auths WHERE reason='legacy-v0'`).Scan(&authID); err != nil {
		t.Fatal(err)
	}
	if authID != want || !strings.HasPrefix(authID, "keyfp:v1:") {
		t.Fatalf("restored v0 identity = %q, want %q", authID, want)
	}
	candidate := schedulerAuthCandidate{ID: raw, Provider: "codex", Attributes: map[string]string{"api_key": raw}}
	invalids, err := queryActiveInvalidAuths(context.Background(), db, providerCodex)
	if err != nil {
		t.Fatal(err)
	}
	if !candidateMatchesInvalidAuth(candidate, invalids) {
		t.Fatal("restored standard v1 restriction does not match the raw candidate")
	}
}

func TestV2UnboundV1RejectsValidButWrongSecretForActiveFingerprintOnlyState(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "usage.db")
	raw := "sk-proj-v1-proof-1234567890-SECRET"
	correctSecret := bytes.Repeat([]byte{0x11}, 32)
	stored := fingerprintRawAPIKeyWithSecret(correctSecret, raw)
	writeAPIKeySecretForTest(t, dir, bytes.Repeat([]byte{0x22}, 32))
	writeConfiguredAPIKeyForTest(t, raw)
	db, err := openSQLiteDB(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Exec(schemaSQL); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`PRAGMA user_version=2`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO invalid_auths(auth_id,auth_index,source,provider,reason,invalidated_at,active) VALUES(?,?,?,'codex','v1-proof',1,1)`, stored, stored, stored); err != nil {
		t.Fatal(err)
	}
	err = initializeSQLiteStore(context.Background(), db, path)
	if err == nil || !strings.Contains(err.Error(), "cannot verify") {
		t.Fatalf("wrong valid secret error = %v", err)
	}
	var version int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != 2 {
		t.Fatalf("failed proof advanced schema to %d", version)
	}
}

func TestV2UnboundV1MixedSecretActiveRestrictionsRequireEveryRowProven(t *testing.T) {
	currentSecret := bytes.Repeat([]byte{0x51}, 32)
	wrongSecret := bytes.Repeat([]byte{0x52}, 32)
	provenRaw := "sk-proj-v1-mixed-proven-1234567890"
	unprovenRaw := "sk-proj-v1-mixed-unproven-1234567890"
	proven := fingerprintRawAPIKeyWithSecret(currentSecret, provenRaw)
	unproven := fingerprintRawAPIKeyWithSecret(wrongSecret, unprovenRaw)

	for _, tc := range []struct {
		name   string
		table  string
		insert func(*testing.T, *sql.DB, string, string)
	}{
		{
			name:  "invalid auth",
			table: "invalid_auths",
			insert: func(t *testing.T, db *sql.DB, proven, unproven string) {
				t.Helper()
				_, err := db.Exec(`INSERT INTO invalid_auths(auth_id,auth_index,source,provider,reason,invalidated_at,active) VALUES
					(?,?,?,'codex','mixed-proven',1,1),
					(?,?,?,'codex','mixed-unproven',2,1)`, proven, proven, proven, unproven, unproven, unproven)
				if err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name:  "autoban",
			table: "autoban_bans",
			insert: func(t *testing.T, db *sql.DB, proven, unproven string) {
				t.Helper()
				resetAt := time.Now().Add(time.Hour).Unix()
				_, err := db.Exec(`INSERT INTO autoban_bans(auth_id,auth_index,source,provider,window,reason,banned_at,reset_at,active) VALUES
					(?,?,?,'codex','5h','mixed-proven',1,?,1),
					(?,?,?,'codex','5h','mixed-unproven',2,?,1)`, proven, proven, proven, resetAt, unproven, unproven, unproven, resetAt)
				if err != nil {
					t.Fatal(err)
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "usage.db")
			writeAPIKeySecretForTest(t, dir, currentSecret)
			writeConfiguredAPIKeyForTest(t, provenRaw)
			db, err := openSQLiteDB(path)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			if _, err := db.Exec(schemaSQL); err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec(`PRAGMA user_version=2`); err != nil {
				t.Fatal(err)
			}
			tc.insert(t, db, proven, unproven)
			err = initializeSQLiteStore(context.Background(), db, path)
			if err == nil || !strings.Contains(err.Error(), "cannot verify") || !strings.Contains(err.Error(), tc.table) {
				t.Fatalf("mixed-secret %s binding error = %v", tc.table, err)
			}
			var version int
			if err := db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
				t.Fatal(err)
			}
			if version != 2 {
				t.Fatalf("failed mixed-secret proof advanced schema to %d", version)
			}
		})
	}

	t.Run("all active restrictions proven", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "usage.db")
		writeAPIKeySecretForTest(t, dir, currentSecret)
		writeConfiguredAPIKeysForTest(t, provenRaw, unprovenRaw)
		db, err := openSQLiteDB(path)
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		if _, err := db.Exec(schemaSQL); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`PRAGMA user_version=2`); err != nil {
			t.Fatal(err)
		}
		secondProven := fingerprintRawAPIKeyWithSecret(currentSecret, unprovenRaw)
		if _, err := db.Exec(`INSERT INTO invalid_auths(auth_id,auth_index,source,provider,reason,invalidated_at,active) VALUES(?,?,?,'codex','proven-invalid',1,1)`, proven, proven, proven); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`INSERT INTO autoban_bans(auth_id,auth_index,source,provider,window,reason,banned_at,reset_at,active) VALUES(?,?,?,'codex','5h','proven-autoban',1,?,1)`, secondProven, secondProven, secondProven, time.Now().Add(time.Hour).Unix()); err != nil {
			t.Fatal(err)
		}
		if err := initializeSQLiteStore(context.Background(), db, path); err != nil {
			t.Fatal(err)
		}
		status := apiKeyFingerprintStatus(context.Background(), db)
		if status.BindingStatus != "verified_legacy" || status.UnverifiedV1Rows != 0 {
			t.Fatalf("fully proven binding diagnostics = %+v", status)
		}
	})
}

func TestV2UnboundV1ConfiguredProofBindsAndHistoricalOnlyIsDiagnosed(t *testing.T) {
	t.Run("configured proof", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "usage.db")
		raw := "sk-proj-v1-correct-proof-1234567890"
		secret := bytes.Repeat([]byte{0x31}, 32)
		stored := fingerprintRawAPIKeyWithSecret(secret, raw)
		writeAPIKeySecretForTest(t, dir, secret)
		writeConfiguredAPIKeyForTest(t, raw)
		db, err := openSQLiteDB(path)
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		if _, err := db.Exec(schemaSQL); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`PRAGMA user_version=2`); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`INSERT INTO invalid_auths(auth_id,auth_index,source,provider,reason,invalidated_at,active) VALUES(?,?,?,'codex','v1-proof',1,1)`, stored, stored, stored); err != nil {
			t.Fatal(err)
		}
		if err := initializeSQLiteStore(context.Background(), db, path); err != nil {
			t.Fatal(err)
		}
		status := apiKeyFingerprintStatus(context.Background(), db)
		if status.BindingStatus != "verified_legacy" || status.UnverifiedV1Rows != 0 {
			t.Fatalf("verified binding diagnostics = %+v", status)
		}
	})

	t.Run("historical only unverified", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "usage.db")
		raw := "sk-proj-v1-historical-proof-1234567890"
		stored := fingerprintRawAPIKeyWithSecret(bytes.Repeat([]byte{0x41}, 32), raw)
		writeAPIKeySecretForTest(t, dir, bytes.Repeat([]byte{0x42}, 32))
		writeConfiguredAPIKeyForTest(t, raw)
		db, err := openSQLiteDB(path)
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		if _, err := db.Exec(schemaSQL); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`PRAGMA user_version=2`); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`INSERT INTO usage_events(requested_at,provider,api_key) VALUES(1,'anthropic',?)`, stored); err != nil {
			t.Fatal(err)
		}
		if err := initializeSQLiteStore(context.Background(), db, path); err != nil {
			t.Fatal(err)
		}
		status := apiKeyFingerprintStatus(context.Background(), db)
		if status.BindingStatus != "legacy_unverified" || status.UnverifiedV1Rows != 1 || !strings.Contains(status.Compatibility, "without a configured-key proof") {
			t.Fatalf("unverified historical binding diagnostics = %+v", status)
		}
	})
}

func TestDatabaseScopedSecretsIsolateNonStandardDatabases(t *testing.T) {
	dir := t.TempDir()
	firstPath := filepath.Join(dir, "first.db")
	secondPath := filepath.Join(dir, "second.db")
	for _, path := range []string{firstPath, secondPath} {
		db, err := openSQLiteDB(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := initializeSQLiteStore(context.Background(), db, path); err != nil {
			_ = db.Close()
			t.Fatal(err)
		}
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if apiKeySecretPath(firstPath) == apiKeySecretPath(secondPath) {
		t.Fatalf("non-standard databases share sidecar %q", apiKeySecretPath(firstPath))
	}
	for _, path := range []string{apiKeySecretPath(firstPath), apiKeySecretPath(secondPath)} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("isolated sidecar %q: %v", path, err)
		}
	}
	raw := "sk-proj-database-scope-1234567890"
	if first, second := privacySafeAPIKey(firstPath, raw), privacySafeAPIKey(secondPath, raw); first == second {
		t.Fatalf("database-scoped fingerprints are linkable: %q", first)
	}
	standard := filepath.Join(dir, "usage.db")
	if got, want := apiKeySecretPath(standard), filepath.Join(dir, apiKeyFingerprintSecretFile); got != want {
		t.Fatalf("standard usage.db sidecar = %q, want legacy-compatible %q", got, want)
	}
}

func TestAPIKeySecretPathPreservesRelativeAndSymlinkUsageDBCompatibility(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("CPA_TOKEN_USAGE_DIR", dir)
	if got, want := apiKeySecretPath("usage.db"), filepath.Join(dir, apiKeyFingerprintSecretFile); got != want {
		t.Fatalf("relative usage.db sidecar = %q, want %q", got, want)
	}

	targetDir := t.TempDir()
	target := filepath.Join(targetDir, "custom-target.db")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	linkDir := t.TempDir()
	link := filepath.Join(linkDir, "usage.db")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if got, want := apiKeySecretPath(link), filepath.Join(linkDir, apiKeyFingerprintSecretFile); got != want {
		t.Fatalf("symlink usage.db sidecar = %q, want legacy-compatible %q", got, want)
	}
	if got := apiKeySecretPath(target); got == filepath.Join(targetDir, apiKeyFingerprintSecretFile) {
		t.Fatalf("non-standard symlink target lost database-scoped sidecar: %q", got)
	}
	nonStandardLink := filepath.Join(linkDir, "custom-link.db")
	if err := os.Symlink(target, nonStandardLink); err != nil {
		t.Fatal(err)
	}
	secret, err := loadOrCreateAPIKeySecret(nonStandardLink)
	if err != nil {
		t.Fatal(err)
	}
	secretPath := apiKeySecretPath(nonStandardLink)
	if filepath.Dir(secretPath) != canonicalAPIKeyDatabasePath(targetDir) && filepath.Dir(secretPath) != filepath.Clean(targetDir) {
		t.Fatalf("non-standard symlink sidecar directory = %q, want canonical target directory %q", filepath.Dir(secretPath), targetDir)
	}
	if _, err := os.Stat(secretPath); err != nil {
		t.Fatalf("non-standard symlink sidecar was not created: %v", err)
	}
	apiKeySecrets.Lock()
	delete(apiKeySecrets.byDB, apiKeySecretCacheKey(nonStandardLink))
	apiKeySecrets.Unlock()
	loaded, err := loadExistingAPIKeySecret(nonStandardLink)
	if err != nil || !bytes.Equal(loaded, secret) {
		t.Fatalf("reload non-standard symlink secret = %x, %v; want %x", loaded, err, secret)
	}
}

func TestStoredIdentityReplacesEveryConfiguredCredentialLongestFirst(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "usage.db")
	shortKey := "sk-proj-overlap-1234567890"
	longKey := shortKey + "-longer-credential"
	configured := []string{shortKey, longKey, shortKey}
	value := "primary=" + longKey + ";fallback=" + shortKey + ";repeat=" + longKey
	want := "primary=" + privacySafeAPIKey(path, longKey) + ";fallback=" + privacySafeAPIKey(path, shortKey) + ";repeat=" + privacySafeAPIKey(path, longKey)

	got, err := privacySafeStoredIdentity(path, value, "", "", configured)
	if err != nil {
		t.Fatal(err)
	}
	if got != want || strings.Contains(got, shortKey) || strings.Contains(got, longKey) {
		t.Fatalf("runtime composite identity = %q, want %q", got, want)
	}

	resolver, err := newLegacyFingerprintResolver(path, configured)
	if err != nil {
		t.Fatal(err)
	}
	got, err = privacySafeStoredIdentityForMigration(path, value, "", "", configured, resolver)
	if err != nil {
		t.Fatal(err)
	}
	if got != want || strings.Contains(got, shortKey) || strings.Contains(got, longKey) {
		t.Fatalf("migration composite identity = %q, want %q", got, want)
	}

	blocker := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blocker, []byte("blocked"), 0o600); err != nil {
		t.Fatal(err)
	}
	badPath := filepath.Join(blocker, "usage.db")
	if _, err := privacySafeStoredIdentity(badPath, value, "", "", configured); err == nil {
		t.Fatal("runtime composite identity swallowed secret-path error")
	}
	if _, err := privacySafeStoredIdentityForMigration(badPath, value, "", "", configured, resolver); err == nil {
		t.Fatal("migration composite identity swallowed secret-path error")
	}
}

func TestV3IdentityMigrationUsesMultipleBatches(t *testing.T) {
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
	if _, err := db.Exec(`PRAGMA user_version=2`); err != nil {
		t.Fatal(err)
	}
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < identityMigrationBatchSize+37; i++ {
		raw := fmt.Sprintf("opaque-provider-key-batch-%04d-SECRET", i)
		if _, err := tx.Exec(`INSERT INTO usage_events(requested_at,provider,api_key,auth_id,auth_index,source) VALUES(?,'codex','',?,?,?)`, i+1, raw, "Bearer "+raw, raw); err != nil {
			_ = tx.Rollback()
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := initializeSQLiteStore(context.Background(), db, path); err != nil {
		t.Fatal(err)
	}
	var migrated, leaked int
	if err := db.QueryRow(`SELECT COUNT(*) FROM usage_events WHERE auth_id LIKE 'keyfp:v1:%' AND auth_index LIKE 'keyfp:v1:%' AND source LIKE 'keyfp:v1:%'`).Scan(&migrated); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM usage_events WHERE auth_id LIKE 'opaque-provider-key-%' OR auth_index LIKE '%opaque-provider-key-%' OR source LIKE '%opaque-provider-key-%'`).Scan(&leaked); err != nil {
		t.Fatal(err)
	}
	if migrated != identityMigrationBatchSize+37 || leaked != 0 {
		t.Fatalf("batched migration: migrated=%d leaked=%d", migrated, leaked)
	}
}

func TestFingerprintDiagnosticsAndLogsDoNotExposeDatabasePath(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "sensitive-user-name", "private")
	path := filepath.Join(dir, "usage.db")
	resetAPIKeySecretCacheForTest(dir)
	var output bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&output)
	t.Cleanup(func() { log.SetOutput(previous) })
	recordAPIKeyFingerprintError(path, &os.PathError{Op: "open", Path: filepath.Join(dir, apiKeyFingerprintSecretFile), Err: os.ErrPermission})
	status := apiKeyFingerprintStatus(context.Background(), nil, path)
	for name, value := range map[string]string{"log": output.String(), "diagnostic": status.LastError} {
		if strings.Contains(value, dir) || strings.Contains(value, "sensitive-user-name") {
			t.Fatalf("%s leaked database path: %q", name, value)
		}
	}
}

func TestModelPriceDiagnosticsStripQueryFragmentAndErrorURLs(t *testing.T) {
	cfg := defaultPluginConfig()
	cfg.ModelPriceAutoUpdateEnabled = false
	cfg.ModelPriceUpdateURL = "HTTPS://Prices.Example.com/private-tenant/table.json?sig=top-secret#private"
	manager := modelPriceUpdateManager{}
	manager.configure(cfg)
	manager.recordPriceUpdateCheck("request HTTPS://Prices.Example.com/private-tenant/table.json?sig=top-secret#private failed", 0, 0, false)
	state := manager.status()
	if state.URL != "https://prices.example.com" {
		t.Fatalf("diagnostic URL = %q, want origin-only lowercase URL", state.URL)
	}
	for _, secret := range []string{"private-tenant", "table.json", "top-secret", "?", "#"} {
		if strings.Contains(state.LastError, secret) {
			t.Fatalf("diagnostic error leaked %q: %q", secret, state.LastError)
		}
	}
}

func TestSafeExportLabelMasksEmbeddedAndOpaqueCredentials(t *testing.T) {
	fingerprint := "keyfp:v1:0123456789abcdef0123456789abcdef:9Z_-"
	if got := safeExportLabel("codex:apikey:" + fingerprint); strings.Contains(got, "0123456789abcdef") || !strings.Contains(got, "****9Z_-") {
		t.Fatalf("embedded fingerprint export = %q", got)
	}
	opaque := "opaque-provider-key-1234567890"
	if got := safeExportLabel(opaque); got == opaque || !strings.Contains(got, "****") {
		t.Fatalf("opaque credential export = %q", got)
	}
}
