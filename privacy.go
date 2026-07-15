package main

import (
	"context"
	"crypto/hmac"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const apiKeyFingerprintSecretFile = ".api-key-hmac"

const identityMigrationBatchSize = 256

var apiKeySecrets = struct {
	sync.Mutex
	byDB map[string][]byte
}{byDB: map[string][]byte{}}

var apiKeyFallbackWarnings = struct {
	sync.Mutex
	byDB map[string]struct{}
}{byDB: map[string]struct{}{}}

type apiKeyFingerprintDiagnostics struct {
	Checked               bool     `json:"checked"`
	Available             bool     `json:"available"`
	SecretBound           bool     `json:"secret_bound"`
	BindingStatus         string   `json:"binding_status,omitempty"`
	UnverifiedV1Rows      int64    `json:"unverified_v1_rows,omitempty"`
	LegacyUnlinkableRows  int64    `json:"legacy_unlinkable_rows"`
	IdentityCollisionTies int64    `json:"identity_collision_ties,omitempty"`
	CollisionTiePolicy    string   `json:"collision_tie_policy,omitempty"`
	QuarantinedProviders  []string `json:"quarantined_providers,omitempty"`
	Compatibility         string   `json:"compatibility,omitempty"`
	LastError             string   `json:"last_error,omitempty"`
	LastErrorAt           string   `json:"last_error_at,omitempty"`
}

var apiKeyFingerprintHealth = struct {
	sync.Mutex
	state apiKeyFingerprintDiagnostics
}{}

type apiKeyPrivacyQuarantineSnapshot struct {
	dbKey     string
	providers map[string]string
}

type apiKeyPrivacyQuarantineStoreState struct {
	snapshot atomic.Pointer[apiKeyPrivacyQuarantineSnapshot]
}

func privacySafeAPIKey(dbPath, raw string) string {
	fingerprint, err := privacySafeAPIKeyWithError(dbPath, raw)
	if err != nil {
		return ""
	}
	return fingerprint
}

func privacySafeAPIKeyWithError(dbPath, raw string) (string, error) {
	raw = normalizeRawAPIKey(raw)
	if raw == "" {
		return "", nil
	}
	if version, _, _, ok := parseAPIKeyFingerprint(raw); ok && version == "v1" {
		return raw, nil
	}
	secret, err := loadOrCreateAPIKeySecret(dbPath)
	if err != nil || len(secret) == 0 {
		if err == nil {
			err = errors.New("API key fingerprint secret is empty")
		}
		recordAPIKeyFingerprintError(dbPath, err)
		return "", fmt.Errorf("API key fingerprint secret unavailable: %w", err)
	}
	recordAPIKeyFingerprintSuccess()
	if version, _, suffix, ok := parseAPIKeyFingerprint(raw); ok && version == "v0" {
		return fingerprintLegacyV0WithSecret(secret, raw, suffix), nil
	}
	return fingerprintRawAPIKeyWithSecret(secret, raw), nil
}

func canonicalAPIKeyDatabasePath(dbPath string) string {
	dbPath = strings.TrimSpace(dbPath)
	if dbPath == "" || dbPath == "." {
		dbPath = filepath.Join(pluginDataDirBestEffort(), "usage.db")
	}
	if absolute, err := filepath.Abs(dbPath); err == nil {
		dbPath = absolute
	}
	dbPath = filepath.Clean(dbPath)
	if resolved, err := filepath.EvalSymlinks(dbPath); err == nil {
		dbPath = filepath.Clean(resolved)
	}
	if runtime.GOOS == "windows" {
		dbPath = strings.ToLower(dbPath)
	}
	return dbPath
}

func isStandardAPIKeyDatabaseRequest(dbPath string) bool {
	dbPath = strings.TrimSpace(dbPath)
	if dbPath == "" || dbPath == "." {
		return true
	}
	base := filepath.Base(filepath.Clean(dbPath))
	if runtime.GOOS == "windows" {
		return strings.EqualFold(base, "usage.db")
	}
	return base == "usage.db"
}

func legacyAPIKeyFingerprintDir(dbPath string) string {
	dir := filepath.Dir(strings.TrimSpace(dbPath))
	if dir == "." || dir == "" {
		return pluginDataDirBestEffort()
	}
	if absolute, err := filepath.Abs(dir); err == nil {
		dir = absolute
	}
	return filepath.Clean(dir)
}

func apiKeySecretPath(dbPath string) string {
	// Decide compatibility from the caller's path before resolving symlinks. A
	// relative usage.db and a usage.db symlink must keep using the legacy
	// directory sidecar instead of being reclassified by their resolved target.
	if isStandardAPIKeyDatabaseRequest(dbPath) {
		return filepath.Join(legacyAPIKeyFingerprintDir(dbPath), apiKeyFingerprintSecretFile)
	}
	canonical := canonicalAPIKeyDatabasePath(dbPath)
	dir := filepath.Dir(canonical)
	digest := sha256.Sum256([]byte(canonical))
	return filepath.Join(dir, apiKeyFingerprintSecretFile+"-"+hex.EncodeToString(digest[:8]))
}

func fingerprintRawAPIKeyWithSecret(secret []byte, raw string) string {
	raw = normalizeRawAPIKey(raw)
	if raw == "" {
		return ""
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(raw))
	return "keyfp:v1:" + hex.EncodeToString(mac.Sum(nil)[:16]) + ":" + safeKeyLast4(raw)
}

func legacyV0Fingerprint(raw string) string {
	raw = normalizeRawAPIKey(raw)
	if raw == "" {
		return ""
	}
	digest := sha256.Sum256([]byte(raw))
	return "keyfp:v0:" + hex.EncodeToString(digest[:16]) + ":" + safeKeyLast4(raw)
}

func fingerprintLegacyV0WithSecret(secret []byte, legacy, suffix string) string {
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte("legacy-v0:" + strings.ToLower(strings.TrimSpace(legacy))))
	return "keyfp:v1:" + hex.EncodeToString(mac.Sum(nil)[:16]) + ":" + suffix
}

func configuredAPIKeyStorageValue(raw string) string {
	return privacySafeAPIKey(filepath.Join(pluginDataDirBestEffort(), "usage.db"), raw)
}

func (s *store) privacyDatabasePath() string {
	if s != nil {
		s.mu.Lock()
		path := strings.TrimSpace(s.dbPath)
		s.mu.Unlock()
		if path != "" {
			return path
		}
	}
	return filepath.Join(pluginDataDirBestEffort(), "usage.db")
}

func normalizeRawAPIKey(value string) string {
	value = strings.TrimSpace(value)
	if len(value) >= len("bearer ") && strings.EqualFold(value[:len("bearer ")], "bearer ") {
		value = strings.TrimSpace(value[len("bearer "):])
	}
	return value
}

func isAPIKeyFingerprint(value string) bool {
	_, _, _, ok := parseAPIKeyFingerprint(value)
	return ok
}

func parseAPIKeyFingerprint(value string) (version, digest, suffix string, ok bool) {
	parts := strings.Split(strings.TrimSpace(value), ":")
	if len(parts) != 4 || !strings.EqualFold(parts[0], "keyfp") || (parts[1] != "v0" && parts[1] != "v1") || len(parts[2]) != 32 || !validAPIKeyFingerprintSuffix(parts[3]) {
		return "", "", "", false
	}
	if _, err := hex.DecodeString(parts[2]); err != nil {
		return "", "", "", false
	}
	return parts[1], strings.ToLower(parts[2]), parts[3], true
}

func validAPIKeyFingerprintSuffix(value string) bool {
	if len(value) != 4 {
		return false
	}
	for _, r := range value {
		// The suffix is a display hint, not part of the fingerprint's security
		// boundary. Accept legacy printable ASCII so export masking errs on the safe
		// side even when an older producer retained punctuation.
		if r < 0x21 || r > 0x7e || r == ':' {
			return false
		}
	}
	return true
}

func safeKeyLast4(value string) string {
	value = normalizeRawAPIKey(value)
	if len(value) < 4 {
		return "----"
	}
	last := value[len(value)-4:]
	for _, r := range last {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')) {
			return "----"
		}
	}
	return last
}

func loadOrCreateAPIKeySecret(dbPath string) ([]byte, error) {
	key := apiKeySecretCacheKey(dbPath)
	apiKeySecrets.Lock()
	if secret := apiKeySecrets.byDB[key]; len(secret) > 0 {
		out := append([]byte(nil), secret...)
		apiKeySecrets.Unlock()
		return out, nil
	}
	apiKeySecrets.Unlock()

	path := apiKeySecretPath(dbPath)
	dir := filepath.Dir(path)
	if err := ensurePrivateDir(dir); err != nil {
		return nil, err
	}
	apiKeySecrets.Lock()
	defer apiKeySecrets.Unlock()
	if secret := apiKeySecrets.byDB[key]; len(secret) > 0 {
		return append([]byte(nil), secret...), nil
	}

	if secret, err := readAPIKeySecret(path); err == nil {
		apiKeySecrets.byDB[key] = append([]byte(nil), secret...)
		return append([]byte(nil), secret...), nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	secret := make([]byte, 32)
	if _, err := io.ReadFull(cryptorand.Reader, secret); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			// Another process may have won O_EXCL but not completed its write yet.
			// Retry briefly rather than falling back to a different fingerprint.
			var readErr error
			for attempt := 0; attempt < 20; attempt++ {
				secret, readErr = readAPIKeySecret(path)
				if readErr == nil {
					apiKeySecrets.byDB[key] = append([]byte(nil), secret...)
					return append([]byte(nil), secret...), nil
				}
				time.Sleep(5 * time.Millisecond)
			}
			return nil, readErr
		}
		return nil, err
	}
	encoded := make([]byte, hex.EncodedLen(len(secret)))
	hex.Encode(encoded, secret)
	if _, err := file.Write(encoded); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return nil, err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return nil, err
	}
	if err := file.Close(); err != nil {
		return nil, err
	}
	apiKeySecrets.byDB[key] = append([]byte(nil), secret...)
	return append([]byte(nil), secret...), nil
}

func loadExistingAPIKeySecret(dbPath string) ([]byte, error) {
	key := apiKeySecretCacheKey(dbPath)
	apiKeySecrets.Lock()
	if secret := apiKeySecrets.byDB[key]; len(secret) > 0 {
		out := append([]byte(nil), secret...)
		apiKeySecrets.Unlock()
		return out, nil
	}
	apiKeySecrets.Unlock()
	secret, err := readAPIKeySecret(apiKeySecretPath(dbPath))
	if err != nil {
		return nil, err
	}
	apiKeySecrets.Lock()
	apiKeySecrets.byDB[key] = append([]byte(nil), secret...)
	apiKeySecrets.Unlock()
	return append([]byte(nil), secret...), nil
}

func apiKeySecretCacheKey(dbPath string) string {
	path := apiKeySecretPath(dbPath)
	if absolute, err := filepath.Abs(path); err == nil {
		path = absolute
	}
	path = filepath.Clean(path)
	if runtime.GOOS == "windows" {
		path = strings.ToLower(path)
	}
	return path
}

func apiKeySecretIdentifier(secret []byte) string {
	digest := sha256.Sum256(secret)
	return hex.EncodeToString(digest[:16])
}

type apiKeySecretStateStore interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

type persistentIdentitySpec struct {
	table   string
	columns []string
}

func persistentIdentitySpecs() []persistentIdentitySpec {
	return []persistentIdentitySpec{
		{table: "usage_events", columns: []string{"api_key", "auth_id", "auth_index", "source"}},
		{table: "invalid_auths", columns: []string{"auth_id", "auth_index", "source", "auth_file"}},
		{table: "autoban_bans", columns: []string{"auth_id", "auth_index", "source"}},
		{table: "xai_account_states", columns: []string{"state_key", "auth_id", "auth_index", "source", "auth_file"}},
		{table: "account_protection_reservations", columns: []string{"auth_id", "auth_index", "source"}},
		{table: "quota_trigger_runs", columns: []string{"auth_id", "auth_index", "source", "auth_file"}},
	}
}

func validPersistentIdentitySpec(spec persistentIdentitySpec) bool {
	for _, allowed := range persistentIdentitySpecs() {
		if allowed.table != spec.table || len(allowed.columns) != len(spec.columns) {
			continue
		}
		match := true
		for i := range allowed.columns {
			if allowed.columns[i] != spec.columns[i] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

type storedIdentityRow struct {
	rowID  int64
	values []string
}

func scanPersistentIdentityRows(ctx context.Context, store apiKeySecretStateStore, spec persistentIdentitySpec, visit func(storedIdentityRow) error) error {
	if !validPersistentIdentitySpec(spec) {
		return fmt.Errorf("unsupported identity migration table %q", spec.table)
	}
	var lastRowID int64
	for {
		rows, err := store.QueryContext(ctx, `SELECT rowid, `+strings.Join(spec.columns, ", ")+` FROM `+spec.table+` WHERE rowid>? ORDER BY rowid LIMIT ?`, lastRowID, identityMigrationBatchSize)
		if err != nil {
			return err
		}
		batch := make([]storedIdentityRow, 0, identityMigrationBatchSize)
		for rows.Next() {
			row := storedIdentityRow{values: make([]string, len(spec.columns))}
			dest := make([]any, 0, len(spec.columns)+1)
			dest = append(dest, &row.rowID)
			for i := range row.values {
				dest = append(dest, &row.values[i])
			}
			if err := rows.Scan(dest...); err != nil {
				_ = rows.Close()
				return err
			}
			batch = append(batch, row)
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return err
		}
		if err := rows.Close(); err != nil {
			return err
		}
		if len(batch) == 0 {
			return nil
		}
		for _, row := range batch {
			lastRowID = row.rowID
			if err := visit(row); err != nil {
				return err
			}
		}
	}
}

const apiKeyFingerprintEncodedLength = len("keyfp:v0:") + 32 + 1 + 4

func storedIdentityFingerprints(value string) []string {
	lower := strings.ToLower(value)
	seen := map[string]bool{}
	var out []string
	for offset := 0; offset < len(value); {
		relative := strings.Index(lower[offset:], "keyfp:v")
		if relative < 0 {
			break
		}
		start := offset + relative
		end := start + apiKeyFingerprintEncodedLength
		if end <= len(value) {
			if version, digest, suffix, ok := parseAPIKeyFingerprint(value[start:end]); ok {
				fingerprint := strings.ToLower("keyfp:" + version + ":" + digest + ":" + suffix)
				if !seen[fingerprint] {
					seen[fingerprint] = true
					out = append(out, fingerprint)
				}
				offset = end
				continue
			}
		}
		offset = start + len("keyfp:v")
	}
	return out
}

func collectStoredFingerprints(ctx context.Context, store apiKeySecretStateStore, version string) (map[string]struct{}, int64, error) {
	fingerprints := map[string]struct{}{}
	var rowsWithFingerprint int64
	for _, spec := range persistentIdentitySpecs() {
		err := scanPersistentIdentityRows(ctx, store, spec, func(row storedIdentityRow) error {
			foundInRow := false
			for _, value := range row.values {
				for _, fingerprint := range storedIdentityFingerprints(value) {
					parsedVersion, _, _, ok := parseAPIKeyFingerprint(fingerprint)
					if !ok || parsedVersion != version {
						continue
					}
					fingerprints[fingerprint] = struct{}{}
					foundInRow = true
				}
			}
			if foundInRow {
				rowsWithFingerprint++
			}
			return nil
		})
		if err != nil {
			return nil, 0, err
		}
	}
	return fingerprints, rowsWithFingerprint, nil
}

func configuredV1FingerprintSet(secret []byte, configuredKeys []string) map[string]struct{} {
	out := make(map[string]struct{}, len(configuredKeys))
	for _, raw := range configuredKeys {
		if fingerprint := fingerprintRawAPIKeyWithSecret(secret, raw); fingerprint != "" {
			out[strings.ToLower(fingerprint)] = struct{}{}
		}
	}
	return out
}

func setsOverlap(left, right map[string]struct{}) bool {
	for value := range left {
		if _, ok := right[value]; ok {
			return true
		}
	}
	return false
}

func storedIdentityHasUsableAlias(value, version string, proven map[string]struct{}, configuredKeys []string) (hasTarget, usable bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return false, false
	}
	fingerprints := storedIdentityFingerprints(value)
	for _, fingerprint := range fingerprints {
		fingerprintVersion, _, _, ok := parseAPIKeyFingerprint(fingerprint)
		if !ok || fingerprintVersion != version {
			continue
		}
		hasTarget = true
		if _, ok := proven[fingerprint]; ok {
			usable = true
		}
	}
	if len(fingerprints) > 0 {
		return hasTarget, usable
	}
	credential, _ := credentialFromStoredIdentity(value, configuredKeys)
	return hasTarget, credential == ""
}

func activeRestrictionDependsOnlyOnUnprovenFingerprint(ctx context.Context, store apiKeySecretStateStore, version string, proven map[string]struct{}, configuredKeys []string) (string, error) {
	now := time.Now().Unix()
	queries := []struct {
		name  string
		query string
	}{
		{name: "invalid_auths", query: `SELECT auth_id,auth_index,source,auth_file FROM invalid_auths WHERE active=1`},
		{name: "autoban_bans", query: `SELECT auth_id,auth_index,source FROM autoban_bans WHERE active=1 AND reset_at>?`},
		{name: "xai_account_states", query: `SELECT state_key,auth_id,auth_index,source,auth_file FROM xai_account_states WHERE active=1 AND (reset_at=0 OR reset_at>?)`},
	}
	for _, check := range queries {
		args := []any{}
		if check.name != "invalid_auths" {
			args = append(args, now)
		}
		rows, err := store.QueryContext(ctx, check.query, args...)
		if err != nil {
			return "", err
		}
		columnCount := 4
		if check.name == "autoban_bans" {
			columnCount = 3
		} else if check.name == "xai_account_states" {
			columnCount = 5
		}
		for rows.Next() {
			values := make([]string, columnCount)
			dest := make([]any, columnCount)
			for i := range values {
				dest[i] = &values[i]
			}
			if err := rows.Scan(dest...); err != nil {
				_ = rows.Close()
				return "", err
			}
			hasTarget := false
			usable := false
			for _, value := range values {
				target, valueUsable := storedIdentityHasUsableAlias(value, version, proven, configuredKeys)
				hasTarget = hasTarget || target
				usable = usable || valueUsable
			}
			if hasTarget && !usable {
				_ = rows.Close()
				return check.name, nil
			}
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return "", err
		}
		if err := rows.Close(); err != nil {
			return "", err
		}
	}
	return "", nil
}

func unprovenActiveV0Quarantines(ctx context.Context, store apiKeySecretStateStore, proven map[string]struct{}, configuredKeys []string) (map[string]map[string]struct{}, error) {
	now := time.Now().Unix()
	queries := []struct {
		table       string
		query       string
		columnCount int
		args        []any
	}{
		{table: "invalid_auths", query: `SELECT provider,auth_id,auth_index,source,auth_file FROM invalid_auths WHERE active=1`, columnCount: 4},
		{table: "autoban_bans", query: `SELECT provider,auth_id,auth_index,source FROM autoban_bans WHERE active=1 AND reset_at>?`, columnCount: 3, args: []any{now}},
		{table: "xai_account_states", query: `SELECT provider,state_key,auth_id,auth_index,source,auth_file FROM xai_account_states WHERE active=1 AND (reset_at=0 OR reset_at>?)`, columnCount: 5, args: []any{now}},
	}
	out := map[string]map[string]struct{}{}
	for _, check := range queries {
		rows, err := store.QueryContext(ctx, check.query, check.args...)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var provider string
			values := make([]string, check.columnCount)
			dest := make([]any, 0, check.columnCount+1)
			dest = append(dest, &provider)
			for i := range values {
				dest = append(dest, &values[i])
			}
			if err := rows.Scan(dest...); err != nil {
				_ = rows.Close()
				return nil, err
			}
			usable := false
			unknown := map[string]struct{}{}
			for _, value := range values {
				target, valueUsable := storedIdentityHasUsableAlias(value, "v0", proven, configuredKeys)
				usable = usable || valueUsable
				if !target {
					continue
				}
				for _, fingerprint := range storedIdentityFingerprints(value) {
					version, _, _, ok := parseAPIKeyFingerprint(fingerprint)
					if !ok || version != "v0" {
						continue
					}
					if _, known := proven[fingerprint]; !known {
						unknown[fingerprint] = struct{}{}
					}
				}
			}
			if usable || len(unknown) == 0 {
				continue
			}
			provider = normalizedPrivacyQuarantineProvider(provider, check.table)
			if out[provider] == nil {
				out[provider] = map[string]struct{}{}
			}
			for fingerprint := range unknown {
				out[provider][fingerprint] = struct{}{}
			}
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return nil, err
		}
		if err := rows.Close(); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func upsertStoreState(ctx context.Context, store apiKeySecretStateStore, key, value string) error {
	_, err := store.ExecContext(ctx, `INSERT INTO store_state(key,value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, value)
	return err
}

const apiKeyPrivacyQuarantinePrefix = "api_key_privacy_quarantine_"

func normalizedPrivacyQuarantineProvider(provider, table string) string {
	switch table {
	case "xai_account_states":
		return "xai"
	case "invalid_auths", "autoban_bans":
		return "codex"
	}
	provider = strings.ToLower(strings.TrimSpace(provider))
	if provider != "" {
		return provider
	}
	return "codex"
}

func newAPIKeyPrivacyQuarantineSnapshot(dbPath string, providers map[string]string) *apiKeyPrivacyQuarantineSnapshot {
	copyProviders := make(map[string]string, len(providers))
	for provider, reason := range providers {
		if provider = strings.ToLower(strings.TrimSpace(provider)); provider != "" {
			copyProviders[provider] = reason
		}
	}
	if len(copyProviders) == 0 {
		return nil
	}
	return &apiKeyPrivacyQuarantineSnapshot{
		dbKey:     canonicalAPIKeyDatabasePath(dbPath),
		providers: copyProviders,
	}
}

func (s *store) setAPIKeyPrivacyQuarantineSnapshot(dbPath string, providers map[string]string) {
	if s == nil {
		return
	}
	s.privacyQuarantine.snapshot.Store(newAPIKeyPrivacyQuarantineSnapshot(dbPath, providers))
}

func (s *store) refreshAPIKeyPrivacyQuarantine(ctx context.Context, db *sql.DB, dbPath string) error {
	reasons, _, err := loadAPIKeyPrivacyQuarantine(ctx, db)
	if err != nil {
		return err
	}
	s.setAPIKeyPrivacyQuarantineSnapshot(dbPath, reasons)
	return nil
}

func (s *store) apiKeyPrivacyQuarantineReason(provider string) (string, bool) {
	if s == nil {
		return "", false
	}
	return apiKeyPrivacyQuarantineReasonFromSnapshot(s.privacyQuarantine.snapshot.Load(), provider)
}

func apiKeyPrivacyQuarantineReasonFromSnapshot(snapshot *apiKeyPrivacyQuarantineSnapshot, provider string) (string, bool) {
	if snapshot == nil {
		return "", false
	}
	provider = strings.TrimSpace(provider)
	if provider == "" {
		return "", false
	}
	// Providers are normally already lowercase. Avoid allocating a normalized
	// copy, while retaining case-insensitive compatibility for host payloads.
	if reason, ok := snapshot.providers[provider]; ok {
		return reason, true
	}
	for normalized, reason := range snapshot.providers {
		if strings.EqualFold(provider, normalized) {
			return reason, true
		}
	}
	return "", false
}

func (s *store) schedulerRequestPrivacyQuarantine(req schedulerPickRequest) (string, string, bool) {
	if s == nil {
		return "", "", false
	}
	snapshot := s.privacyQuarantine.snapshot.Load()
	if snapshot == nil {
		return "", "", false
	}
	if reason, quarantined := apiKeyPrivacyQuarantineReasonFromSnapshot(snapshot, req.Provider); quarantined {
		return strings.ToLower(strings.TrimSpace(req.Provider)), reason, true
	}
	for _, provider := range req.Providers {
		if reason, quarantined := apiKeyPrivacyQuarantineReasonFromSnapshot(snapshot, provider); quarantined {
			return strings.ToLower(strings.TrimSpace(provider)), reason, true
		}
	}
	for _, candidate := range req.Candidates {
		if reason, quarantined := apiKeyPrivacyQuarantineReasonFromSnapshot(snapshot, candidate.Provider); quarantined {
			return strings.ToLower(strings.TrimSpace(candidate.Provider)), reason, true
		}
	}
	return "", "", false
}

func loadAPIKeyPrivacyQuarantine(ctx context.Context, db *sql.DB) (map[string]string, map[string][]string, error) {
	rows, err := db.QueryContext(ctx, `SELECT key,value FROM store_state WHERE key GLOB 'api_key_privacy_quarantine_*'`)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	reasons := map[string]string{}
	fingerprints := map[string][]string{}
	for rows.Next() {
		var key, value string
		if err := rows.Scan(&key, &value); err != nil {
			return nil, nil, err
		}
		provider := strings.TrimPrefix(key, apiKeyPrivacyQuarantinePrefix)
		provider = strings.ToLower(strings.TrimSpace(provider))
		if provider == "" {
			continue
		}
		var stored []string
		for _, fingerprint := range strings.Split(value, ",") {
			fingerprint = strings.ToLower(strings.TrimSpace(fingerprint))
			if _, _, _, ok := parseAPIKeyFingerprint(fingerprint); ok {
				stored = append(stored, fingerprint)
			}
		}
		if len(stored) == 0 {
			fingerprints[provider] = nil
			reasons[provider] = "privacy quarantine marker is malformed; repair the marker or explicitly remove it only after verifying legacy restrictions"
			continue
		}
		sort.Strings(stored)
		fingerprints[provider] = stored
		reasons[provider] = "legacy API-key identity requires configured-key recovery or explicit restriction release"
	}
	return reasons, fingerprints, rows.Err()
}

func configuredQuarantineFingerprintMappings(secret []byte, configuredKeys []string) map[string]string {
	out := make(map[string]string, len(configuredKeys))
	for _, raw := range configuredKeys {
		raw = normalizeRawAPIKey(raw)
		if raw == "" || isAPIKeyFingerprint(raw) {
			continue
		}
		legacy := legacyV0Fingerprint(raw)
		_, _, suffix, _ := parseAPIKeyFingerprint(legacy)
		legacyV1 := fingerprintLegacyV0WithSecret(secret, legacy, suffix)
		out[strings.ToLower(legacyV1)] = fingerprintRawAPIKeyWithSecret(secret, raw)
	}
	return out
}

func rewriteStoredFingerprintsWithMap(value string, replacements map[string]string) string {
	if len(replacements) == 0 || !strings.Contains(strings.ToLower(value), "keyfp:v1:") {
		return value
	}
	var out strings.Builder
	lower := strings.ToLower(value)
	offset := 0
	for offset < len(value) {
		relative := strings.Index(lower[offset:], "keyfp:v1:")
		if relative < 0 {
			out.WriteString(value[offset:])
			break
		}
		start := offset + relative
		out.WriteString(value[offset:start])
		end := start + apiKeyFingerprintEncodedLength
		if end > len(value) {
			out.WriteString(value[start:])
			break
		}
		candidate := value[start:end]
		canonical := strings.ToLower(candidate)
		if replacement, ok := replacements[canonical]; ok {
			out.WriteString(replacement)
		} else {
			out.WriteString(candidate)
		}
		offset = end
	}
	return out.String()
}

func rewriteQuarantinedIdentityRows(ctx context.Context, tx *sql.Tx, dbPath string, replacements map[string]string, configuredKeys []string, resolver *legacyFingerprintResolver) error {
	stateTables := map[string]bool{"invalid_auths": true, "autoban_bans": true, "xai_account_states": true}
	for _, spec := range persistentIdentitySpecs() {
		assignments := make([]string, len(spec.columns))
		for i, column := range spec.columns {
			assignments[i] = column + "=?"
		}
		err := scanPersistentIdentityRows(ctx, tx, spec, func(row storedIdentityRow) error {
			protected := make([]string, len(row.values))
			changed := false
			for i, value := range row.values {
				protected[i] = rewriteStoredFingerprintsWithMap(value, replacements)
				changed = changed || protected[i] != value
			}
			if !changed {
				return nil
			}
			if stateTables[spec.table] && protected[0] != row.values[0] {
				var collisionRowID int64
				collisionErr := tx.QueryRowContext(ctx, `SELECT rowid FROM `+spec.table+` WHERE `+spec.columns[0]+`=? AND rowid<>? LIMIT 1`, protected[0], row.rowID).Scan(&collisionRowID)
				if collisionErr == nil {
					return mergeAuthStateCollisionV3(ctx, tx, dbPath, spec, protected, row.rowID, collisionRowID, configuredKeys, resolver)
				}
				if !errors.Is(collisionErr, sql.ErrNoRows) {
					return collisionErr
				}
			}
			args := make([]any, 0, len(protected)+1)
			for _, value := range protected {
				args = append(args, value)
			}
			args = append(args, row.rowID)
			_, err := tx.ExecContext(ctx, `UPDATE `+spec.table+` SET `+strings.Join(assignments, ", ")+` WHERE rowid=?`, args...)
			return err
		})
		if err != nil {
			return err
		}
	}
	_, err := tx.ExecContext(ctx, `DELETE FROM summary_cache`)
	return err
}

func activeQuarantineReferences(ctx context.Context, tx *sql.Tx, provider string, tracked map[string]struct{}) (map[string]struct{}, error) {
	if len(tracked) == 0 {
		return map[string]struct{}{}, nil
	}
	now := time.Now().Unix()
	queries := []struct {
		query       string
		columnCount int
		args        []any
	}{}
	switch provider {
	case "codex":
		queries = append(queries,
			struct {
				query       string
				columnCount int
				args        []any
			}{query: `SELECT auth_id,auth_index,source,auth_file FROM invalid_auths WHERE active=1`, columnCount: 4},
			struct {
				query       string
				columnCount int
				args        []any
			}{query: `SELECT auth_id,auth_index,source FROM autoban_bans WHERE active=1 AND reset_at>?`, columnCount: 3, args: []any{now}},
		)
	case "xai":
		queries = append(queries, struct {
			query       string
			columnCount int
			args        []any
		}{query: `SELECT state_key,auth_id,auth_index,source,auth_file FROM xai_account_states WHERE active=1 AND (reset_at=0 OR reset_at>?)`, columnCount: 5, args: []any{now}})
	default:
		return tracked, nil
	}
	found := map[string]struct{}{}
	for _, check := range queries {
		rows, err := tx.QueryContext(ctx, check.query, check.args...)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			values := make([]string, check.columnCount)
			dest := make([]any, check.columnCount)
			for i := range values {
				dest[i] = &values[i]
			}
			if err := rows.Scan(dest...); err != nil {
				_ = rows.Close()
				return nil, err
			}
			for _, value := range values {
				for _, fingerprint := range storedIdentityFingerprints(value) {
					if _, ok := tracked[fingerprint]; ok {
						found[fingerprint] = struct{}{}
					}
				}
			}
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return nil, err
		}
		if err := rows.Close(); err != nil {
			return nil, err
		}
	}
	return found, nil
}

func reconcileAPIKeyPrivacyQuarantine(ctx context.Context, db *sql.DB, dbPath string, secret []byte) error {
	_, quarantines, err := loadAPIKeyPrivacyQuarantine(ctx, db)
	if err != nil || len(quarantines) == 0 {
		return err
	}
	configuredKeys := configuredRawAPIKeys()
	configuredMappings := configuredQuarantineFingerprintMappings(secret, configuredKeys)
	replacements := map[string]string{}
	for _, stored := range quarantines {
		for _, fingerprint := range stored {
			if replacement, ok := configuredMappings[fingerprint]; ok {
				replacements[fingerprint] = replacement
			}
		}
	}
	resolver, err := newLegacyFingerprintResolver(dbPath, configuredKeys)
	if err != nil {
		return err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if len(replacements) > 0 {
		if err := rewriteQuarantinedIdentityRows(ctx, tx, dbPath, replacements, configuredKeys, resolver); err != nil {
			return err
		}
	}
	for provider, stored := range quarantines {
		if len(stored) == 0 {
			// A present but malformed marker must remain fail-closed. There is no
			// trustworthy fingerprint set from which to infer a safe release.
			continue
		}
		tracked := make(map[string]struct{}, len(stored))
		for _, fingerprint := range stored {
			if _, resolved := replacements[fingerprint]; !resolved {
				tracked[fingerprint] = struct{}{}
			}
		}
		active, err := activeQuarantineReferences(ctx, tx, provider, tracked)
		if err != nil {
			return err
		}
		key := apiKeyPrivacyQuarantinePrefix + provider
		if len(active) == 0 {
			if _, err := tx.ExecContext(ctx, `DELETE FROM store_state WHERE key=?`, key); err != nil {
				return err
			}
			continue
		}
		remaining := make([]string, 0, len(active))
		for fingerprint := range active {
			remaining = append(remaining, fingerprint)
		}
		sort.Strings(remaining)
		if err := upsertStoreState(ctx, tx, key, strings.Join(remaining, ",")); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return nil
}

func bindAPIKeyFingerprintSecret(ctx context.Context, store apiKeySecretStateStore, dbPath string) error {
	var expected string
	err := store.QueryRowContext(ctx, `SELECT value FROM store_state WHERE key='api_key_hmac_id'`).Scan(&expected)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	var secret []byte
	bindingStatus := "verified"
	var unverifiedRows int64
	if strings.TrimSpace(expected) != "" {
		secret, err = loadExistingAPIKeySecret(dbPath)
	} else {
		storedV1, v1Rows, scanErr := collectStoredFingerprints(ctx, store, "v1")
		if scanErr != nil {
			return scanErr
		}
		if len(storedV1) > 0 {
			secret, err = loadExistingAPIKeySecret(dbPath)
			if errors.Is(err, os.ErrNotExist) {
				err = errors.New("API key fingerprint secret is missing while v1 fingerprints already exist")
			}
		} else {
			secret, err = loadOrCreateAPIKeySecret(dbPath)
			bindingStatus = "created"
		}
		if err == nil && len(storedV1) > 0 {
			configuredKeys := configuredRawAPIKeys()
			proven := configuredV1FingerprintSet(secret, configuredKeys)
			blockedTable, checkErr := activeRestrictionDependsOnlyOnUnprovenFingerprint(ctx, store, "v1", proven, configuredKeys)
			if checkErr != nil {
				return checkErr
			}
			if blockedTable != "" {
				err = fmt.Errorf("cannot verify API key fingerprint secret for active v1-only restriction in %s", blockedTable)
			} else if setsOverlap(storedV1, proven) {
				bindingStatus = "verified_legacy"
			} else {
				bindingStatus = "legacy_unverified"
				unverifiedRows = v1Rows
			}
		}
	}
	if err != nil || len(secret) == 0 {
		if err == nil {
			err = errors.New("API key fingerprint secret is empty")
		}
		recordAPIKeyFingerprintError(dbPath, err)
		return fmt.Errorf("API key fingerprint secret unavailable: %w", err)
	}
	identifier := apiKeySecretIdentifier(secret)
	if expected != "" && !hmac.Equal([]byte(strings.TrimSpace(expected)), []byte(identifier)) {
		err := errors.New("API key fingerprint secret does not match the usage database")
		recordAPIKeyFingerprintError(dbPath, err)
		return err
	}
	if expected == "" {
		if err := upsertStoreState(ctx, store, "api_key_hmac_id", identifier); err != nil {
			return err
		}
		if err := upsertStoreState(ctx, store, "api_key_hmac_binding_status", bindingStatus); err != nil {
			return err
		}
		if err := upsertStoreState(ctx, store, "api_key_hmac_unverified_v1_rows", strconv.FormatInt(unverifiedRows, 10)); err != nil {
			return err
		}
	}
	recordAPIKeyFingerprintSuccess()
	return nil
}

func verifyAPIKeyFingerprintSecretBinding(ctx context.Context, db *sql.DB, dbPath string) error {
	var expected string
	if err := db.QueryRowContext(ctx, `SELECT value FROM store_state WHERE key='api_key_hmac_id'`).Scan(&expected); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return errors.New("API key fingerprint secret is not bound to the usage database")
		}
		return err
	}
	secret, err := loadExistingAPIKeySecret(dbPath)
	if err != nil || len(secret) == 0 {
		if err == nil {
			err = errors.New("API key fingerprint secret is empty")
		}
		recordAPIKeyFingerprintError(dbPath, err)
		return fmt.Errorf("API key fingerprint secret unavailable: %w", err)
	}
	if !hmac.Equal([]byte(strings.TrimSpace(expected)), []byte(apiKeySecretIdentifier(secret))) {
		err := errors.New("API key fingerprint secret does not match the usage database")
		recordAPIKeyFingerprintError(dbPath, err)
		return err
	}
	if err := reconcileAPIKeyPrivacyQuarantine(ctx, db, dbPath, secret); err != nil {
		recordAPIKeyFingerprintError(dbPath, err)
		return fmt.Errorf("API key privacy quarantine reconciliation failed: %w", err)
	}
	recordAPIKeyFingerprintSuccess()
	return nil
}

func logAPIKeyFingerprintFallback(dbPath string, err error) {
	if err == nil {
		err = errors.New("API key fingerprint secret is unavailable")
	}
	key := apiKeySecretCacheKey(dbPath)
	apiKeyFallbackWarnings.Lock()
	if _, exists := apiKeyFallbackWarnings.byDB[key]; exists {
		apiKeyFallbackWarnings.Unlock()
		return
	}
	apiKeyFallbackWarnings.byDB[key] = struct{}{}
	apiKeyFallbackWarnings.Unlock()
	log.Printf("%s: API key fingerprint secret unavailable for %s; refusing to persist API key identity: %v", pluginID, apiKeyDatabaseDiagnosticLabel(dbPath), privacySecretDiagnosticError(err))
}

func recordAPIKeyFingerprintError(dbPath string, err error) {
	logAPIKeyFingerprintFallback(dbPath, err)
	apiKeyFingerprintHealth.Lock()
	apiKeyFingerprintHealth.state.Checked = true
	apiKeyFingerprintHealth.state.Available = false
	apiKeyFingerprintHealth.state.LastError = privacySecretDiagnosticError(err)
	apiKeyFingerprintHealth.state.LastErrorAt = time.Now().Format(time.RFC3339)
	apiKeyFingerprintHealth.Unlock()
}

func apiKeyDatabaseDiagnosticLabel(dbPath string) string {
	canonical := canonicalAPIKeyDatabasePath(dbPath)
	digest := sha256.Sum256([]byte(canonical))
	base := filepath.Base(canonical)
	if base == "." || base == "" {
		base = "usage.db"
	}
	return base + "#" + hex.EncodeToString(digest[:4])
}

func privacySecretDiagnosticError(err error) string {
	if err == nil {
		return "API key fingerprint secret is unavailable"
	}
	var pathErr *os.PathError
	if errors.As(err, &pathErr) {
		if errors.Is(pathErr.Err, os.ErrNotExist) {
			return "API key fingerprint secret file is missing"
		}
		return "API key fingerprint secret filesystem operation failed"
	}
	text := sanitizeTriggerError(err)
	if text == "" {
		return "API key fingerprint secret is unavailable"
	}
	return text
}

func recordAPIKeyFingerprintSuccess() {
	apiKeyFingerprintHealth.Lock()
	apiKeyFingerprintHealth.state.Checked = true
	apiKeyFingerprintHealth.state.Available = true
	apiKeyFingerprintHealth.state.LastError = ""
	apiKeyFingerprintHealth.state.LastErrorAt = ""
	apiKeyFingerprintHealth.Unlock()
}

func apiKeyFingerprintStatus(ctx context.Context, db *sql.DB) apiKeyFingerprintDiagnostics {
	apiKeyFingerprintHealth.Lock()
	out := apiKeyFingerprintHealth.state
	apiKeyFingerprintHealth.Unlock()
	if db == nil {
		return out
	}
	var secretID string
	if err := db.QueryRowContext(ctx, `SELECT value FROM store_state WHERE key='api_key_hmac_id'`).Scan(&secretID); err == nil && strings.TrimSpace(secretID) != "" {
		out.SecretBound = true
	}
	_ = db.QueryRowContext(ctx, `SELECT value FROM store_state WHERE key='api_key_hmac_binding_status'`).Scan(&out.BindingStatus)
	var unverifiedRows string
	if err := db.QueryRowContext(ctx, `SELECT value FROM store_state WHERE key='api_key_hmac_unverified_v1_rows'`).Scan(&unverifiedRows); err == nil {
		out.UnverifiedV1Rows, _ = strconv.ParseInt(strings.TrimSpace(unverifiedRows), 10, 64)
	}
	var legacyRows string
	if err := db.QueryRowContext(ctx, `SELECT value FROM store_state WHERE key='api_key_legacy_unlinkable_rows'`).Scan(&legacyRows); err == nil {
		out.LegacyUnlinkableRows, _ = strconv.ParseInt(strings.TrimSpace(legacyRows), 10, 64)
	}
	for _, table := range []string{"invalid_auths", "autoban_bans", "xai_account_states"} {
		var raw string
		if err := db.QueryRowContext(ctx, `SELECT value FROM store_state WHERE key=?`, "api_key_identity_collision_ties_"+table).Scan(&raw); err == nil {
			count, _ := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
			out.IdentityCollisionTies += count
		}
	}
	if out.IdentityCollisionTies > 0 {
		out.CollisionTiePolicy = "equal-time conflicts preserve one complete row; inactive wins active/inactive ties"
	}
	if reasons, _, err := loadAPIKeyPrivacyQuarantine(ctx, db); err == nil {
		for provider := range reasons {
			out.QuarantinedProviders = append(out.QuarantinedProviders, provider)
		}
		sort.Strings(out.QuarantinedProviders)
	}
	compatibility := make([]string, 0, 2)
	if out.LegacyUnlinkableRows > 0 {
		compatibility = append(compatibility, "legacy v0 identities were locally re-keyed and cannot be linked to newly observed credentials")
	}
	if out.BindingStatus == "legacy_unverified" {
		compatibility = append(compatibility, "legacy v1 history was bound without a configured-key proof; no active fingerprint-only restriction depended on it")
	}
	if out.IdentityCollisionTies > 0 {
		compatibility = append(compatibility, out.CollisionTiePolicy)
	}
	if len(out.QuarantinedProviders) > 0 {
		compatibility = append(compatibility, "legacy active identities are fail-closed for the listed providers; restore the configured API key or release the restriction, then restart")
	}
	out.Compatibility = strings.Join(compatibility, "; ")
	return out
}

func readAPIKeySecret(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	decoded := make([]byte, hex.DecodedLen(len(strings.TrimSpace(string(raw)))))
	n, err := hex.Decode(decoded, []byte(strings.TrimSpace(string(raw))))
	if err != nil {
		return nil, err
	}
	decoded = decoded[:n]
	if len(decoded) != 32 {
		return nil, errors.New("invalid API key fingerprint secret")
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(path, 0o600); err != nil {
			return nil, err
		}
	}
	return decoded, nil
}

func sanitizeStoredIdentity(value, rawAPIKey, fingerprint string) string {
	value = strings.TrimSpace(value)
	rawAPIKey = normalizeRawAPIKey(rawAPIKey)
	if value == "" || rawAPIKey == "" || fingerprint == "" {
		return value
	}
	value = strings.ReplaceAll(value, "Bearer "+rawAPIKey, fingerprint)
	value = strings.ReplaceAll(value, "bearer "+rawAPIKey, fingerprint)
	return strings.ReplaceAll(value, rawAPIKey, fingerprint)
}

func privacySafeUsageRecord(dbPath string, rec usageRecord) (usageRecord, error) {
	rawAPIKey := trim(rec.APIKey)
	fingerprint, err := privacySafeAPIKeyWithError(dbPath, rawAPIKey)
	if err != nil {
		return usageRecord{}, err
	}
	rec.APIKey = fingerprint
	if rec.AuthID, err = privacySafeStoredIdentity(dbPath, rec.AuthID, rawAPIKey, fingerprint, nil); err != nil {
		return usageRecord{}, err
	}
	if rec.AuthIndex, err = privacySafeStoredIdentity(dbPath, rec.AuthIndex, rawAPIKey, fingerprint, nil); err != nil {
		return usageRecord{}, err
	}
	if rec.Source, err = privacySafeStoredIdentity(dbPath, rec.Source, rawAPIKey, fingerprint, nil); err != nil {
		return usageRecord{}, err
	}
	return rec, nil
}

func privacySafeQuotaTriggerRun(dbPath string, run quotaTriggerRun) (quotaTriggerRun, error) {
	var err error
	if run.AuthID, err = privacySafeStoredIdentity(dbPath, run.AuthID, "", "", nil); err != nil {
		return quotaTriggerRun{}, err
	}
	if run.AuthIndex, err = privacySafeStoredIdentity(dbPath, run.AuthIndex, "", "", nil); err != nil {
		return quotaTriggerRun{}, err
	}
	if run.Source, err = privacySafeStoredIdentity(dbPath, run.Source, "", "", nil); err != nil {
		return quotaTriggerRun{}, err
	}
	if run.AuthFile, err = privacySafeStoredIdentity(dbPath, run.AuthFile, "", "", nil); err != nil {
		return quotaTriggerRun{}, err
	}
	return run, nil
}

func storedCredentialAlias(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || isAPIKeyFingerprint(value) {
		return value
	}
	bearer := false
	if len(value) > len("bearer") && strings.EqualFold(value[:len("bearer")], "bearer") {
		if rest := strings.TrimSpace(value[len("bearer"):]); rest != "" {
			value = rest
			bearer = true
		}
	}
	lower := strings.ToLower(value)
	if strings.HasPrefix(lower, "codex:apikey:") {
		value = strings.TrimSpace(value[len("codex:apikey:"):])
		lower = strings.ToLower(value)
	}
	credentialLike := bearer || looksLikeOpaqueCredential(value)
	for _, prefix := range []string{"sk-svcacct-", "sk-proj-", "sk-ant-", "xai-", "aiza", "sk-"} {
		if strings.HasPrefix(lower, prefix) {
			credentialLike = true
			break
		}
	}
	if !credentialLike {
		return ""
	}
	return configuredAPIKeyStorageValue(value)
}

func schedulerCandidateExplicitAPIKey(candidate schedulerAuthCandidate) string {
	return firstNonEmptyString(
		candidate.Attributes["api_key"],
		candidate.Attributes["api-key"],
		candidate.Attributes["APIKey"],
		stringFromAny(candidate.Metadata["api_key"]),
		stringFromAny(candidate.Metadata["api-key"]),
		stringFromAny(candidate.Metadata["APIKey"]),
	)
}

func privacySafeSchedulerIdentity(dbPath string, candidate schedulerAuthCandidate, authID, authIndex, source string) (string, string, string, error) {
	rawAPIKey := schedulerCandidateExplicitAPIKey(candidate)
	fingerprint, err := privacySafeAPIKeyWithError(dbPath, rawAPIKey)
	if err != nil {
		return "", "", "", err
	}
	if authID, err = privacySafeStoredIdentity(dbPath, authID, rawAPIKey, fingerprint, nil); err != nil {
		return "", "", "", err
	}
	if authIndex, err = privacySafeStoredIdentity(dbPath, authIndex, rawAPIKey, fingerprint, nil); err != nil {
		return "", "", "", err
	}
	if source, err = privacySafeStoredIdentity(dbPath, source, rawAPIKey, fingerprint, nil); err != nil {
		return "", "", "", err
	}
	return authID, authIndex, source, nil
}

type legacyFingerprintResolver struct {
	dbPath        string
	secret        []byte
	configuredKey []string
	v0ToV1        map[string]string
}

func newLegacyFingerprintResolver(dbPath string, configuredKeys []string) (*legacyFingerprintResolver, error) {
	secret, err := loadExistingAPIKeySecret(dbPath)
	if err != nil {
		return nil, err
	}
	configuredCredentials := normalizedConfiguredCredentials(configuredKeys)
	resolver := &legacyFingerprintResolver{
		dbPath:        dbPath,
		secret:        secret,
		configuredKey: configuredCredentials,
		v0ToV1:        make(map[string]string, len(configuredCredentials)),
	}
	for _, raw := range configuredCredentials {
		resolver.v0ToV1[strings.ToLower(legacyV0Fingerprint(raw))] = fingerprintRawAPIKeyWithSecret(secret, raw)
	}
	return resolver, nil
}

func (r *legacyFingerprintResolver) resolveV0(fingerprint string) (string, bool) {
	if r == nil {
		return "", false
	}
	protected, ok := r.v0ToV1[strings.ToLower(strings.TrimSpace(fingerprint))]
	return protected, ok
}

func (r *legacyFingerprintResolver) protectV0(fingerprint string) (string, error) {
	if protected, ok := r.resolveV0(fingerprint); ok {
		return protected, nil
	}
	_, _, suffix, ok := parseAPIKeyFingerprint(fingerprint)
	if !ok {
		return "", fmt.Errorf("invalid legacy API key fingerprint %q", fingerprint)
	}
	return fingerprintLegacyV0WithSecret(r.secret, fingerprint, suffix), nil
}

func rewriteLegacyV0Fingerprints(value string, resolve func(string) (string, error)) (string, error) {
	if !strings.Contains(strings.ToLower(value), "keyfp:v0:") {
		return value, nil
	}
	var out strings.Builder
	lower := strings.ToLower(value)
	offset := 0
	for offset < len(value) {
		relative := strings.Index(lower[offset:], "keyfp:v0:")
		if relative < 0 {
			out.WriteString(value[offset:])
			break
		}
		start := offset + relative
		out.WriteString(value[offset:start])
		end := start + apiKeyFingerprintEncodedLength
		if end > len(value) {
			out.WriteString(value[start:])
			break
		}
		candidate := value[start:end]
		version, _, _, ok := parseAPIKeyFingerprint(candidate)
		if !ok || version != "v0" {
			out.WriteString(value[start : start+len("keyfp:v0:")])
			offset = start + len("keyfp:v0:")
			continue
		}
		protected, err := resolve(candidate)
		if err != nil {
			return "", err
		}
		out.WriteString(protected)
		offset = end
	}
	return out.String(), nil
}

func normalizedConfiguredCredentials(configuredKeys []string) []string {
	if len(configuredKeys) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(configuredKeys))
	credentials := make([]string, 0, len(configuredKeys))
	for _, configured := range configuredKeys {
		configured = normalizeRawAPIKey(configured)
		if configured == "" || isAPIKeyFingerprint(configured) {
			continue
		}
		if _, exists := seen[configured]; exists {
			continue
		}
		seen[configured] = struct{}{}
		credentials = append(credentials, configured)
	}
	sort.Slice(credentials, func(i, j int) bool {
		if len(credentials[i]) != len(credentials[j]) {
			return len(credentials[i]) > len(credentials[j])
		}
		return credentials[i] < credentials[j]
	})
	return credentials
}

func configuredCredentialWholeValue(value string) string {
	value = strings.TrimSpace(value)
	for _, prefix := range []string{"bearer", "codex:apikey:"} {
		if len(value) > len(prefix) && strings.EqualFold(value[:len(prefix)], prefix) {
			return strings.TrimSpace(value[len(prefix):])
		}
	}
	return value
}

func replaceConfiguredCredentials(dbPath, value string, configuredKeys []string) (string, bool, error) {
	return replaceNormalizedConfiguredCredentials(dbPath, value, normalizedConfiguredCredentials(configuredKeys))
}

func replaceNormalizedConfiguredCredentials(dbPath, value string, credentials []string) (string, bool, error) {
	if len(credentials) == 0 {
		return value, false, nil
	}
	whole := configuredCredentialWholeValue(value)
	for _, credential := range credentials {
		if whole != credential {
			continue
		}
		protected, err := privacySafeAPIKeyWithError(dbPath, credential)
		if err != nil {
			return "", false, err
		}
		return protected, true, nil
	}
	replaced := false
	for _, credential := range credentials {
		if !strings.Contains(value, credential) {
			continue
		}
		protected, err := privacySafeAPIKeyWithError(dbPath, credential)
		if err != nil {
			return "", false, err
		}
		value = strings.ReplaceAll(value, credential, protected)
		replaced = true
	}
	return value, replaced, nil
}

func privacySafeStoredIdentity(dbPath, value, rawAPIKey, fingerprint string, configuredKeys []string) (string, error) {
	value = sanitizeStoredIdentity(value, rawAPIKey, fingerprint)
	var err error
	value, err = rewriteLegacyV0Fingerprints(value, func(legacy string) (string, error) {
		return privacySafeAPIKeyWithError(dbPath, legacy)
	})
	if err != nil {
		return "", err
	}
	value, replaced, err := replaceConfiguredCredentials(dbPath, value, configuredKeys)
	if err != nil {
		return "", err
	}
	if replaced {
		return strings.TrimSpace(value), nil
	}
	credential, replaceWhole := credentialFromStoredIdentity(value, nil)
	if credential == "" {
		return strings.TrimSpace(value), nil
	}
	protected, err := privacySafeAPIKeyWithError(dbPath, credential)
	if err != nil {
		return "", err
	}
	if replaceWhole {
		return protected, nil
	}
	return strings.ReplaceAll(value, credential, protected), nil
}

func privacySafeStoredIdentityForMigration(dbPath, value, rawAPIKey, fingerprint string, configuredKeys []string, resolver *legacyFingerprintResolver) (string, error) {
	value = sanitizeStoredIdentity(value, rawAPIKey, fingerprint)
	var err error
	value, err = rewriteLegacyV0Fingerprints(value, resolver.protectV0)
	if err != nil {
		return "", err
	}
	credentials := configuredKeys
	if resolver != nil {
		credentials = resolver.configuredKey
	} else {
		credentials = normalizedConfiguredCredentials(configuredKeys)
	}
	value, replaced, err := replaceNormalizedConfiguredCredentials(dbPath, value, credentials)
	if err != nil {
		return "", err
	}
	if replaced {
		return strings.TrimSpace(value), nil
	}
	credential, replaceWhole := credentialFromStoredIdentity(value, nil)
	if credential == "" {
		return strings.TrimSpace(value), nil
	}
	protected, err := privacySafeAPIKeyWithError(dbPath, credential)
	if err != nil {
		return "", err
	}
	if replaceWhole {
		return protected, nil
	}
	return strings.ReplaceAll(value, credential, protected), nil
}

func credentialFromStoredIdentity(value string, configuredKeys []string) (string, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", false
	}
	if version, _, _, ok := parseAPIKeyFingerprint(value); ok {
		if version == "v0" {
			return value, true
		}
		return "", false
	}
	if len(value) > len("bearer") && strings.EqualFold(value[:len("bearer")], "bearer") {
		if credential := strings.TrimSpace(value[len("bearer"):]); credential != "" {
			return credential, true
		}
	}
	if len(value) > len("codex:apikey:") && strings.EqualFold(value[:len("codex:apikey:")], "codex:apikey:") {
		if credential := strings.TrimSpace(value[len("codex:apikey:"):]); credential != "" {
			return credential, true
		}
	}
	for _, configured := range configuredKeys {
		configured = normalizeRawAPIKey(configured)
		if configured == "" {
			continue
		}
		if value == configured {
			return configured, true
		}
		if strings.Contains(value, configured) {
			return configured, false
		}
	}
	lower := strings.ToLower(value)
	for _, prefix := range []string{"sk-svcacct-", "sk-proj-", "sk-ant-", "xai-", "aiza", "ark-", "sk-"} {
		if strings.HasPrefix(lower, prefix) {
			return value, true
		}
	}
	if looksLikeOpaqueCredential(value) {
		return value, true
	}
	return "", false
}

func looksLikeOpaqueCredential(value string) bool {
	value = strings.TrimSpace(value)
	if len(value) < 24 || strings.Contains(value, "@") || strings.ContainsAny(value, " \\/") || fileNameIfJSON(value) != "" || looksLikeUUID(value) {
		return false
	}
	useful := 0
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			useful++
		case r == '-', r == '_', r == '.':
		default:
			return false
		}
	}
	return useful >= 20
}

func looksLikeUUID(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return false
	}
	for i, r := range value {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			continue
		}
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return true
}

func configuredRawAPIKeys() []string {
	entries := readConfiguredProviderEntries()
	keys := make([]string, 0, len(entries))
	for _, entry := range entries {
		if key := normalizeRawAPIKey(entry.APIKey); key != "" {
			keys = append(keys, key)
		}
	}
	return keys
}

// migrateStoredIdentitiesV3 is the schema-v3 privacy migration. It uses
// bounded rowid batches and complete identity coverage.
func migrateStoredIdentitiesV3(ctx context.Context, tx *sql.Tx, dbPath string) (int64, error) {
	configuredKeys := configuredRawAPIKeys()
	resolver, err := newLegacyFingerprintResolver(dbPath, configuredKeys)
	if err != nil {
		return 0, err
	}
	knownV0 := make(map[string]struct{}, len(resolver.v0ToV1))
	for fingerprint := range resolver.v0ToV1 {
		knownV0[fingerprint] = struct{}{}
	}
	quarantines, err := unprovenActiveV0Quarantines(ctx, tx, knownV0, configuredKeys)
	if err != nil {
		return 0, err
	}
	legacyRows, err := countLegacyUnlinkableRowsV3(ctx, tx, resolver)
	if err != nil {
		return 0, err
	}
	if err := migrateUsageIdentitiesV3(ctx, tx, dbPath, configuredKeys, resolver); err != nil {
		return 0, err
	}
	if err := migrateAuthStateIdentitiesV3(ctx, tx, dbPath, configuredKeys, resolver); err != nil {
		return 0, err
	}
	for provider, legacy := range quarantines {
		stored := make([]string, 0, len(legacy))
		for fingerprint := range legacy {
			protected, err := resolver.protectV0(fingerprint)
			if err != nil {
				return 0, err
			}
			stored = append(stored, strings.ToLower(protected))
		}
		sort.Strings(stored)
		if err := upsertStoreState(ctx, tx, apiKeyPrivacyQuarantinePrefix+provider, strings.Join(stored, ",")); err != nil {
			return 0, err
		}
	}
	return legacyRows, nil
}

func countLegacyUnlinkableRowsV3(ctx context.Context, tx *sql.Tx, resolver *legacyFingerprintResolver) (int64, error) {
	var count int64
	for _, spec := range persistentIdentitySpecs() {
		err := scanPersistentIdentityRows(ctx, tx, spec, func(row storedIdentityRow) error {
			for _, value := range row.values {
				for _, fingerprint := range storedIdentityFingerprints(value) {
					version, _, _, ok := parseAPIKeyFingerprint(fingerprint)
					if !ok || version != "v0" {
						continue
					}
					if _, known := resolver.resolveV0(fingerprint); !known {
						count++
						return nil
					}
				}
			}
			return nil
		})
		if err != nil {
			return 0, err
		}
	}
	return count, nil
}

func protectStoredAPIKeyV3(dbPath, value string, resolver *legacyFingerprintResolver) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", nil
	}
	if version, _, _, ok := parseAPIKeyFingerprint(value); ok {
		if version == "v1" {
			return value, nil
		}
		return resolver.protectV0(value)
	}
	return privacySafeAPIKeyWithError(dbPath, value)
}

func migrateUsageIdentitiesV3(ctx context.Context, tx *sql.Tx, dbPath string, configuredKeys []string, resolver *legacyFingerprintResolver) error {
	spec := persistentIdentitySpec{table: "usage_events", columns: []string{"api_key", "auth_id", "auth_index", "source"}}
	err := scanPersistentIdentityRows(ctx, tx, spec, func(row storedIdentityRow) error {
		apiKey := strings.TrimSpace(row.values[0])
		protectedAPIKey, err := protectStoredAPIKeyV3(dbPath, apiKey, resolver)
		if err != nil {
			return err
		}
		rawAPIKey := ""
		if _, _, _, fingerprint := parseAPIKeyFingerprint(apiKey); !fingerprint {
			rawAPIKey = apiKey
		}
		protected := make([]string, 3)
		for i, value := range row.values[1:] {
			protected[i], err = privacySafeStoredIdentityForMigration(dbPath, value, rawAPIKey, protectedAPIKey, configuredKeys, resolver)
			if err != nil {
				return err
			}
		}
		if protectedAPIKey == row.values[0] && protected[0] == row.values[1] && protected[1] == row.values[2] && protected[2] == row.values[3] {
			return nil
		}
		_, err = tx.ExecContext(ctx, `UPDATE usage_events SET api_key=?,auth_id=?,auth_index=?,source=? WHERE rowid=?`, protectedAPIKey, protected[0], protected[1], protected[2], row.rowID)
		return err
	})
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `DELETE FROM summary_cache`)
	return err
}

func protectIdentityValuesV3(dbPath string, values, configuredKeys []string, resolver *legacyFingerprintResolver) ([]string, bool, error) {
	protectedValues := make([]string, len(values))
	changed := false
	for i, value := range values {
		protected, err := privacySafeStoredIdentityForMigration(dbPath, value, "", "", configuredKeys, resolver)
		if err != nil {
			return nil, false, err
		}
		protectedValues[i] = protected
		changed = changed || protected != value
	}
	return protectedValues, changed, nil
}

func migrateAuthStateIdentitiesV3(ctx context.Context, tx *sql.Tx, dbPath string, configuredKeys []string, resolver *legacyFingerprintResolver) error {
	for _, spec := range []persistentIdentitySpec{
		{table: "invalid_auths", columns: []string{"auth_id", "auth_index", "source", "auth_file"}},
		{table: "autoban_bans", columns: []string{"auth_id", "auth_index", "source"}},
		{table: "xai_account_states", columns: []string{"state_key", "auth_id", "auth_index", "source", "auth_file"}},
	} {
		if err := migrateAuthStateTableV3(ctx, tx, dbPath, spec, configuredKeys, resolver); err != nil {
			return err
		}
	}
	for _, spec := range []persistentIdentitySpec{
		{table: "account_protection_reservations", columns: []string{"auth_id", "auth_index", "source"}},
		{table: "quota_trigger_runs", columns: []string{"auth_id", "auth_index", "source", "auth_file"}},
	} {
		if err := migrateNonUniqueIdentityTableV3(ctx, tx, dbPath, spec, configuredKeys, resolver); err != nil {
			return err
		}
	}
	return nil
}

func migrateNonUniqueIdentityTableV3(ctx context.Context, tx *sql.Tx, dbPath string, spec persistentIdentitySpec, configuredKeys []string, resolver *legacyFingerprintResolver) error {
	assignments := make([]string, len(spec.columns))
	for i, column := range spec.columns {
		assignments[i] = column + "=?"
	}
	return scanPersistentIdentityRows(ctx, tx, spec, func(row storedIdentityRow) error {
		protectedValues, changed, err := protectIdentityValuesV3(dbPath, row.values, configuredKeys, resolver)
		if err != nil || !changed {
			return err
		}
		args := make([]any, 0, len(protectedValues)+1)
		for _, value := range protectedValues {
			args = append(args, value)
		}
		args = append(args, row.rowID)
		_, err = tx.ExecContext(ctx, `UPDATE `+spec.table+` SET `+strings.Join(assignments, ", ")+` WHERE rowid=?`, args...)
		return err
	})
}

func migrateAuthStateTableV3(ctx context.Context, tx *sql.Tx, dbPath string, spec persistentIdentitySpec, configuredKeys []string, resolver *legacyFingerprintResolver) error {
	assignments := make([]string, len(spec.columns))
	for i, column := range spec.columns {
		assignments[i] = column + "=?"
	}
	return scanPersistentIdentityRows(ctx, tx, spec, func(row storedIdentityRow) error {
		protectedValues, changed, err := protectIdentityValuesV3(dbPath, row.values, configuredKeys, resolver)
		if err != nil || !changed {
			return err
		}
		var collisionRowID int64
		collisionErr := tx.QueryRowContext(ctx, `SELECT rowid FROM `+spec.table+` WHERE `+spec.columns[0]+`=? AND rowid<>? LIMIT 1`, protectedValues[0], row.rowID).Scan(&collisionRowID)
		if collisionErr == nil {
			return mergeAuthStateCollisionV3(ctx, tx, dbPath, spec, protectedValues, row.rowID, collisionRowID, configuredKeys, resolver)
		}
		if !errors.Is(collisionErr, sql.ErrNoRows) {
			return collisionErr
		}
		args := make([]any, 0, len(protectedValues)+1)
		for _, value := range protectedValues {
			args = append(args, value)
		}
		args = append(args, row.rowID)
		_, err = tx.ExecContext(ctx, `UPDATE `+spec.table+` SET `+strings.Join(assignments, ", ")+` WHERE rowid=?`, args...)
		return err
	})
}

type invalidAuthMigrationRow struct {
	AuthID, AuthIndex, Source, Provider, Reason, AuthFile string
	InvalidatedAt, AuthFileMTime                          int64
	Active, LastStatusCode                                int
}

func loadInvalidAuthMigrationRow(ctx context.Context, tx *sql.Tx, rowID int64) (invalidAuthMigrationRow, error) {
	var row invalidAuthMigrationRow
	err := tx.QueryRowContext(ctx, `SELECT auth_id,auth_index,source,provider,reason,invalidated_at,active,last_status_code,auth_file,auth_file_mtime FROM invalid_auths WHERE rowid=?`, rowID).Scan(
		&row.AuthID, &row.AuthIndex, &row.Source, &row.Provider, &row.Reason, &row.InvalidatedAt, &row.Active, &row.LastStatusCode, &row.AuthFile, &row.AuthFileMTime,
	)
	return row, err
}

func sourceWinsInvalidCollision(source, target invalidAuthMigrationRow) (bool, bool) {
	if source.InvalidatedAt != target.InvalidatedAt {
		return source.InvalidatedAt > target.InvalidatedAt, false
	}
	if source.Active != target.Active {
		// Older schemas did not record recovery time. For equal event timestamps,
		// prefer the cleared row so migration never resurrects a known recovery.
		return source.Active == 0, true
	}
	if source.AuthFileMTime != target.AuthFileMTime {
		return source.AuthFileMTime > target.AuthFileMTime, false
	}
	return false, true
}

type autobanMigrationRow struct {
	AuthID, AuthIndex, Source, Provider, Window, Reason, ReleaseReason string
	BannedAt, ResetAt, ReleasedAt                                      int64
	Active, LastStatusCode                                             int
	PrimaryUsedPercent, SecondaryUsedPercent                           sql.NullFloat64
	PrimaryResetAt, SecondaryResetAt                                   sql.NullInt64
}

func loadAutobanMigrationRow(ctx context.Context, tx *sql.Tx, rowID int64) (autobanMigrationRow, error) {
	var row autobanMigrationRow
	err := tx.QueryRowContext(ctx, `SELECT auth_id,auth_index,source,provider,window,reason,banned_at,reset_at,active,last_status_code,primary_used_percent,primary_reset_at,secondary_used_percent,secondary_reset_at,released_at,release_reason FROM autoban_bans WHERE rowid=?`, rowID).Scan(
		&row.AuthID, &row.AuthIndex, &row.Source, &row.Provider, &row.Window, &row.Reason, &row.BannedAt, &row.ResetAt, &row.Active, &row.LastStatusCode,
		&row.PrimaryUsedPercent, &row.PrimaryResetAt, &row.SecondaryUsedPercent, &row.SecondaryResetAt, &row.ReleasedAt, &row.ReleaseReason,
	)
	return row, err
}

func autobanStateEventAt(row autobanMigrationRow) int64 {
	eventAt := row.BannedAt
	if row.Active == 0 && row.ReleasedAt > eventAt {
		eventAt = row.ReleasedAt
	}
	return eventAt
}

func sourceWinsAutobanCollision(source, target autobanMigrationRow) (bool, bool) {
	sourceEvent, targetEvent := autobanStateEventAt(source), autobanStateEventAt(target)
	if sourceEvent != targetEvent {
		return sourceEvent > targetEvent, false
	}
	if source.Active != target.Active {
		return source.Active == 0, true
	}
	if source.Active != 0 && source.ResetAt != target.ResetAt {
		return source.ResetAt > target.ResetAt, false
	}
	if source.BannedAt != target.BannedAt {
		return source.BannedAt > target.BannedAt, false
	}
	return false, true
}

type xaiMigrationRow struct {
	StateKey, AuthID, AuthIndex, Source, Provider, State, Reason, AuthFile string
	ObservedAt, ResetAt, AuthFileMTime                                     int64
	Active, LastStatusCode                                                 int
}

func loadXAIMigrationRow(ctx context.Context, tx *sql.Tx, rowID int64) (xaiMigrationRow, error) {
	var row xaiMigrationRow
	err := tx.QueryRowContext(ctx, `SELECT state_key,auth_id,auth_index,source,provider,state,reason,observed_at,reset_at,active,last_status_code,auth_file,auth_file_mtime FROM xai_account_states WHERE rowid=?`, rowID).Scan(
		&row.StateKey, &row.AuthID, &row.AuthIndex, &row.Source, &row.Provider, &row.State, &row.Reason, &row.ObservedAt, &row.ResetAt, &row.Active, &row.LastStatusCode, &row.AuthFile, &row.AuthFileMTime,
	)
	return row, err
}

func sourceWinsXAICollision(source, target xaiMigrationRow) (bool, bool) {
	if source.ObservedAt != target.ObservedAt {
		return source.ObservedAt > target.ObservedAt, false
	}
	if source.Active != target.Active {
		return source.Active == 0, true
	}
	if source.Active != 0 && source.ResetAt != target.ResetAt {
		if source.ResetAt == 0 {
			return true, false
		}
		if target.ResetAt == 0 {
			return false, false
		}
		return source.ResetAt > target.ResetAt, false
	}
	return false, true
}

func recordMigrationTieDiagnostic(ctx context.Context, tx *sql.Tx, table string) error {
	key := "api_key_identity_collision_ties_" + table
	var raw string
	_ = tx.QueryRowContext(ctx, `SELECT value FROM store_state WHERE key=?`, key).Scan(&raw)
	count, _ := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
	return upsertStoreState(ctx, tx, key, strconv.FormatInt(count+1, 10))
}

func protectInvalidMigrationIdentities(dbPath string, row *invalidAuthMigrationRow, configuredKeys []string, resolver *legacyFingerprintResolver) error {
	values, _, err := protectIdentityValuesV3(dbPath, []string{row.AuthID, row.AuthIndex, row.Source, row.AuthFile}, configuredKeys, resolver)
	if err == nil {
		row.AuthID, row.AuthIndex, row.Source, row.AuthFile = values[0], values[1], values[2], values[3]
	}
	return err
}

func protectAutobanMigrationIdentities(dbPath string, row *autobanMigrationRow, configuredKeys []string, resolver *legacyFingerprintResolver) error {
	values, _, err := protectIdentityValuesV3(dbPath, []string{row.AuthID, row.AuthIndex, row.Source}, configuredKeys, resolver)
	if err == nil {
		row.AuthID, row.AuthIndex, row.Source = values[0], values[1], values[2]
	}
	return err
}

func protectXAIMigrationIdentities(dbPath string, row *xaiMigrationRow, configuredKeys []string, resolver *legacyFingerprintResolver) error {
	values, _, err := protectIdentityValuesV3(dbPath, []string{row.StateKey, row.AuthID, row.AuthIndex, row.Source, row.AuthFile}, configuredKeys, resolver)
	if err == nil {
		row.StateKey, row.AuthID, row.AuthIndex, row.Source, row.AuthFile = values[0], values[1], values[2], values[3], values[4]
	}
	return err
}

func mergeAuthStateCollisionV3(ctx context.Context, tx *sql.Tx, dbPath string, spec persistentIdentitySpec, sourceProtected []string, sourceRowID, targetRowID int64, configuredKeys []string, resolver *legacyFingerprintResolver) error {
	switch spec.table {
	case "invalid_auths":
		source, err := loadInvalidAuthMigrationRow(ctx, tx, sourceRowID)
		if err != nil {
			return err
		}
		target, err := loadInvalidAuthMigrationRow(ctx, tx, targetRowID)
		if err != nil {
			return err
		}
		source.AuthID, source.AuthIndex, source.Source, source.AuthFile = sourceProtected[0], sourceProtected[1], sourceProtected[2], sourceProtected[3]
		if err := protectInvalidMigrationIdentities(dbPath, &target, configuredKeys, resolver); err != nil {
			return err
		}
		sourceWins, tie := sourceWinsInvalidCollision(source, target)
		if tie {
			if err := recordMigrationTieDiagnostic(ctx, tx, spec.table); err != nil {
				return err
			}
		}
		winner := target
		if sourceWins {
			winner = source
		}
		_, err = tx.ExecContext(ctx, `UPDATE invalid_auths SET auth_id=?,auth_index=?,source=?,provider=?,reason=?,invalidated_at=?,active=?,last_status_code=?,auth_file=?,auth_file_mtime=? WHERE rowid=?`,
			winner.AuthID, winner.AuthIndex, winner.Source, winner.Provider, winner.Reason, winner.InvalidatedAt, winner.Active, winner.LastStatusCode, winner.AuthFile, winner.AuthFileMTime, targetRowID)
		if err != nil {
			return err
		}
	case "autoban_bans":
		source, err := loadAutobanMigrationRow(ctx, tx, sourceRowID)
		if err != nil {
			return err
		}
		target, err := loadAutobanMigrationRow(ctx, tx, targetRowID)
		if err != nil {
			return err
		}
		source.AuthID, source.AuthIndex, source.Source = sourceProtected[0], sourceProtected[1], sourceProtected[2]
		if err := protectAutobanMigrationIdentities(dbPath, &target, configuredKeys, resolver); err != nil {
			return err
		}
		sourceWins, tie := sourceWinsAutobanCollision(source, target)
		if tie {
			if err := recordMigrationTieDiagnostic(ctx, tx, spec.table); err != nil {
				return err
			}
		}
		winner := target
		if sourceWins {
			winner = source
		}
		_, err = tx.ExecContext(ctx, `UPDATE autoban_bans SET auth_id=?,auth_index=?,source=?,provider=?,window=?,reason=?,banned_at=?,reset_at=?,active=?,last_status_code=?,primary_used_percent=?,primary_reset_at=?,secondary_used_percent=?,secondary_reset_at=?,released_at=?,release_reason=? WHERE rowid=?`,
			winner.AuthID, winner.AuthIndex, winner.Source, winner.Provider, winner.Window, winner.Reason, winner.BannedAt, winner.ResetAt, winner.Active, winner.LastStatusCode,
			winner.PrimaryUsedPercent, winner.PrimaryResetAt, winner.SecondaryUsedPercent, winner.SecondaryResetAt, winner.ReleasedAt, winner.ReleaseReason, targetRowID)
		if err != nil {
			return err
		}
	case "xai_account_states":
		source, err := loadXAIMigrationRow(ctx, tx, sourceRowID)
		if err != nil {
			return err
		}
		target, err := loadXAIMigrationRow(ctx, tx, targetRowID)
		if err != nil {
			return err
		}
		source.StateKey, source.AuthID, source.AuthIndex, source.Source, source.AuthFile = sourceProtected[0], sourceProtected[1], sourceProtected[2], sourceProtected[3], sourceProtected[4]
		if err := protectXAIMigrationIdentities(dbPath, &target, configuredKeys, resolver); err != nil {
			return err
		}
		sourceWins, tie := sourceWinsXAICollision(source, target)
		if tie {
			if err := recordMigrationTieDiagnostic(ctx, tx, spec.table); err != nil {
				return err
			}
		}
		winner := target
		if sourceWins {
			winner = source
		}
		_, err = tx.ExecContext(ctx, `UPDATE xai_account_states SET state_key=?,auth_id=?,auth_index=?,source=?,provider=?,state=?,reason=?,observed_at=?,reset_at=?,active=?,last_status_code=?,auth_file=?,auth_file_mtime=? WHERE rowid=?`,
			winner.StateKey, winner.AuthID, winner.AuthIndex, winner.Source, winner.Provider, winner.State, winner.Reason, winner.ObservedAt, winner.ResetAt, winner.Active, winner.LastStatusCode, winner.AuthFile, winner.AuthFileMTime, targetRowID)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported auth-state migration table %q", spec.table)
	}
	_, err := tx.ExecContext(ctx, `DELETE FROM `+spec.table+` WHERE rowid=?`, sourceRowID)
	return err
}
