package main

import (
	"context"
	"crypto/hmac"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

const apiKeyFingerprintSecretFile = ".api-key-hmac"

var apiKeySecrets = struct {
	sync.Mutex
	byDir map[string][]byte
}{byDir: map[string][]byte{}}

var apiKeyFallbackWarnings = struct {
	sync.Mutex
	byDir map[string]struct{}
}{byDir: map[string]struct{}{}}

func privacySafeAPIKey(dbPath, raw string) string {
	raw = normalizeRawAPIKey(raw)
	if raw == "" || isAPIKeyFingerprint(raw) {
		return raw
	}
	dir := filepath.Dir(strings.TrimSpace(dbPath))
	if dir == "." || dir == "" {
		dir = pluginDataDirBestEffort()
	}
	secret, err := loadOrCreateAPIKeySecret(dir)
	version := "v1"
	var digest []byte
	if err == nil && len(secret) > 0 {
		mac := hmac.New(sha256.New, secret)
		_, _ = mac.Write([]byte(raw))
		digest = mac.Sum(nil)
	} else {
		logAPIKeyFingerprintFallback(dir, err)
		fallback := sha256.Sum256([]byte(raw))
		digest = fallback[:]
		version = "v0"
	}
	return "keyfp:" + version + ":" + hex.EncodeToString(digest[:16]) + ":" + safeKeyLast4(raw)
}

func configuredAPIKeyStorageValue(raw string) string {
	return privacySafeAPIKey(filepath.Join(pluginDataDirBestEffort(), "usage.db"), raw)
}

func normalizeRawAPIKey(value string) string {
	value = strings.TrimSpace(value)
	if len(value) >= len("bearer ") && strings.EqualFold(value[:len("bearer ")], "bearer ") {
		value = strings.TrimSpace(value[len("bearer "):])
	}
	return value
}

func isAPIKeyFingerprint(value string) bool {
	parts := strings.Split(strings.TrimSpace(value), ":")
	if len(parts) != 4 || !strings.EqualFold(parts[0], "keyfp") || (parts[1] != "v0" && parts[1] != "v1") || len(parts[2]) != 32 || len(parts[3]) != 4 {
		return false
	}
	if _, err := hex.DecodeString(parts[2]); err != nil {
		return false
	}
	return safeKeyLast4(parts[3]) == parts[3]
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

func loadOrCreateAPIKeySecret(dir string) ([]byte, error) {
	key := filepath.Clean(dir)
	if runtime.GOOS == "windows" {
		key = strings.ToLower(key)
	}
	apiKeySecrets.Lock()
	if secret := apiKeySecrets.byDir[key]; len(secret) > 0 {
		out := append([]byte(nil), secret...)
		apiKeySecrets.Unlock()
		return out, nil
	}
	apiKeySecrets.Unlock()

	if err := ensurePrivateDir(dir); err != nil {
		return nil, err
	}
	apiKeySecrets.Lock()
	defer apiKeySecrets.Unlock()
	if secret := apiKeySecrets.byDir[key]; len(secret) > 0 {
		return append([]byte(nil), secret...), nil
	}

	path := filepath.Join(dir, apiKeyFingerprintSecretFile)
	if secret, err := readAPIKeySecret(path); err == nil {
		apiKeySecrets.byDir[key] = append([]byte(nil), secret...)
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
					apiKeySecrets.byDir[key] = append([]byte(nil), secret...)
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
	apiKeySecrets.byDir[key] = append([]byte(nil), secret...)
	return append([]byte(nil), secret...), nil
}

func logAPIKeyFingerprintFallback(dir string, err error) {
	if err == nil {
		err = errors.New("API key fingerprint secret is unavailable")
	}
	key := filepath.Clean(dir)
	if runtime.GOOS == "windows" {
		key = strings.ToLower(key)
	}
	apiKeyFallbackWarnings.Lock()
	if _, exists := apiKeyFallbackWarnings.byDir[key]; exists {
		apiKeyFallbackWarnings.Unlock()
		return
	}
	apiKeyFallbackWarnings.byDir[key] = struct{}{}
	apiKeyFallbackWarnings.Unlock()
	log.Printf("%s: API key fingerprint secret unavailable for %q; using unkeyed v0 fingerprints: %v", pluginID, dir, err)
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

func migrateStoredAPIKeys(ctx context.Context, tx *sql.Tx, dbPath string) error {
	rows, err := tx.QueryContext(ctx, `SELECT DISTINCT api_key FROM usage_events WHERE api_key<>''`)
	if err != nil {
		return err
	}
	var keys []string
	for rows.Next() {
		var key string
		if err := rows.Scan(&key); err != nil {
			_ = rows.Close()
			return err
		}
		if key = strings.TrimSpace(key); key != "" && !isAPIKeyFingerprint(key) {
			keys = append(keys, key)
		}
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, raw := range keys {
		fingerprint := privacySafeAPIKey(dbPath, raw)
		if fingerprint == "" {
			continue
		}
		if _, err := tx.ExecContext(ctx, `
UPDATE usage_events
SET api_key=?,
    auth_id=replace(auth_id, ?, ?),
    auth_index=replace(auth_index, ?, ?),
    source=replace(replace(source, 'Bearer ' || ?, ?), ?, ?)
WHERE api_key=?`,
			fingerprint,
			raw, fingerprint,
			raw, fingerprint,
			raw, fingerprint, raw, fingerprint,
			raw,
		); err != nil {
			return err
		}
	}
	_, err = tx.ExecContext(ctx, `DELETE FROM summary_cache`)
	return err
}
