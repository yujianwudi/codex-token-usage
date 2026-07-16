package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
)

var diagnosticPathLabelKey = func() []byte {
	key := make([]byte, sha256.Size)
	if _, err := cryptorand.Read(key); err == nil {
		return key
	}
	return nil
}()

type databaseDiagnostics struct {
	Path                 string                      `json:"path"`
	SizeBytes            int64                       `json:"size_bytes"`
	UsageEvents          int64                       `json:"usage_events"`
	QuotaTriggerRuns     int64                       `json:"quota_trigger_runs"`
	AutobanRows          int64                       `json:"autoban_rows"`
	InvalidAuthRows      int64                       `json:"invalid_auth_rows"`
	StateProviderRows    map[string]map[string]int64 `json:"state_provider_rows,omitempty"`
	UnsupportedProviders map[string]int64            `json:"unsupported_provider_rows,omitempty"`
	LatestEventAt        string                      `json:"latest_event_at,omitempty"`
	LatestEventAgeSecs   int64                       `json:"latest_event_age_seconds,omitempty"`
	LatestTriggerAt      string                      `json:"latest_trigger_at,omitempty"`
	LatestTriggerAgeSecs int64                       `json:"latest_trigger_age_seconds,omitempty"`
}

type authDiagnostics struct {
	Files                 int `json:"files"`
	Codex                 int `json:"codex"`
	Anthropic             int `json:"anthropic"`
	Antigravity           int `json:"antigravity"`
	Gemini                int `json:"gemini"`
	XAI                   int `json:"xai"`
	Disabled              int `json:"disabled"`
	Expired               int `json:"expired"`
	Invalid401            int `json:"invalid_401"`
	Autoban429            int `json:"autoban_429"`
	ExternalUseSuspected  int `json:"external_use_suspected"`
	QuotaTriggerAvailable int `json:"quota_trigger_available"`
}

type schedulerDiagnostics struct {
	ActiveBanCount                   int    `json:"active_ban_count"`
	FilteredCandidates               int    `json:"filtered_candidates"`
	UnmatchedActiveBans              int    `json:"unmatched_active_bans"`
	LastFilteredAt                   string `json:"last_filtered_at,omitempty"`
	ActiveReservations               int64  `json:"active_reservations"`
	OldestReservationAgeSeconds      int64  `json:"oldest_reservation_age_seconds,omitempty"`
	ExpiredReservationsCleaned       int64  `json:"expired_reservations_cleaned"`
	LegacyUncorrelatedReleaseMatched int64  `json:"legacy_uncorrelated_release_matched"`
	LegacyUncorrelatedReleaseMissed  int64  `json:"legacy_uncorrelated_release_unmatched"`
	ReservationDBBusyCount           int64  `json:"reservation_db_busy_count"`
	ReservationLockWaitMicroseconds  int64  `json:"reservation_lock_wait_microseconds"`
	ReservationInsertMicroseconds    int64  `json:"reservation_insert_microseconds"`
}

type schedulerDiagnosticsTracker struct {
	mu    sync.Mutex
	state schedulerDiagnostics
}

func (t *schedulerDiagnosticsTracker) record(activeBans int, filteredCandidates int, unmatchedActiveBans int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.state.ActiveBanCount = activeBans
	t.state.FilteredCandidates = filteredCandidates
	t.state.UnmatchedActiveBans = unmatchedActiveBans
	if filteredCandidates > 0 {
		t.state.LastFilteredAt = time.Now().Format(time.RFC3339)
	}
}

func (t *schedulerDiagnosticsTracker) status(activeBans int) schedulerDiagnostics {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := t.state
	out.ActiveBanCount = activeBans
	if activeBans == 0 {
		out.UnmatchedActiveBans = 0
	}
	return out
}

func (t *schedulerDiagnosticsTracker) recordReservationTiming(lockWait, insertLatency time.Duration, err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.state.ReservationLockWaitMicroseconds = maxInt64(0, lockWait.Microseconds())
	t.state.ReservationInsertMicroseconds = maxInt64(0, insertLatency.Microseconds())
	if isSQLiteBusyError(err) {
		t.state.ReservationDBBusyCount++
	}
}

func (t *schedulerDiagnosticsTracker) recordExpiredReservations(count int64) {
	if count <= 0 {
		return
	}
	t.mu.Lock()
	t.state.ExpiredReservationsCleaned += count
	t.mu.Unlock()
}

func (t *schedulerDiagnosticsTracker) recordLegacyReservationRelease(matched bool) {
	t.mu.Lock()
	if matched {
		t.state.LegacyUncorrelatedReleaseMatched++
	} else {
		t.state.LegacyUncorrelatedReleaseMissed++
	}
	t.mu.Unlock()
}

type providerDiagnostics struct {
	Configured              int      `json:"configured"`
	Observed                int      `json:"observed"`
	Matched                 int      `json:"matched"`
	UnmatchedConfigured     []string `json:"unmatched_configured,omitempty"`
	PossibleDuplicates      []string `json:"possible_duplicates,omitempty"`
	ConfiguredProviderTypes []string `json:"configured_provider_types,omitempty"`
}

type modelPriceDiagnostics struct {
	Enabled        bool   `json:"enabled"`
	URL            string `json:"url"`
	Path           string `json:"path"`
	IntervalHours  int    `json:"interval_hours"`
	TimeoutSeconds int    `json:"timeout_seconds"`
	LastCheckedAt  string `json:"last_checked_at,omitempty"`
	LastUpdatedAt  string `json:"last_updated_at,omitempty"`
	LastError      string `json:"last_error,omitempty"`
	FileSizeBytes  int64  `json:"file_size_bytes"`
	Entries        int    `json:"entries"`
	LoadedPrices   int    `json:"loaded_prices"`
	Exists         bool   `json:"exists"`
	Stale          bool   `json:"stale"`
	AgeSeconds     int64  `json:"age_seconds,omitempty"`
}

type diagnosticsSummary struct {
	Database      databaseDiagnostics          `json:"database"`
	AuthFiles     authDiagnostics              `json:"auth_files"`
	CodexAuth     xaiAuthSourceDiagnostics     `json:"codex_auth"`
	XAIAuth       xaiAuthSourceDiagnostics     `json:"xai_auth"`
	Scheduler     schedulerDiagnostics         `json:"scheduler"`
	Providers     providerDiagnostics          `json:"providers"`
	ModelPrices   modelPriceDiagnostics        `json:"model_prices"`
	APIKeyPrivacy apiKeyFingerprintDiagnostics `json:"api_key_privacy"`
	QuotaTrigger  quotaTriggerState            `json:"quota_trigger"`
	Retention     retentionState               `json:"retention"`
}

type dashboardAlert struct {
	ID        string `json:"id"`
	Severity  string `json:"severity"`
	Type      string `json:"type"`
	Scope     string `json:"scope"`
	Target    string `json:"target"`
	Message   string `json:"message"`
	Detail    string `json:"detail,omitempty"`
	CreatedAt string `json:"created_at,omitempty"`
	Active    bool   `json:"active"`
}

type retentionState struct {
	UsageRetentionDays         int    `json:"usage_retention_days"`
	QuotaTriggerRetentionDays  int    `json:"quota_trigger_retention_days"`
	RequestDetailRetentionDays int    `json:"request_detail_retention_days"`
	CatchUpPending             bool   `json:"catch_up_pending"`
	LastRunAt                  string `json:"last_run_at,omitempty"`
	LastError                  string `json:"last_error,omitempty"`
	LastUsageDeleted           int64  `json:"last_usage_deleted"`
	LastQuotaTriggerDeleted    int64  `json:"last_quota_trigger_deleted"`
	LastSizeBeforeBytes        int64  `json:"last_size_before_bytes"`
	LastSizeAfterBytes         int64  `json:"last_size_after_bytes"`
}

const (
	retentionInitialDelay             = time.Minute
	retentionRegularInterval          = 24 * time.Hour
	retentionCatchUpInterval          = 30 * time.Second
	retentionErrorRetryInterval       = 5 * time.Minute
	retentionBatchPause               = 10 * time.Millisecond
	retentionBatchSize          int64 = 5000
	retentionMaxBatchesPerTable       = 4
	retentionMaxTimePerTable          = time.Second
)

type retentionCleaner struct {
	mu     sync.Mutex
	cfg    pluginConfig
	cancel context.CancelFunc
	wg     sync.WaitGroup
	state  retentionState
}

func (r *retentionCleaner) configure(cfg pluginConfig) {
	r.stop()
	r.mu.Lock()
	r.cfg = cfg
	r.state.UsageRetentionDays = cfg.UsageRetentionDays
	r.state.QuotaTriggerRetentionDays = cfg.QuotaTriggerRetentionDays
	r.state.RequestDetailRetentionDays = cfg.RequestDetailRetentionDays
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	r.wg.Add(1)
	r.mu.Unlock()
	go func() {
		defer r.wg.Done()
		r.loop(ctx, cfg)
	}()
}

func (r *retentionCleaner) stop() {
	r.mu.Lock()
	cancel := r.cancel
	r.cancel = nil
	r.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	r.wg.Wait()
}

func (r *retentionCleaner) status() retentionState {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.state
}

func (r *retentionCleaner) loop(ctx context.Context, cfg pluginConfig) {
	timer := time.NewTimer(retentionInitialDelay)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			more := r.run(ctx, cfg)
			if ctx.Err() != nil {
				return
			}
			next := retentionRegularInterval
			if more {
				next = retentionCatchUpInterval
				if r.status().LastError != "" {
					next = retentionErrorRetryInterval
				}
			}
			timer.Reset(next)
		}
	}
}

func (r *retentionCleaner) run(ctx context.Context, cfg pluginConfig) bool {
	db, path, err := globalStore.open(ctx)
	if err != nil {
		if ctx.Err() == nil {
			r.record(err, 0, 0, 0, 0, true)
			return true
		}
		return false
	}
	before := databaseFileSize(path)
	now := time.Now().Unix()
	usageCutoff := now - int64(cfg.UsageRetentionDays)*86400
	triggerCutoff := now - int64(cfg.QuotaTriggerRetentionDays)*86400
	usageDeleted, usageMore, err := execDeleteBatchesLimited(ctx, db, `
DELETE FROM usage_events
WHERE id IN (
  SELECT id FROM usage_events WHERE requested_at < ? ORDER BY id LIMIT ?
)`, usageCutoff, retentionBatchSize, retentionMaxBatchesPerTable, retentionMaxTimePerTable)
	if err != nil {
		if ctx.Err() == nil {
			r.record(err, usageDeleted, 0, before, databaseFileSize(path), true)
			return true
		}
		return false
	}
	triggerDeleted, triggerMore, err := execDeleteBatchesLimited(ctx, db, `
DELETE FROM quota_trigger_runs
WHERE id IN (
  SELECT id FROM quota_trigger_runs WHERE finished_at < ? ORDER BY id LIMIT ?
)`, triggerCutoff, retentionBatchSize, retentionMaxBatchesPerTable, retentionMaxTimePerTable)
	if err != nil {
		if ctx.Err() == nil {
			r.record(err, usageDeleted, triggerDeleted, before, databaseFileSize(path), true)
			return true
		}
		return false
	}
	more := usageMore || triggerMore
	r.record(nil, usageDeleted, triggerDeleted, before, databaseFileSize(path), more)
	return more
}

func (r *retentionCleaner) record(err error, usageDeleted, triggerDeleted, before, after int64, catchUpPending bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.state.CatchUpPending = catchUpPending
	r.state.LastRunAt = time.Now().Format(time.RFC3339)
	r.state.LastUsageDeleted = usageDeleted
	r.state.LastQuotaTriggerDeleted = triggerDeleted
	r.state.LastSizeBeforeBytes = before
	r.state.LastSizeAfterBytes = after
	if err != nil {
		r.state.LastError = sanitizeTriggerError(err.Error())
	} else {
		r.state.LastError = ""
	}
}

func execDeleteBatches(ctx context.Context, db *sql.DB, query string, cutoff int64, batchSize int64) (int64, error) {
	total, _, err := execDeleteBatchesLimited(ctx, db, query, cutoff, batchSize, 0, 0)
	return total, err
}

func execDeleteBatchesLimited(ctx context.Context, db *sql.DB, query string, cutoff int64, batchSize int64, maxBatches int, maxDuration time.Duration) (int64, bool, error) {
	if batchSize <= 0 {
		batchSize = retentionBatchSize
	}
	started := time.Now()
	var total int64
	for batch := 0; ; batch++ {
		if (maxBatches > 0 && batch >= maxBatches) || (maxDuration > 0 && batch > 0 && time.Since(started) >= maxDuration) {
			return total, true, nil
		}
		res, err := db.ExecContext(ctx, query, cutoff, batchSize)
		if err != nil {
			return total, false, err
		}
		deleted, err := res.RowsAffected()
		if err != nil {
			return total, false, err
		}
		total += deleted
		if deleted < batchSize {
			return total, false, nil
		}
		if (maxBatches > 0 && batch+1 >= maxBatches) || (maxDuration > 0 && time.Since(started) >= maxDuration) {
			return total, true, nil
		}
		timer := time.NewTimer(retentionBatchPause)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return total, false, ctx.Err()
		case <-timer.C:
		}
	}
}

func buildDiagnostics(ctx context.Context, db *sql.DB, dbPath string, accounts []accountRow, providers []providerRow, invalidAuths []invalidAuthRow, autobans []autobanRow, externalAlerts []externalUseAlert) diagnosticsSummary {
	priceState := globalModelPriceUpdater.status()
	scheduler := globalSchedulerDiagnostics.status(len(autobans))
	now := time.Now().Unix()
	var oldest int64
	_ = db.QueryRowContext(ctx, `
SELECT COUNT(*), COALESCE(MIN(created_at),0)
FROM account_protection_reservations
WHERE provider=? AND expires_at>?`, providerCodex, now).Scan(&scheduler.ActiveReservations, &oldest)
	if oldest > 0 {
		scheduler.OldestReservationAgeSeconds = maxInt64(0, now-oldest)
	}
	return diagnosticsSummary{
		Database:      queryDatabaseDiagnostics(ctx, db, dbPath),
		AuthFiles:     buildAuthDiagnostics(accounts, invalidAuths, autobans, externalAlerts),
		CodexAuth:     globalCodexAuthSource.status(),
		XAIAuth:       globalXAIAuthSource.status(),
		Scheduler:     scheduler,
		Providers:     buildProviderDiagnostics(providers),
		ModelPrices:   buildModelPriceDiagnostics(priceState),
		APIKeyPrivacy: apiKeyFingerprintStatus(ctx, db, dbPath),
		QuotaTrigger:  globalQuotaTrigger.status(),
		Retention:     globalRetentionCleaner.status(),
	}
}

func queryDatabaseDiagnostics(ctx context.Context, db *sql.DB, path string) databaseDiagnostics {
	now := time.Now().Unix()
	out := databaseDiagnostics{
		Path:             diagnosticPathLabel(path),
		SizeBytes:        databaseFileSize(path),
		UsageEvents:      queryCount(ctx, db, `SELECT COUNT(*) FROM usage_events`),
		QuotaTriggerRuns: queryCount(ctx, db, `SELECT COUNT(*) FROM quota_trigger_runs`),
		AutobanRows:      queryCount(ctx, db, `SELECT COUNT(*) FROM autoban_bans`),
		InvalidAuthRows:  queryCount(ctx, db, `SELECT COUNT(*) FROM invalid_auths`),
	}
	out.StateProviderRows, out.UnsupportedProviders = queryStateProviderDiagnostics(ctx, db)
	if ts := queryMaxUnix(ctx, db, `SELECT COALESCE(MAX(requested_at),0) FROM usage_events`); ts > 0 {
		out.LatestEventAt = unixTime(ts)
		out.LatestEventAgeSecs = maxInt64(0, now-ts)
	}
	if ts := queryMaxUnix(ctx, db, `SELECT COALESCE(MAX(finished_at),0) FROM quota_trigger_runs`); ts > 0 {
		out.LatestTriggerAt = unixTime(ts)
		out.LatestTriggerAgeSecs = maxInt64(0, now-ts)
	}
	return out
}

func queryStateProviderDiagnostics(ctx context.Context, db *sql.DB) (map[string]map[string]int64, map[string]int64) {
	supported := map[string]map[string]struct{}{
		// Usage analytics intentionally accepts third-party Providers. Keep the
		// distribution visible without classifying those rows as unsupported.
		"usage_events":                    nil,
		"quota_trigger_runs":              {providerCodex: {}},
		"invalid_auths":                   {providerCodex: {}},
		"autoban_bans":                    {providerCodex: {}},
		"xai_account_states":              {providerXAI: {}},
		"account_protection_reservations": {providerCodex: {}},
	}
	counts := make(map[string]map[string]int64, len(supported))
	unsupported := make(map[string]int64)
	for table, supportedProviders := range supported {
		rows, err := db.QueryContext(ctx, `SELECT provider, COUNT(*) FROM `+quoteSQLiteIdentifier(table)+` GROUP BY provider ORDER BY provider`)
		if err != nil {
			continue
		}
		tableCounts := map[string]int64{}
		for rows.Next() {
			var provider string
			var count int64
			if err := rows.Scan(&provider, &count); err != nil {
				continue
			}
			provider = canonicalProvider(provider)
			if provider == "" {
				provider = "invalid"
			}
			tableCounts[provider] += count
			if supportedProviders != nil {
				if _, ok := supportedProviders[provider]; !ok {
					unsupported[table] += count
				}
			}
		}
		_ = rows.Close()
		if len(tableCounts) > 0 {
			counts[table] = tableCounts
		}
	}
	if len(counts) == 0 {
		counts = nil
	}
	if len(unsupported) == 0 {
		unsupported = nil
	}
	return counts, unsupported
}

func databaseFileSize(path string) int64 {
	var size int64
	for _, candidate := range []string{path, path + "-wal", path + "-shm"} {
		if info, err := os.Stat(candidate); err == nil {
			size += info.Size()
		}
	}
	return size
}

func queryCount(ctx context.Context, db *sql.DB, query string) int64 {
	var n int64
	_ = db.QueryRowContext(ctx, query).Scan(&n)
	return n
}

func queryMaxUnix(ctx context.Context, db *sql.DB, query string) int64 {
	var n int64
	_ = db.QueryRowContext(ctx, query).Scan(&n)
	return normalizeUnixSeconds(n)
}

func buildAuthDiagnostics(accounts []accountRow, invalidAuths []invalidAuthRow, autobans []autobanRow, externalAlerts []externalUseAlert) authDiagnostics {
	files := readConfiguredAuthFiles()
	codexStatus := globalCodexAuthSource.status()
	out := authDiagnostics{
		Files:                len(files),
		Codex:                codexStatus.Accounts,
		XAI:                  globalXAIAuthSource.status().Accounts,
		Invalid401:           len(invalidAuths),
		Autoban429:           count429Autobans(autobans),
		ExternalUseSuspected: len(externalAlerts),
	}
	for _, file := range files {
		switch strings.ToLower(strings.TrimSpace(file.Provider)) {
		case "anthropic":
			out.Anthropic++
		case "antigravity":
			out.Antigravity++
		case "gemini":
			out.Gemini++
		}
		if !isCodexAuthProvider(file.Provider) && file.Disabled {
			out.Disabled++
		}
		if !isCodexAuthProvider(file.Provider) && file.Expired {
			out.Expired++
		}
	}
	for _, account := range accounts {
		if account.Configured && isCodexAuthProvider(account.Provider) && account.Disabled {
			out.Disabled++
		}
		if account.Configured && isCodexAuthProvider(account.Provider) && account.Expired {
			out.Expired++
		}
		if isCodexAuthProvider(account.Provider) && !account.Disabled && !account.Expired && !account.InvalidAuth && !account.ExternalUseSuspected {
			out.QuotaTriggerAvailable++
		}
	}
	return out
}

func count429Autobans(autobans []autobanRow) int {
	count := 0
	for _, ban := range autobans {
		window := strings.TrimSpace(ban.Window)
		if strings.EqualFold(window, "401") || strings.EqualFold(window, "402") || strings.EqualFold(window, "403") ||
			ban.LastStatusCode == http.StatusUnauthorized || ban.LastStatusCode == http.StatusPaymentRequired || ban.LastStatusCode == http.StatusForbidden {
			continue
		}
		count++
	}
	return count
}

func buildProviderDiagnostics(providers []providerRow) providerDiagnostics {
	configured := readConfiguredProviderEntries()
	out := providerDiagnostics{Configured: len(configured), Observed: len(providers)}
	observed := map[string]bool{}
	for _, provider := range providers {
		observed[normalizeAccountAlias(providerLabelForBackend(provider.Provider))] = true
	}
	typeSet := map[string]bool{}
	for _, entry := range configured {
		typeSet[entry.Provider] = true
		name := providerLabelForBackend(entry.Name)
		if observed[normalizeAccountAlias(name)] {
			out.Matched++
		} else {
			out.UnmatchedConfigured = append(out.UnmatchedConfigured, entry.Name)
		}
	}
	for typ := range typeSet {
		out.ConfiguredProviderTypes = append(out.ConfiguredProviderTypes, typ)
	}
	sort.Strings(out.ConfiguredProviderTypes)
	out.PossibleDuplicates = possibleProviderDuplicates(providers)
	return out
}

func providerLabelForBackend(name string) string {
	name = strings.TrimSpace(name)
	lower := strings.ToLower(name)
	for _, prefix := range []string{"openai-compatible-", "openai-compatibility-"} {
		if strings.HasPrefix(lower, prefix) && len(name) > len(prefix) {
			return name[len(prefix):]
		}
	}
	if strings.HasPrefix(lower, "openai-compatibility:") {
		parts := strings.Split(name, ":")
		if len(parts) >= 2 && strings.TrimSpace(parts[1]) != "" {
			return strings.TrimSpace(parts[1])
		}
	}
	return name
}

func possibleProviderDuplicates(providers []providerRow) []string {
	groups := map[string][]string{}
	for _, provider := range providers {
		name := providerLabelForBackend(provider.Provider)
		key := normalizeAccountAlias(strings.TrimRight(name, "0123456789 "))
		if key == "" {
			key = normalizeAccountAlias(name)
		}
		groups[key] = append(groups[key], provider.Provider)
	}
	var out []string
	for _, names := range groups {
		if len(names) > 1 {
			sort.Strings(names)
			out = append(out, strings.Join(names, " / "))
		}
	}
	sort.Strings(out)
	return out
}

func buildModelPriceDiagnostics(state modelPriceUpdateState) modelPriceDiagnostics {
	out := modelPriceDiagnostics{
		Enabled:        state.Enabled,
		URL:            modelPriceURLForDiagnostics(state.URL),
		Path:           diagnosticPathLabel(state.Path),
		IntervalHours:  state.IntervalHours,
		TimeoutSeconds: state.TimeoutSeconds,
		LastCheckedAt:  state.LastCheckedAt,
		LastUpdatedAt:  state.LastUpdatedAt,
		LastError:      sanitizeModelPriceDiagnosticText(state.LastError),
		FileSizeBytes:  state.FileSizeBytes,
		Entries:        state.Entries,
		LoadedPrices:   state.LoadedPrices,
	}
	if info, err := os.Stat(state.Path); err == nil {
		out.Exists = true
		out.FileSizeBytes = info.Size()
		out.AgeSeconds = int64(time.Since(info.ModTime()).Seconds())
		maxAge := time.Duration(maxInt(1, state.IntervalHours*2)) * time.Hour
		out.Stale = time.Since(info.ModTime()) > maxAge
		if out.LastUpdatedAt == "" {
			out.LastUpdatedAt = info.ModTime().Format(time.RFC3339)
		}
	} else {
		out.Stale = true
	}
	return out
}

func diagnosticPathLabel(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	if opaqueDiagnosticPathLabel(path) {
		return path
	}
	if len(diagnosticPathLabelKey) == 0 {
		return "path#0000000000000000"
	}
	clean := filepath.Clean(path)
	if absolute, err := filepath.Abs(clean); err == nil {
		clean = absolute
	}
	mac := hmac.New(sha256.New, diagnosticPathLabelKey)
	_, _ = mac.Write([]byte(clean))
	return "path#" + hex.EncodeToString(mac.Sum(nil)[:8])
}

func opaqueDiagnosticPathLabel(value string) bool {
	const prefix = "path#"
	if !strings.HasPrefix(value, prefix) || len(value) != len(prefix)+16 {
		return false
	}
	_, err := hex.DecodeString(value[len(prefix):])
	return err == nil
}

func sanitizeSummaryDiagnosticPaths(data map[string]any) {
	if data == nil {
		return
	}
	if path, ok := data["db_path"].(string); ok {
		data["db_path"] = diagnosticPathLabel(path)
	}
	switch diagnostics := data["diagnostics"].(type) {
	case diagnosticsSummary:
		diagnostics.Database.Path = diagnosticPathLabel(diagnostics.Database.Path)
		diagnostics.ModelPrices.Path = diagnosticPathLabel(diagnostics.ModelPrices.Path)
		data["diagnostics"] = diagnostics
	case map[string]any:
		for _, section := range []string{"database", "model_prices"} {
			values, ok := diagnostics[section].(map[string]any)
			if !ok {
				continue
			}
			if path, ok := values["path"].(string); ok {
				values["path"] = diagnosticPathLabel(path)
			}
		}
	}
}

func buildAlerts(data map[string]any) []dashboardAlert {
	now := time.Now().Format(time.RFC3339)
	var alerts []dashboardAlert
	if rows, ok := data["invalid_auths"].([]invalidAuthRow); ok {
		for _, row := range rows {
			alerts = append(alerts, dashboardAlert{ID: "invalid:" + firstNonEmptyString(row.AuthID, row.AuthIndex, row.Source), Severity: "critical", Type: "401", Scope: "account", Target: firstNonEmptyString(row.Source, row.AuthID, row.AuthIndex), Message: "账号 401 失效，已停止使用", Detail: row.Reason, CreatedAt: row.InvalidatedAtText, Active: row.Active})
		}
	}
	if rows, ok := data["autobans"].([]autobanRow); ok {
		for _, row := range rows {
			window := strings.TrimSpace(row.Window)
			if strings.EqualFold(window, "401") || strings.EqualFold(window, "402") || strings.EqualFold(window, "403") ||
				row.LastStatusCode == http.StatusUnauthorized || row.LastStatusCode == http.StatusPaymentRequired || row.LastStatusCode == http.StatusForbidden {
				continue
			}
			alerts = append(alerts, dashboardAlert{ID: "autoban:" + firstNonEmptyString(row.AuthID, row.AuthIndex, row.Source), Severity: "warning", Type: "429", Scope: "account", Target: firstNonEmptyString(row.Source, row.AuthID, row.AuthIndex), Message: "账号 429 自动禁用中", Detail: "恢复时间 " + row.ResetAtText, CreatedAt: row.BannedAtText, Active: row.Active})
		}
	}
	if rows, ok := data["external_use_alerts"].([]externalUseAlert); ok {
		for _, row := range rows {
			alerts = append(alerts, dashboardAlert{ID: "external:" + firstNonEmptyString(row.AuthID, row.AuthIndex, row.Source) + ":" + row.Window, Severity: "critical", Type: "external_use", Scope: "account", Target: firstNonEmptyString(row.Source, row.AuthID, row.AuthIndex), Message: "疑似外部消耗", Detail: row.Window + " 增加 " + fmt.Sprintf("%.1f%%", row.DeltaPercent) + "，本地仅 " + strconv.FormatInt(row.LocalTokens, 10) + " tok", CreatedAt: row.DetectedAtText, Active: true})
		}
	}
	if providers, ok := data["providers"].([]providerRow); ok {
		for _, row := range providers {
			if row.Requests >= 5 && row.Failed*100/row.Requests >= 20 {
				alerts = append(alerts, dashboardAlert{ID: "provider-error:" + row.Provider, Severity: "warning", Type: "provider_error_rate", Scope: "provider", Target: row.Provider, Message: "Provider 错误率偏高", Detail: fmt.Sprintf("失败 %d / 请求 %d", row.Failed, row.Requests), CreatedAt: now, Active: true})
			}
		}
	}
	if diagnostics, ok := data["diagnostics"].(diagnosticsSummary); ok {
		if !diagnostics.ModelPrices.Exists || diagnostics.ModelPrices.Stale || diagnostics.ModelPrices.LoadedPrices == 0 || diagnostics.ModelPrices.LastError != "" {
			alerts = append(alerts, dashboardAlert{ID: "model-prices", Severity: "warning", Type: "model_prices", Scope: "system", Target: "model_prices.json", Message: "模型价格文件需要检查", Detail: firstNonEmptyString(diagnostics.ModelPrices.LastError, "文件缺失、过期或没有可用价格"), CreatedAt: now, Active: true})
		}
		if diagnostics.Database.UsageEvents > 0 && diagnostics.Database.LatestEventAgeSecs > 6*3600 {
			alerts = append(alerts, dashboardAlert{ID: "stale-usage", Severity: "info", Type: "stale_data", Scope: "system", Target: "usage_events", Message: "长时间没有新的 usage 事件", Detail: "最近事件 " + diagnostics.Database.LatestEventAt, CreatedAt: now, Active: true})
		}
		if len(diagnostics.Providers.UnmatchedConfigured) > 0 {
			alerts = append(alerts, dashboardAlert{ID: "provider-unmatched", Severity: "info", Type: "provider_config", Scope: "provider", Target: "CPA config", Message: "存在已配置但暂无流量的接入点", Detail: strings.Join(diagnostics.Providers.UnmatchedConfigured, " / "), CreatedAt: now, Active: true})
		}
	}
	sort.SliceStable(alerts, func(i, j int) bool {
		return alertSeverityRank(alerts[i].Severity) > alertSeverityRank(alerts[j].Severity)
	})
	return alerts
}

func alertSeverityRank(value string) int {
	switch value {
	case "critical":
		return 4
	case "warning":
		return 3
	case "info":
		return 2
	default:
		return 1
	}
}

type logExportFilter struct {
	Window   string
	Scope    string
	Provider string
	Account  string
	Model    string
	Date     string
	Status   string
	Limit    int
}

type logExportFilters = logExportFilter

func handleExport(ctx context.Context, window, kind, format string, limit int) managementResponse {
	return handleExportWithFilters(ctx, window, kind, format, limit, nil)
}

func handleExportWithFilters(ctx context.Context, window, kind, format string, limit int, query map[string][]string) managementResponse {
	if strings.EqualFold(strings.TrimSpace(kind), "logs") {
		filters := logExportFilter{
			Window:   window,
			Scope:    firstQuery(query, "scope", "codex"),
			Provider: firstQuery(query, "provider", ""),
			Account:  firstQuery(query, "account", ""),
			Model:    firstQuery(query, "model", ""),
			Date:     firstQuery(query, "date", ""),
			Status:   firstQuery(query, "status", "all"),
			Limit:    limit,
		}
		type logExportResult struct {
			records []map[string]string
			headers []string
		}
		result, err := withSQLiteAutoRepair(ctx, globalStore, "log export", func() (logExportResult, error) {
			db, _, err := globalStore.open(ctx)
			if err != nil {
				return logExportResult{}, err
			}
			records, headers, err := exportLogRecords(ctx, db, filters, defaultModelPrices())
			if err != nil {
				return logExportResult{}, err
			}
			return logExportResult{records: records, headers: headers}, nil
		})
		if err != nil {
			return jsonResponse(http.StatusInternalServerError, map[string]any{"error": "export_failed", "message": publicErrorMessage("export_failed")})
		}
		name := exportLogFileName(filters, format)
		if strings.EqualFold(format, "json") {
			body, _ := json.MarshalIndent(result.records, "", "  ")
			return managementResponse{StatusCode: http.StatusOK, Headers: exportHeaders("application/json; charset=utf-8", name), Body: body}
		}
		body, err := recordsToCSV(result.headers, result.records)
		if err != nil {
			return jsonResponse(http.StatusInternalServerError, map[string]any{"error": "export_failed", "message": publicErrorMessage("export_failed")})
		}
		return managementResponse{StatusCode: http.StatusOK, Headers: exportHeaders("text/csv; charset=utf-8", name), Body: body}
	}
	data, err := globalSummaryPrecomputer.summary(ctx, globalStore, window, limit)
	if err != nil {
		return jsonResponse(http.StatusInternalServerError, map[string]any{"error": "summary_failed", "message": publicErrorMessage("summary_failed")})
	}
	records, headers := exportRecords(data, kind)
	if strings.EqualFold(format, "json") {
		body, _ := json.MarshalIndent(records, "", "  ")
		return managementResponse{StatusCode: http.StatusOK, Headers: exportHeaders("application/json; charset=utf-8", kind+".json"), Body: body}
	}
	body, err := recordsToCSV(headers, records)
	if err != nil {
		return jsonResponse(http.StatusInternalServerError, map[string]any{"error": "export_failed", "message": publicErrorMessage("export_failed")})
	}
	return managementResponse{StatusCode: http.StatusOK, Headers: exportHeaders("text/csv; charset=utf-8", kind+".csv"), Body: body}
}

func exportLogFileName(filters logExportFilter, format string) string {
	scope := strings.ToLower(strings.TrimSpace(filters.Scope))
	if scope == "" {
		scope = "codex"
	}
	if scope == "provider" && strings.TrimSpace(filters.Provider) != "" {
		scope = "provider-" + exportSafeFilePart(filters.Provider)
	}
	date := strings.TrimSpace(filters.Date)
	if date == "" {
		date = strings.ToLower(strings.TrimSpace(filters.Window))
	}
	if date == "" {
		date = "all"
	}
	ext := "csv"
	if strings.EqualFold(format, "json") {
		ext = "json"
	}
	return "codex-token-usage-logs-" + exportSafeFilePart(scope) + "-" + exportSafeFilePart(date) + "." + ext
}

func exportSafeFilePart(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	var b strings.Builder
	lastDash := false
	for _, r := range value {
		ok := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')
		if ok {
			b.WriteRune(r)
			lastDash = false
			continue
		}
		if !lastDash {
			b.WriteByte('-')
			lastDash = true
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "all"
	}
	return out
}

func exportHeaders(contentType, name string) map[string][]string {
	return map[string][]string{
		"content-type":        {contentType},
		"cache-control":       {"no-store"},
		"content-disposition": {"attachment; filename=\"" + strings.ReplaceAll(name, `"`, "") + "\""},
	}
}

func exportRecords(data map[string]any, kind string) ([]map[string]string, []string) {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "providers":
		return providerExportRows(anySlice[providerRow](data["providers"])), []string{"provider", "requests", "success_rate", "total_tokens", "cost_usd", "avg_latency_ms", "rate_limited", "last_seen"}
	case "models":
		rows := append(anySlice[modelRow](data["models"]), anySlice[modelRow](data["provider_models"])...)
		return modelExportRows(rows), []string{"provider", "model", "alias", "requests", "total_tokens", "cost_usd", "avg_latency_ms", "cache_rate"}
	case "recent":
		rows := append(anySlice[recentRow](data["recent"]), anySlice[recentRow](data["provider_recent"])...)
		return recentExportRows(rows), []string{"time", "provider", "account", "model", "alias", "generate", "status_code", "failed", "total_tokens", "input_tokens", "output_tokens", "cost_usd", "latency_ms"}
	default:
		return accountExportRows(anySlice[accountRow](data["accounts"])), []string{"account", "auth_index", "provider", "requests", "success_rate", "total_tokens", "cost_usd", "quota_total_estimate", "quota_remaining_estimate", "invalid_auth", "external_use_suspected", "last_seen"}
	}
}

func exportLogRecords(ctx context.Context, db *sql.DB, filters logExportFilter, prices map[string]modelPrice) ([]map[string]string, []string, error) {
	if filters.Limit <= 0 {
		filters.Limit = 5000
	}
	if filters.Limit > 20000 {
		filters.Limit = 20000
	}
	where := []string{}
	args := []any{}
	if strings.TrimSpace(filters.Date) != "" {
		start, end, ok := localDateRange(filters.Date)
		if ok {
			where = append(where, "requested_at >= ?", "requested_at < ?")
			args = append(args, start, end)
		}
	} else {
		since, _ := windowStart(firstNonEmptyString(filters.Window, "24h"))
		where = append(where, "requested_at >= ?")
		args = append(args, since)
	}
	scope := strings.ToLower(strings.TrimSpace(filters.Scope))
	switch scope {
	case "providers", "provider":
		where = append(where, usageScopeSQL("other"))
	case "xai":
		where = append(where, usageScopeSQL("xai"))
	default:
		where = append(where, usageScopeSQL("codex"))
	}
	providerExpr := cpaProviderSQL()
	if provider := strings.TrimSpace(filters.Provider); provider != "" {
		where = append(where, providerExpr+" = ?")
		args = append(args, provider)
	}
	accountFilter := strings.TrimSpace(filters.Account)
	if filterID, ok := normalizeKeySummaryFilterID(accountFilter); ok {
		storedKey, found, err := resolveKeySummaryFilterID(ctx, db, filterID, where, args)
		if err != nil {
			return nil, nil, err
		}
		if found {
			where = append(where, `api_key=?`)
			args = append(args, storedKey)
		} else {
			where = append(where, `1=0`)
		}
	} else if strings.Contains(accountFilter, "****") {
		// Display masks are intentionally not identifiers. Failing closed prevents
		// two credentials with the same last four characters from being exported
		// together by an ambiguous legacy filter.
		where = append(where, `1=0`)
	} else if account := normalizeAccountAlias(accountFilter); account != "" {
		where = append(where, `(lower(api_key)=? OR lower(auth_id)=? OR lower(auth_index)=? OR lower(source)=?)`)
		args = append(args, account, account, account, account)
	}
	if model := normalizeAccountAlias(filters.Model); model != "" {
		where = append(where, `(lower(model)=? OR lower(alias)=?)`)
		args = append(args, model, model)
	}
	if status := strings.ToLower(strings.TrimSpace(filters.Status)); status != "" && status != "all" {
		switch status {
		case "success":
			where = append(where, `(failed=0 AND (status_code=0 OR (status_code >= 200 AND status_code < 300)))`)
		case "failed":
			where = append(where, `(failed=1 OR status_code >= 400)`)
		case "401", "402", "403", "429":
			code, _ := strconv.Atoi(status)
			where = append(where, `status_code=?`)
			args = append(args, code)
		case "5xx":
			where = append(where, `status_code >= 500`)
		}
	}
	query := `
SELECT requested_at,
CASE WHEN ` + usageScopeSQL("codex") + ` THEN 'codex' WHEN ` + usageScopeSQL("xai") + ` THEN 'xai' ELSE 'providers' END AS scope_key,
` + providerExpr + ` AS provider_key,
api_key, auth_id, auth_index, source, model, alias, reasoning_effort, service_tier,
generate, latency_ms, ttft_ms, status_code, failed, input_tokens, output_tokens, reasoning_tokens,
cached_tokens, cache_read_tokens, cache_creation_tokens, total_tokens
FROM usage_events
WHERE ` + strings.Join(where, " AND ") + `
ORDER BY requested_at DESC, id DESC
LIMIT ?`
	args = append(args, filters.Limit)
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	headers := []string{
		"time", "scope", "provider", "account", "api_key", "auth_id", "auth_index", "source",
		"model", "alias", "generate", "status_code", "failed", "input_tokens", "output_tokens", "cached_tokens",
		"cache_read_tokens", "cache_creation_tokens", "reasoning_tokens", "total_tokens", "cost_usd",
		"latency_ms", "ttft_ms", "output_tokens_per_second", "error_summary",
	}
	out := []map[string]string{}
	for rows.Next() {
		var ts int64
		var scope, provider, apiKey, authID, authIndex, source, model, alias, reasoning, serviceTier string
		var latency, ttft, input, output, reasoningTokens, cached, cacheRead, cacheCreation, total int64
		var status, generatedInt, failedInt int
		if err := rows.Scan(
			&ts, &scope, &provider, &apiKey, &authID, &authIndex, &source, &model, &alias, &reasoning, &serviceTier,
			&generatedInt, &latency, &ttft, &status, &failedInt, &input, &output, &reasoningTokens, &cached, &cacheRead, &cacheCreation, &total,
		); err != nil {
			return nil, nil, err
		}
		costRow := costTokenRow{
			Model:               model,
			Alias:               alias,
			Provider:            provider,
			ServiceTier:         serviceTier,
			InputTokens:         input,
			OutputTokens:        output,
			CachedTokens:        cached,
			CacheReadTokens:     cacheRead,
			CacheCreationTokens: cacheCreation,
			TotalTokens:         total,
		}
		cost := 0.0
		generated := generatedInt != 0
		if generated {
			if value, ok := costForTokens(costRow, prices); ok {
				cost = value
			}
		}
		throughput := ""
		if generated && output > 0 {
			ms := latency
			if ttft > ms {
				ms = ttft
			}
			if ms >= 1000 {
				throughput = fmt.Sprintf("%.2f", float64(output)/(float64(ms)/1000.0))
			}
		}
		failed := failedInt != 0
		errorSummary := ""
		if failed || status >= 400 {
			if status == 0 {
				status = 599
			}
			errorSummary = "http " + strconv.Itoa(status)
		}
		account := safeExportLabel(firstNonEmptyString(apiKey, authIndex, authID, source))
		if strings.TrimSpace(apiKey) != "" {
			account = maskAPIKeyForDisplay(apiKey)
		}
		out = append(out, map[string]string{
			"time":                     unixTime(ts),
			"scope":                    scope,
			"provider":                 provider,
			"account":                  account,
			"api_key":                  maskAPIKeyForDisplay(apiKey),
			"auth_id":                  safeExportIdentity(authID, apiKey),
			"auth_index":               safeExportIdentity(authIndex, apiKey),
			"source":                   safeExportIdentity(source, apiKey),
			"model":                    model,
			"alias":                    alias,
			"generate":                 strconv.FormatBool(generated),
			"status_code":              strconv.Itoa(status),
			"failed":                   strconv.FormatBool(failed),
			"input_tokens":             strconv.FormatInt(input, 10),
			"output_tokens":            strconv.FormatInt(output, 10),
			"cached_tokens":            strconv.FormatInt(cached, 10),
			"cache_read_tokens":        strconv.FormatInt(cacheRead, 10),
			"cache_creation_tokens":    strconv.FormatInt(cacheCreation, 10),
			"reasoning_tokens":         strconv.FormatInt(reasoningTokens, 10),
			"total_tokens":             strconv.FormatInt(total, 10),
			"cost_usd":                 fmt.Sprintf("%.6f", cost),
			"latency_ms":               strconv.FormatInt(latency, 10),
			"ttft_ms":                  strconv.FormatInt(ttft, 10),
			"output_tokens_per_second": throughput,
			"error_summary":            errorSummary,
		})
	}
	return out, headers, rows.Err()
}

func localDateRange(value string) (int64, int64, bool) {
	date, err := time.ParseInLocation("2006-01-02", strings.TrimSpace(value), time.Local)
	if err != nil {
		return 0, 0, false
	}
	return date.Unix(), date.Add(24 * time.Hour).Unix(), true
}

func anySlice[T any](value any) []T {
	if rows, ok := value.([]T); ok {
		return rows
	}
	return nil
}

func accountExportRows(rows []accountRow) []map[string]string {
	out := make([]map[string]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, map[string]string{
			"account":                  safeExportLabel(firstNonEmptyString(r.Email, r.Source, r.Name, r.AuthID, r.AuthFile, r.AuthIndex)),
			"auth_index":               safeExportLabel(r.AuthIndex),
			"provider":                 r.Provider,
			"requests":                 strconv.FormatInt(r.Requests, 10),
			"success_rate":             fmt.Sprintf("%.2f", successRateBackend(r.Requests, r.Failed)),
			"total_tokens":             strconv.FormatInt(r.TotalTokens, 10),
			"cost_usd":                 fmt.Sprintf("%.6f", r.CostUSD),
			"quota_total_estimate":     strconv.FormatInt(r.SecondaryQuotaTotalEstimate, 10),
			"quota_remaining_estimate": strconv.FormatInt(r.SecondaryQuotaRemainingEstimate, 10),
			"invalid_auth":             strconv.FormatBool(r.InvalidAuth),
			"external_use_suspected":   strconv.FormatBool(r.ExternalUseSuspected),
			"last_seen":                r.LastSeen,
		})
	}
	return out
}

func providerExportRows(rows []providerRow) []map[string]string {
	out := make([]map[string]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, map[string]string{
			"provider":       r.Provider,
			"requests":       strconv.FormatInt(r.Requests, 10),
			"success_rate":   fmt.Sprintf("%.2f", successRateBackend(r.Requests, r.Failed)),
			"total_tokens":   strconv.FormatInt(r.TotalTokens, 10),
			"cost_usd":       fmt.Sprintf("%.6f", r.CostUSD),
			"avg_latency_ms": fmt.Sprintf("%.0f", r.AverageLatencyMs),
			"rate_limited":   strconv.FormatInt(r.RateLimited, 10),
			"last_seen":      r.LastSeen,
		})
	}
	return out
}

func modelExportRows(rows []modelRow) []map[string]string {
	out := make([]map[string]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, map[string]string{
			"provider":       r.Provider,
			"model":          r.Model,
			"alias":          r.Alias,
			"requests":       strconv.FormatInt(r.Requests, 10),
			"total_tokens":   strconv.FormatInt(r.TotalTokens, 10),
			"cost_usd":       fmt.Sprintf("%.6f", r.CostUSD),
			"avg_latency_ms": fmt.Sprintf("%.0f", r.AverageLatencyMs),
			"cache_rate":     fmt.Sprintf("%.2f", cacheRateBackend(r.InputTokens, r.CachedTokens, r.CacheReadTokens)),
		})
	}
	return out
}

func recentExportRows(rows []recentRow) []map[string]string {
	out := make([]map[string]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, map[string]string{
			"time":          r.Time,
			"provider":      r.Provider,
			"account":       safeExportLabel(firstNonEmptyString(r.AuthIndex, r.Source)),
			"model":         r.Model,
			"alias":         r.Alias,
			"generate":      strconv.FormatBool(r.Generate),
			"status_code":   strconv.Itoa(r.StatusCode),
			"failed":        strconv.FormatBool(r.Failed),
			"total_tokens":  strconv.FormatInt(r.TotalTokens, 10),
			"input_tokens":  strconv.FormatInt(r.InputTokens, 10),
			"output_tokens": strconv.FormatInt(r.OutputTokens, 10),
			"cost_usd":      fmt.Sprintf("%.6f", r.CostUSD),
			"latency_ms":    strconv.FormatInt(r.LatencyMs, 10),
		})
	}
	return out
}

func recordsToCSV(headers []string, records []map[string]string) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteString("\xEF\xBB\xBF")
	writer := csv.NewWriter(&buf)
	safeHeaders := make([]string, len(headers))
	for i, header := range headers {
		safeHeaders[i] = safeCSVCell(header)
	}
	if err := writer.Write(safeHeaders); err != nil {
		return nil, err
	}
	for _, record := range records {
		row := make([]string, len(headers))
		for i, header := range headers {
			row[i] = safeCSVCell(record[header])
		}
		if err := writer.Write(row); err != nil {
			return nil, err
		}
	}
	writer.Flush()
	return buf.Bytes(), writer.Error()
}

func safeCSVCell(value string) string {
	for _, r := range value {
		switch r {
		case '\t', '\r', '\n':
			return "'" + value
		case '=', '+', '-', '@':
			return "'" + value
		}
		if unicode.IsSpace(r) {
			continue
		}
		break
	}
	return value
}

func safeExportLabel(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	value = maskEmbeddedStoredFingerprints(value)
	if strings.Contains(value, "****") {
		return value
	}
	if _, ok := storedAPIKeyFingerprintLast4(value); ok {
		return maskAPIKeyForDisplay(value)
	}
	if _, ok := bearerCredential(value); ok {
		return maskAPIKeyForDisplay(value)
	}
	if apiKeyPrefixLength(value) > 0 {
		return maskAPIKeyForDisplay(value)
	}
	if looksLikeOpaqueCredential(value) {
		return maskAPIKeyForDisplay(value)
	}
	return value
}

func safeExportIdentity(value, storedAPIKey string) string {
	value = strings.TrimSpace(value)
	storedAPIKey = strings.TrimSpace(storedAPIKey)
	if value == "" || storedAPIKey == "" {
		return safeExportLabel(value)
	}
	masked := maskAPIKeyForDisplay(storedAPIKey)
	value = strings.ReplaceAll(value, "Bearer "+storedAPIKey, masked)
	value = strings.ReplaceAll(value, "bearer "+storedAPIKey, masked)
	value = strings.ReplaceAll(value, storedAPIKey, masked)
	return safeExportLabel(value)
}

func maskEmbeddedStoredFingerprints(value string) string {
	const fingerprintLength = len("keyfp:v1:") + 32 + 1 + 4
	for offset := 0; offset < len(value); {
		index := strings.Index(strings.ToLower(value[offset:]), "keyfp:")
		if index < 0 {
			break
		}
		index += offset
		if len(value)-index < fingerprintLength {
			break
		}
		candidate := value[index : index+fingerprintLength]
		if _, ok := storedAPIKeyFingerprintLast4(candidate); !ok {
			offset = index + len("keyfp:")
			continue
		}
		value = value[:index] + maskAPIKeyForDisplay(candidate) + value[index+fingerprintLength:]
		offset = index + len("key-****")
	}
	return value
}

func maskAPIKeyForDisplay(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if last4, ok := storedAPIKeyFingerprintLast4(value); ok {
		return "key-****" + last4
	}
	if credential, ok := bearerCredential(value); ok {
		return "Bearer " + maskCredentialForDisplay(credential, apiKeyPrefixLength(credential))
	}
	prefixLen := apiKeyPrefixLength(value)
	if prefixLen == 0 {
		return "key-" + maskCredentialForDisplay(value, 0)
	}
	return maskCredentialForDisplay(value, prefixLen)
}

const keySummaryFilterIDPrefix = "keyid:v1:"

func keySummaryFilterID(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	digest := sha256.Sum256([]byte(value))
	return keySummaryFilterIDPrefix + hex.EncodeToString(digest[:])
}

func normalizeKeySummaryFilterID(value string) (string, bool) {
	value = strings.ToLower(strings.TrimSpace(value))
	if !strings.HasPrefix(value, keySummaryFilterIDPrefix) || len(value) != len(keySummaryFilterIDPrefix)+sha256.Size*2 {
		return "", false
	}
	if _, err := hex.DecodeString(value[len(keySummaryFilterIDPrefix):]); err != nil {
		return "", false
	}
	return value, true
}

func resolveKeySummaryFilterID(ctx context.Context, db *sql.DB, filterID string, where []string, args []any) (string, bool, error) {
	query := `SELECT DISTINCT api_key FROM usage_events`
	conditions := append([]string(nil), where...)
	conditions = append(conditions, `api_key <> ''`)
	if len(conditions) > 0 {
		query += ` WHERE ` + strings.Join(conditions, " AND ")
	}
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return "", false, err
	}
	defer rows.Close()
	matched := ""
	for rows.Next() {
		var stored string
		if err := rows.Scan(&stored); err != nil {
			return "", false, err
		}
		if keySummaryFilterID(stored) != filterID {
			continue
		}
		if matched != "" && matched != stored {
			return "", false, fmt.Errorf("ambiguous key summary filter identifier")
		}
		matched = stored
	}
	if err := rows.Err(); err != nil {
		return "", false, err
	}
	return matched, matched != "", nil
}

func bearerCredential(value string) (string, bool) {
	if len(value) <= len("bearer") || !strings.EqualFold(value[:len("bearer")], "bearer") {
		return "", false
	}
	rest := value[len("bearer"):]
	trimmed := strings.TrimLeftFunc(rest, unicode.IsSpace)
	if len(trimmed) == len(rest) || strings.TrimSpace(trimmed) == "" {
		return "", false
	}
	return strings.TrimSpace(trimmed), true
}

func apiKeyPrefixLength(value string) int {
	lower := strings.ToLower(value)
	for _, prefix := range []string{"sk-svcacct-", "sk-proj-", "sk-ant-", "xai-", "aiza", "sk-"} {
		if strings.HasPrefix(lower, prefix) {
			return len(prefix)
		}
	}
	return 0
}

func maskCredentialForDisplay(value string, prefixLen int) string {
	if prefixLen < 0 || prefixLen > len(value) {
		prefixLen = 0
	}
	masked := value[:prefixLen] + "****"
	if len(value)-prefixLen > 8 {
		masked += value[len(value)-4:]
	}
	return masked
}

func storedAPIKeyFingerprintLast4(value string) (string, bool) {
	_, _, suffix, ok := parseAPIKeyFingerprint(value)
	return suffix, ok
}

func successRateBackend(requests, failed int64) float64 {
	if requests <= 0 {
		return 0
	}
	return float64(requests-failed) * 100 / float64(requests)
}

func cacheRateBackend(input, cached, cacheRead int64) float64 {
	cache := cached
	if cacheRead > cache {
		cache = cacheRead
	}
	if input <= 0 {
		return 0
	}
	return float64(cache) * 100 / float64(input)
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
