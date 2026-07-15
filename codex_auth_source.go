package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const codexAuthSourceCacheTTL = 3 * time.Second

var (
	errCodexHostAuthListUnavailable = errors.New("host.auth.list unavailable")
	errCodexHostAuthListInvalid     = errors.New("host.auth.list returned an invalid response")
)

// These wire types mirror pluginapi.HostAuthFileEntry at CLIProxyAPI commit
// b6ce0beecd31dff389d3190f7db6d7a1d4ce0e7e. Keep the time fields typed as
// time.Time: the current host ABI emits RFC3339 timestamps, not the legacy
// string fields previously assumed by this plugin.
type codexHostRecentRequestEntry struct {
	Time    string `json:"time"`
	Success int64  `json:"success"`
	Failed  int64  `json:"failed"`
}

type codexHostAuthFileEntry struct {
	ID             string                        `json:"id,omitempty"`
	AuthIndex      string                        `json:"auth_index,omitempty"`
	Name           string                        `json:"name"`
	Type           string                        `json:"type,omitempty"`
	Provider       string                        `json:"provider,omitempty"`
	Label          string                        `json:"label,omitempty"`
	Status         string                        `json:"status,omitempty"`
	StatusMessage  string                        `json:"status_message,omitempty"`
	Disabled       bool                          `json:"disabled,omitempty"`
	Unavailable    bool                          `json:"unavailable,omitempty"`
	RuntimeOnly    bool                          `json:"runtime_only,omitempty"`
	Source         string                        `json:"source,omitempty"`
	Path           string                        `json:"path,omitempty"`
	Size           int64                         `json:"size,omitempty"`
	ModTime        time.Time                     `json:"modtime,omitempty"`
	UpdatedAt      time.Time                     `json:"updated_at,omitempty"`
	CreatedAt      time.Time                     `json:"created_at,omitempty"`
	LastRefresh    time.Time                     `json:"last_refresh,omitempty"`
	NextRetryAfter time.Time                     `json:"next_retry_after,omitempty"`
	Email          string                        `json:"email,omitempty"`
	ProjectID      string                        `json:"project_id,omitempty"`
	AccountType    string                        `json:"account_type,omitempty"`
	Account        string                        `json:"account,omitempty"`
	Priority       int                           `json:"priority,omitempty"`
	Note           string                        `json:"note,omitempty"`
	Websockets     bool                          `json:"websockets,omitempty"`
	Success        int64                         `json:"success,omitempty"`
	Failed         int64                         `json:"failed,omitempty"`
	RecentRequests []codexHostRecentRequestEntry `json:"recent_requests,omitempty"`
}

type codexHostAuthListResponse struct {
	Files []codexHostAuthFileEntry `json:"files"`
}

type codexAuthSourceManager struct {
	mu        sync.RWMutex
	refreshMu sync.Mutex

	fetchedAt    time.Time
	callbackErr  error
	hostSnapshot []configuredAccount
	accounts     []configuredAccount
	revision     string
	diagnostics  xaiAuthSourceDiagnostics
}

var globalCodexAuthSource = &codexAuthSourceManager{}

// hostAccounts returns only a successful host snapshot. A callback or decode
// failure is deliberately returned to the caller so it can select a
// filesystem fallback. No raw callback error or credential payload is cached.
func (m *codexAuthSourceManager) hostAccounts() ([]configuredAccount, error) {
	if accounts, err, ok := m.cachedHostResult(time.Now()); ok {
		return accounts, err
	}

	// Serialize cache misses and re-check after acquiring the refresh lock. This
	// avoids callback stampedes while keeping reads of a fresh snapshot cheap.
	m.refreshMu.Lock()
	defer m.refreshMu.Unlock()
	if accounts, err, ok := m.cachedHostResult(time.Now()); ok {
		return accounts, err
	}

	raw, err := hostAuthCaller("host.auth.list", map[string]any{})
	if err != nil {
		m.recordHostFailure(errCodexHostAuthListUnavailable)
		return nil, errCodexHostAuthListUnavailable
	}
	var response codexHostAuthListResponse
	if err := json.Unmarshal(raw, &response); err != nil {
		m.recordHostFailure(errCodexHostAuthListInvalid)
		return nil, errCodexHostAuthListInvalid
	}

	accounts := make([]configuredAccount, 0, len(response.Files))
	for _, entry := range response.Files {
		if account, ok := codexConfiguredAccountFromHostEntry(entry); ok {
			accounts = append(accounts, account)
		}
	}
	now := time.Now()
	diagnostics := xaiAuthSourceDiagnostics{
		Source:        "host_callback",
		Authoritative: true,
		Accounts:      len(accounts),
		LastSuccessAt: now.Format(time.RFC3339),
	}
	m.mu.Lock()
	m.fetchedAt = now
	m.callbackErr = nil
	m.hostSnapshot = cloneConfiguredAccounts(accounts)
	m.accounts = cloneConfiguredAccounts(accounts)
	m.revision = configuredAccountListRevision(accounts)
	m.diagnostics = diagnostics
	m.mu.Unlock()
	return cloneConfiguredAccounts(accounts), nil
}

func (m *codexAuthSourceManager) cachedHostResult(now time.Time) ([]configuredAccount, error, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.fetchedAt.IsZero() {
		return nil, nil, false
	}
	age := now.Sub(m.fetchedAt)
	if age < 0 || age >= codexAuthSourceCacheTTL {
		return nil, nil, false
	}
	if m.callbackErr != nil {
		return nil, m.callbackErr, true
	}
	if m.diagnostics.Source != "host_callback" || !m.diagnostics.Authoritative {
		return nil, nil, false
	}
	return cloneConfiguredAccounts(m.accounts), nil, true
}

func (m *codexAuthSourceManager) recordHostFailure(failure error) {
	now := time.Now()
	m.mu.Lock()
	m.fetchedAt = now
	m.callbackErr = failure
	m.diagnostics = xaiAuthSourceDiagnostics{
		Source:        "host_callback_error",
		Authoritative: false,
		Accounts:      len(m.accounts),
		LastSuccessAt: m.diagnostics.LastSuccessAt,
		LastError:     failure.Error(),
	}
	m.mu.Unlock()
}

// markFilesystemFallback records the caller-selected fallback without making
// it authoritative. The host can expose runtime-only credentials, so a local
// directory cannot prove that absent host entries were removed.
func (m *codexAuthSourceManager) markFilesystemFallback(accounts []configuredAccount, _ error) []configuredAccount {
	m.mu.Lock()
	if m.callbackErr == nil && m.diagnostics.Source == "host_callback" && m.diagnostics.Authoritative {
		// A filesystem read that started after an older callback failure must not
		// overwrite a newer authoritative host refresh. It may enrich matching
		// rows with non-secret metadata, but it cannot reintroduce file-only rows.
		current := mergeConfiguredAccountMetadata(cloneConfiguredAccounts(m.hostSnapshot), accounts)
		m.mu.Unlock()
		return current
	}
	merged := mergeCodexAccountSnapshots(m.hostSnapshot, accounts)
	m.accounts = cloneConfiguredAccounts(merged)
	m.revision = configuredAccountListRevision(merged)
	m.diagnostics = xaiAuthSourceDiagnostics{
		Source:        "filesystem_fallback",
		Authoritative: false,
		Accounts:      len(merged),
		LastSuccessAt: m.diagnostics.LastSuccessAt,
		LastError:     errCodexHostAuthListUnavailable.Error(),
	}
	m.mu.Unlock()
	return cloneConfiguredAccounts(merged)
}

func mergeCodexAccountSnapshots(hostAccounts, filesystemAccounts []configuredAccount) []configuredAccount {
	merged := cloneConfiguredAccounts(hostAccounts)
	for _, candidate := range filesystemAccounts {
		candidateAliases := configuredAliases(candidate)
		duplicate := false
		for _, existing := range merged {
			if aliasesOverlap(candidateAliases, configuredAliases(existing)) {
				duplicate = true
				break
			}
		}
		if !duplicate {
			merged = append(merged, candidate)
		}
	}
	return merged
}

func (m *codexAuthSourceManager) authoritative() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.diagnostics.Authoritative
}

func (m *codexAuthSourceManager) status() xaiAuthSourceDiagnostics {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.diagnostics
}

func (m *codexAuthSourceManager) currentRevision() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.revision
}

func (m *codexAuthSourceManager) invalidate() {
	m.mu.Lock()
	m.fetchedAt = time.Time{}
	m.callbackErr = nil
	m.mu.Unlock()
}

func codexConfiguredAccountFromHostEntry(entry codexHostAuthFileEntry) (configuredAccount, bool) {
	provider := normalizeAuthProvider(
		firstNonEmptyString(entry.Provider, entry.Type),
		firstNonEmptyString(entry.Name, entry.Path, entry.AuthIndex),
	)
	if !isCodexAuthProvider(provider) {
		return configuredAccount{}, false
	}

	// Account is intentionally ignored. In current CPA it is the literal API
	// key when AccountType is api_key. Label, Note, and StatusMessage are also
	// never used as identities because they are free text and may contain
	// credentials. StatusMessage is retained only after the shared redactor.
	email := safeAuthAccountEmail(entry.AccountType, entry.Email, entry.Account)
	authFile := firstNonEmptyString(
		fileNameIfJSON(entry.Name),
		fileNameIfJSON(entry.Path),
		fileNameIfJSON(entry.ID),
	)
	authIndex := firstNonEmptyString(entry.AuthIndex, authFile, entry.ID)
	authID := firstNonEmptyString(entry.ID, authIndex, authFile)
	name := firstNonEmptyString(entry.Name, filepath.Base(entry.Path), entry.ID)
	source := firstNonEmptyString(email, name, authIndex, authID)
	if authIndex == "" && authID == "" && source == "" {
		return configuredAccount{}, false
	}
	modified := entry.ModTime
	if modified.IsZero() {
		modified = entry.UpdatedAt
	}
	status := strings.TrimSpace(entry.Status)
	return configuredAccount{
		AuthIndex:          authIndex,
		AuthID:             authID,
		Source:             source,
		Provider:           "codex",
		Email:              email,
		Name:               name,
		AuthFile:           authFile,
		AuthFileMTime:      unixSecondsOrZero(modified),
		Disabled:           entry.Disabled || strings.EqualFold(status, "disabled"),
		Expired:            strings.EqualFold(status, "expired"),
		RuntimeStatus:      status,
		RuntimeMessage:     sanitizeTriggerError(entry.StatusMessage),
		RuntimeUnavailable: entry.Unavailable,
	}, true
}

func unixSecondsOrZero(value time.Time) int64 {
	if value.IsZero() {
		return 0
	}
	return value.Unix()
}

func configuredAccountListRevision(accounts []configuredAccount) string {
	rows := make([]string, 0, len(accounts))
	for _, account := range accounts {
		rows = append(rows, strings.Join([]string{
			account.Provider,
			account.AuthIndex,
			account.AuthID,
			account.AuthFile,
			account.Email,
			strconv.FormatInt(account.AuthFileMTime, 10),
			strconv.FormatBool(account.Disabled),
			strconv.FormatBool(account.Expired),
			account.RuntimeStatus,
			strconv.FormatBool(account.RuntimeUnavailable),
		}, "\x00"))
	}
	sort.Strings(rows)
	hash := sha256.New()
	for _, row := range rows {
		_, _ = hash.Write([]byte(row))
		_, _ = hash.Write([]byte{0})
	}
	return strconv.Itoa(len(rows)) + ":" + hex.EncodeToString(hash.Sum(nil)[:16])
}

// mergeConfiguredAccountMetadata enriches host rows with non-secret file
// metadata. In particular it never copies AccessToken, even if the fallback
// scanner has loaded one from disk.
func mergeConfiguredAccountMetadata(accounts, metadata []configuredAccount) []configuredAccount {
	if len(accounts) == 0 || len(metadata) == 0 {
		return accounts
	}
	index := make(map[string]configuredAccount, len(metadata)*4)
	for _, item := range metadata {
		for _, alias := range configuredAliases(item) {
			if alias != "" {
				index[alias] = item
			}
		}
	}
	for i := range accounts {
		var detail configuredAccount
		found := false
		for _, alias := range configuredAliases(accounts[i]) {
			if item, ok := index[alias]; ok {
				detail = item
				found = true
				break
			}
		}
		if !found {
			continue
		}
		accounts[i].Email = firstNonEmptyString(accounts[i].Email, detail.Email)
		accounts[i].Name = firstNonEmptyString(accounts[i].Name, detail.Name)
		accounts[i].PlanType = firstNonEmptyString(accounts[i].PlanType, detail.PlanType)
		accounts[i].ChatGPTAccountID = firstNonEmptyString(accounts[i].ChatGPTAccountID, detail.ChatGPTAccountID)
		if accounts[i].AuthFileMTime == 0 {
			accounts[i].AuthFileMTime = detail.AuthFileMTime
		}
	}
	return accounts
}
