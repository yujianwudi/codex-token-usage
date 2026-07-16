package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	xaiTierFree          = "free"
	xaiTierSuper         = "super"
	xaiTierHeavy         = "heavy"
	xaiTierCacheMaxItems = 1024
	xaiTierCacheTTL      = 30 * time.Minute
)

var (
	errXAIHostAuthListUnavailable = errors.New("host.auth.list unavailable")
	errXAIHostAuthListInvalid     = errors.New("host.auth.list returned an invalid response")
)

type hostCallFunc func(method string, payload any) (json.RawMessage, error)

var hostAuthCaller hostCallFunc = callHost

type hostAuthListResponse struct {
	Files []hostAuthFileEntry `json:"files"`
}

type hostAuthFileEntry struct {
	Account       string `json:"account"`
	AccountType   string `json:"account_type"`
	AuthIndex     string `json:"auth_index"`
	Disabled      bool   `json:"disabled"`
	Email         string `json:"email"`
	Expired       bool   `json:"expired"`
	ID            string `json:"id"`
	Label         string `json:"label"`
	Name          string `json:"name"`
	Note          string `json:"note"`
	Path          string `json:"path"`
	Plan          string `json:"plan"`
	PlanType      string `json:"plan_type"`
	Prefix        string `json:"prefix"`
	Priority      int    `json:"priority"`
	Provider      string `json:"provider"`
	Source        string `json:"source"`
	Status        string `json:"status"`
	StatusMessage string `json:"status_message"`
	Subscription  string `json:"subscription"`
	Tag           string `json:"tag"`
	Type          string `json:"type"`
	Unavailable   bool   `json:"unavailable"`
	UpdatedAt     string `json:"updated_at"`
}

type hostAuthGetRequest struct {
	AuthIndex string `json:"auth_index"`
}

type hostAuthGetResponse struct {
	AuthIndex string          `json:"auth_index"`
	Name      string          `json:"name,omitempty"`
	Path      string          `json:"path,omitempty"`
	JSON      json.RawMessage `json:"json"`
}

type hostAuthRuntimeResponse struct {
	Auth hostAuthFileEntry `json:"auth"`
}

type xaiTierClassification struct {
	Tier   string
	Source string
	Detail string
}

type cachedXAITier struct {
	Version   string
	FetchedAt time.Time
	Value     xaiTierClassification
}

type xaiAuthSourceDiagnostics struct {
	Source             string `json:"source"`
	Authoritative      bool   `json:"authoritative"`
	Accounts           int    `json:"accounts"`
	MetadataReadErrors int    `json:"metadata_read_errors"`
	HostStatus         string `json:"host_status,omitempty"`
	FallbackStatus     string `json:"fallback_status,omitempty"`
	LastSuccessAt      string `json:"last_success_at,omitempty"`
	LastError          string `json:"last_error,omitempty"`
}

type xaiAuthSourceManager struct {
	mu        sync.Mutex
	refreshMu sync.Mutex

	fetchedAt    time.Time
	callbackErr  error
	hostSnapshot []configuredAccount
	accounts     []configuredAccount
	tierCache    map[string]cachedXAITier
	diagnostics  xaiAuthSourceDiagnostics
}

var globalXAIAuthSource = &xaiAuthSourceManager{}

func (m *xaiAuthSourceManager) hostAccounts() ([]configuredAccount, error) {
	if accounts, err, ok := m.cachedHostResult(time.Now()); ok {
		return accounts, err
	}

	m.refreshMu.Lock()
	defer m.refreshMu.Unlock()
	if accounts, err, ok := m.cachedHostResult(time.Now()); ok {
		return accounts, err
	}

	raw, err := hostAuthCaller("host.auth.list", map[string]any{})
	if err != nil {
		m.recordHostFailure(errXAIHostAuthListUnavailable)
		return nil, errXAIHostAuthListUnavailable
	}
	var response hostAuthListResponse
	if err := json.Unmarshal(raw, &response); err != nil {
		m.recordHostFailure(errXAIHostAuthListInvalid)
		return nil, errXAIHostAuthListInvalid
	}
	accounts := make([]configuredAccount, 0, len(response.Files))
	metadataErrors := 0
	for _, entry := range response.Files {
		provider := normalizeAuthProvider(firstNonEmptyString(entry.Provider, entry.Type), firstNonEmptyString(entry.Name, entry.Path, entry.AuthIndex))
		if !strings.EqualFold(provider, "xai") {
			continue
		}
		if strings.TrimSpace(entry.AuthIndex) != "" && strings.TrimSpace(entry.Status) == "" {
			if runtimeErr := m.mergeHostRuntime(&entry); runtimeErr != nil {
				metadataErrors++
			}
		}
		classification, metadataErr := m.classifyHostEntry(entry)
		if metadataErr != nil {
			metadataErrors++
		}
		email := safeAuthAccountEmail(entry.AccountType, entry.Email, entry.Account)
		authFile := firstNonEmptyString(fileNameIfJSON(entry.Name), fileNameIfJSON(entry.Path), fileNameIfJSON(entry.AuthIndex))
		authIndex := firstNonEmptyString(entry.AuthIndex, authFile, entry.ID)
		name := firstNonEmptyString(entry.Name, filepath.Base(entry.Path))
		hostSource := strings.TrimSpace(entry.Source)
		if looksLikeCredentialToken(hostSource) {
			hostSource = ""
		}
		source := firstNonEmptyString(hostSource, email, name, authIndex)
		planType := firstNonEmptyString(entry.PlanType, entry.Plan, entry.Subscription)
		accounts = append(accounts, configuredAccount{
			AuthIndex:          authIndex,
			AuthID:             firstNonEmptyString(entry.ID, email),
			Source:             source,
			Provider:           "xai",
			Email:              email,
			Name:               name,
			AuthFile:           authFile,
			AuthFileMTime:      parseHostAuthUpdatedAt(entry.UpdatedAt),
			Disabled:           entry.Disabled || strings.EqualFold(strings.TrimSpace(entry.Status), "disabled"),
			Expired:            entry.Expired || strings.EqualFold(strings.TrimSpace(entry.Status), "expired"),
			PlanType:           planType,
			XAITier:            classification.Tier,
			XAITierSource:      classification.Source,
			XAITierDetail:      classification.Detail,
			RuntimeStatus:      strings.TrimSpace(entry.Status),
			RuntimeMessage:     sanitizeTriggerError(entry.StatusMessage),
			RuntimeUnavailable: entry.Unavailable,
		})
	}
	now := time.Now()
	m.mu.Lock()
	m.fetchedAt = now
	m.callbackErr = nil
	m.hostSnapshot = cloneConfiguredAccounts(accounts)
	m.accounts = cloneConfiguredAccounts(accounts)
	m.diagnostics = xaiAuthSourceDiagnostics{
		Source:             "host_callback",
		Authoritative:      true,
		Accounts:           len(accounts),
		MetadataReadErrors: metadataErrors,
		HostStatus:         "ok",
		LastSuccessAt:      now.Format(time.RFC3339),
	}
	m.mu.Unlock()
	return accounts, nil
}

func (m *xaiAuthSourceManager) cachedHostResult(now time.Time) ([]configuredAccount, error, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fetchedAt.IsZero() {
		return nil, nil, false
	}
	age := now.Sub(m.fetchedAt)
	if age < 0 || age >= 3*time.Second {
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

func (m *xaiAuthSourceManager) recordHostFailure(failure error) {
	now := time.Now()
	m.mu.Lock()
	m.fetchedAt = now
	m.callbackErr = failure
	m.diagnostics = xaiAuthSourceDiagnostics{
		Source:        "host_callback_error",
		Authoritative: false,
		Accounts:      len(m.accounts),
		HostStatus:    hostAuthDiagnosticStatus(failure),
		LastSuccessAt: m.diagnostics.LastSuccessAt,
		LastError:     failure.Error(),
	}
	m.mu.Unlock()
}

func (m *xaiAuthSourceManager) mergeHostRuntime(entry *hostAuthFileEntry) error {
	raw, err := hostAuthCaller("host.auth.get_runtime", hostAuthGetRequest{AuthIndex: entry.AuthIndex})
	if err != nil {
		return err
	}
	var response hostAuthRuntimeResponse
	if err := json.Unmarshal(raw, &response); err != nil {
		return fmt.Errorf("decode host.auth.get_runtime result: %w", err)
	}
	runtime := response.Auth
	if runtime.Status != "" {
		entry.Status = runtime.Status
	}
	if runtime.StatusMessage != "" {
		entry.StatusMessage = runtime.StatusMessage
	}
	entry.Disabled = entry.Disabled || runtime.Disabled
	entry.Unavailable = entry.Unavailable || runtime.Unavailable
	if runtime.UpdatedAt != "" {
		entry.UpdatedAt = runtime.UpdatedAt
	}
	if runtime.Priority != 0 {
		entry.Priority = runtime.Priority
	}
	return nil
}

func (m *xaiAuthSourceManager) classifyHostEntry(entry hostAuthFileEntry) (xaiTierClassification, error) {
	base := classifyXAITierSignals([]xaiTierSignal{
		{Path: "host.account_type", Value: entry.AccountType},
		{Path: "host.plan_type", Value: entry.PlanType},
		{Path: "host.plan", Value: entry.Plan},
		{Path: "host.subscription", Value: entry.Subscription},
		{Path: "host.note", Value: entry.Note},
		{Path: "host.prefix", Value: entry.Prefix},
		{Path: "host.label", Value: entry.Label},
		{Path: "host.tag", Value: entry.Tag},
		{Path: "host.name", Value: entry.Name},
	})
	if strings.TrimSpace(entry.AuthIndex) == "" || base.Tier == xaiTierHeavy {
		return base, nil
	}
	cacheKey := normalizeAccountAlias(entry.AuthIndex)
	version := strings.TrimSpace(entry.UpdatedAt)
	m.mu.Lock()
	if cached, ok := m.tierCache[cacheKey]; ok {
		age := time.Since(cached.FetchedAt)
		fresh := age >= 0 && age < xaiTierCacheTTL
		versionMatches := version != "" && cached.Version == version
		unversionedFresh := version == "" && age >= 0 && age < 5*time.Minute
		if fresh && (versionMatches || unversionedFresh) {
			m.mu.Unlock()
			return cached.Value, nil
		}
	}
	m.mu.Unlock()
	raw, err := hostAuthCaller("host.auth.get", hostAuthGetRequest{AuthIndex: entry.AuthIndex})
	if err != nil {
		return base, err
	}
	var response hostAuthGetResponse
	if err := json.Unmarshal(raw, &response); err != nil {
		return base, fmt.Errorf("decode host.auth.get result: %w", err)
	}
	classification := classifyXAITierJSON(response.JSON, base)
	m.mu.Lock()
	if m.tierCache == nil {
		m.tierCache = make(map[string]cachedXAITier)
	}
	now := time.Now()
	m.pruneTierCacheLocked(now)
	m.tierCache[cacheKey] = cachedXAITier{Version: version, FetchedAt: now, Value: classification}
	m.mu.Unlock()
	return classification, nil
}

func (m *xaiAuthSourceManager) pruneTierCacheLocked(now time.Time) {
	oldestKey := ""
	var oldest time.Time
	for key, cached := range m.tierCache {
		if now.Sub(cached.FetchedAt) > xaiTierCacheTTL {
			delete(m.tierCache, key)
			continue
		}
		if oldestKey == "" || cached.FetchedAt.Before(oldest) {
			oldestKey = key
			oldest = cached.FetchedAt
		}
	}
	if len(m.tierCache) >= xaiTierCacheMaxItems && oldestKey != "" {
		delete(m.tierCache, oldestKey)
	}
}

func (m *xaiAuthSourceManager) markFilesystemFallback(accounts []configuredAccount, _ error) []configuredAccount {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.callbackErr == nil && m.diagnostics.Source == "host_callback" && m.diagnostics.Authoritative {
		return cloneConfiguredAccounts(m.accounts)
	}
	// A readable directory is not proof that it contains every account exposed
	// by the host. Runtime-only entries and host-managed paths can disappear from
	// a filesystem fallback during a transient callback failure. Preserve the
	// last successful host snapshot for continuity, but mark the merged view as
	// non-authoritative so missing entries cannot clear active scheduler state.
	merged := mergeXAIAccountSnapshots(m.hostSnapshot, accounts)
	m.accounts = cloneConfiguredAccounts(merged)
	hostStatus := hostAuthDiagnosticStatus(m.callbackErr)
	fallbackStatus := configuredAuthFilesFallbackStatus()
	m.diagnostics = xaiAuthSourceDiagnostics{
		Source:             "filesystem_fallback",
		Authoritative:      false,
		Accounts:           len(merged),
		MetadataReadErrors: 0,
		HostStatus:         hostStatus,
		FallbackStatus:     fallbackStatus,
		LastSuccessAt:      m.diagnostics.LastSuccessAt,
		LastError:          authSourceFallbackDiagnostic(hostStatus, fallbackStatus),
	}
	return cloneConfiguredAccounts(merged)
}

func mergeXAIAccountSnapshots(hostAccounts, filesystemAccounts []configuredAccount) []configuredAccount {
	merged := cloneConfiguredAccounts(hostAccounts)
	for _, candidate := range filesystemAccounts {
		candidateAliases := normalizeAccountAliases(
			candidate.AuthFile,
			candidate.AuthIndex,
			candidate.AuthID,
			candidate.Email,
		)
		duplicate := false
		for _, existing := range merged {
			if aliasesOverlap(candidateAliases, normalizeAccountAliases(
				existing.AuthFile,
				existing.AuthIndex,
				existing.AuthID,
				existing.Email,
			)) {
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

func (m *xaiAuthSourceManager) authoritative() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.diagnostics.Authoritative
}

func (m *xaiAuthSourceManager) status() xaiAuthSourceDiagnostics {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.diagnostics
}

func cloneConfiguredAccounts(accounts []configuredAccount) []configuredAccount {
	return append([]configuredAccount(nil), accounts...)
}

func parseHostAuthUpdatedAt(value string) int64 {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}
	if unix, err := strconv.ParseInt(value, 10, 64); err == nil {
		return normalizeUnixSeconds(unix)
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed.Unix()
		}
	}
	return 0
}

type xaiTierSignal struct {
	Path  string
	Value string
}

func classifyXAITierJSON(raw json.RawMessage, base xaiTierClassification) xaiTierClassification {
	if len(bytes.TrimSpace(raw)) == 0 || string(bytes.TrimSpace(raw)) == "null" {
		return base
	}
	var value any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return base
	}
	signals := collectXAITierSignals(value, "auth")
	classified := classifyXAITierSignals(signals)
	if xaiTierRank(classified.Tier) > xaiTierRank(base.Tier) || (base.Source == "default" && classified.Source != "default") {
		return classified
	}
	return base
}

func classifyXAITierDocument(doc map[string]any) xaiTierClassification {
	raw, _ := json.Marshal(doc)
	return classifyXAITierJSON(raw, xaiTierClassification{Tier: xaiTierFree, Source: "default", Detail: "No paid xAI tier metadata"})
}

func collectXAITierSignals(value any, path string) []xaiTierSignal {
	var out []xaiTierSignal
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			childPath := path + "." + key
			if xaiTierMetadataKey(key) {
				switch scalar := child.(type) {
				case string:
					out = append(out, xaiTierSignal{Path: childPath, Value: scalar})
				case json.Number:
					out = append(out, xaiTierSignal{Path: childPath, Value: scalar.String()})
				}
			}
			out = append(out, collectXAITierSignals(child, childPath)...)
		}
	case []any:
		for index, child := range typed {
			out = append(out, collectXAITierSignals(child, fmt.Sprintf("%s[%d]", path, index))...)
		}
	}
	return out
}

func xaiTierMetadataKey(key string) bool {
	normalized := normalizeXAITierText(key)
	switch normalized {
	case "tier", "plantype", "plan", "accounttype", "accounttier", "subscription", "subscriptiontype", "subscriptiontier", "subscriptionplan", "membership", "membershiptier", "product", "producttier", "sku", "license", "entitlement", "entitlements", "xaitier", "xaiplan", "groktier", "grokplan", "groksubscription", "servicetier", "note", "prefix", "label", "tag", "grouptag", "grouplabel":
		return true
	default:
		return false
	}
}

func classifyXAITierSignals(signals []xaiTierSignal) xaiTierClassification {
	best := xaiTierClassification{Tier: xaiTierFree, Source: "default", Detail: "No paid xAI tier metadata"}
	for _, signal := range signals {
		tier := xaiTierFromText(signal.Value)
		if tier == "" {
			continue
		}
		candidate := xaiTierClassification{
			Tier:   tier,
			Source: safeXAITierSignalSource(signal.Path),
			Detail: xaiTierDetail(tier),
		}
		if xaiTierRank(candidate.Tier) > xaiTierRank(best.Tier) || best.Source == "default" {
			best = candidate
		}
	}
	return best
}

func safeXAITierSignalSource(path string) string {
	path = strings.TrimSpace(path)
	origin := "metadata"
	if strings.HasPrefix(strings.ToLower(path), "host.") {
		origin = "host"
	}
	if index := strings.LastIndex(path, "."); index >= 0 {
		path = path[index+1:]
	}
	if index := strings.Index(path, "["); index >= 0 {
		path = path[:index]
	}
	key := normalizeXAITierText(path)
	if !xaiTierMetadataKey(key) {
		return origin + ".tier"
	}
	return origin + "." + key
}

func xaiTierDetail(tier string) string {
	switch tier {
	case xaiTierHeavy:
		return "Recognized Heavy xAI tier metadata"
	case xaiTierSuper:
		return "Recognized Super xAI tier metadata"
	default:
		return "Recognized Free xAI tier metadata"
	}
}

func xaiTierFromText(value string) string {
	normalized := normalizeXAITierText(value)
	switch {
	case normalized == "":
		return ""
	case strings.Contains(normalized, "supergrokheavy"), strings.Contains(normalized, "grokheavy"), strings.Contains(normalized, "heavy"), strings.Contains(normalized, "supergrokpro"):
		return xaiTierHeavy
	case strings.Contains(normalized, "supergrok"), strings.Contains(normalized, "grokpro"), strings.Contains(normalized, "premiumplus"), strings.Contains(normalized, "premium"), normalized == "super", normalized == "pro", normalized == "plus", normalized == "paid":
		return xaiTierSuper
	case normalized == "free", strings.Contains(normalized, "freetier"), strings.Contains(normalized, "subscriptiontierfree"):
		return xaiTierFree
	default:
		return ""
	}
}

func normalizeXAITierText(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	var builder strings.Builder
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			builder.WriteRune(r)
		}
	}
	return builder.String()
}

func xaiTierRank(tier string) int {
	switch tier {
	case xaiTierHeavy:
		return 3
	case xaiTierSuper:
		return 2
	case xaiTierFree:
		return 1
	default:
		return 0
	}
}
