package main

import (
	"context"
	"database/sql"
	"sort"
	"strings"
	"sync"
	"time"
)

type accountProtectionManager struct {
	mu     sync.RWMutex
	pickMu sync.Mutex
	cfg    pluginConfig
}

var globalAccountProtection accountProtectionManager

type protectionCandidate struct {
	Candidate schedulerAuthCandidate
	AuthID    string
	AuthIndex string
	Source    string
	PlanType  string
	InFlight  int
	Limit     int
	Tokens    int64
	Threshold int64
}

func (m *accountProtectionManager) configure(cfg pluginConfig) {
	m.mu.Lock()
	m.cfg = cfg
	m.mu.Unlock()
}

func (m *accountProtectionManager) config() pluginConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cfg
}

func (m *accountProtectionManager) enabled() bool {
	return m.config().AccountProtectionEnabled
}

func normalizedProtectionPlan(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	switch {
	case strings.Contains(value, "pro"):
		return "pro"
	case strings.Contains(value, "team"):
		return "team"
	case strings.Contains(value, "k12"), strings.Contains(value, "edu"):
		return "k12"
	case strings.Contains(value, "free"), strings.Contains(value, "trial"):
		return "free"
	default:
		return "plus"
	}
}

func protectionConcurrencyLimit(cfg pluginConfig, plan string) int {
	switch normalizedProtectionPlan(plan) {
	case "free":
		return cfg.AccountProtectionFreeConcurrency
	case "k12":
		return cfg.AccountProtectionK12Concurrency
	case "team":
		return cfg.AccountProtectionTeamConcurrency
	case "pro":
		return cfg.AccountProtectionProConcurrency
	default:
		return cfg.AccountProtectionPlusConcurrency
	}
}

func protectionTokenLimit(cfg pluginConfig, plan string) int64 {
	switch normalizedProtectionPlan(plan) {
	case "free":
		return cfg.AccountProtectionFreeTokenLimit
	case "k12":
		return cfg.AccountProtectionK12TokenLimit
	case "team":
		return cfg.AccountProtectionTeamTokenLimit
	case "pro":
		return cfg.AccountProtectionProTokenLimit
	default:
		return cfg.AccountProtectionPlusTokenLimit
	}
}

func schedulerCandidateIdentity(candidate schedulerAuthCandidate) accountIdentity {
	return accountIdentity{
		AuthID:    strings.TrimSpace(candidate.ID),
		AuthIndex: firstNonEmptyString(candidate.Attributes["auth_index"], stringFromAny(candidate.Metadata["auth_index"])),
		Source:    firstNonEmptyString(candidate.Attributes["source"], stringFromAny(candidate.Metadata["source"])),
		AuthFile:  firstNonEmptyString(candidate.Attributes["auth_file"], stringFromAny(candidate.Metadata["auth_file"])),
	}
}

func schedulerCandidatePlan(candidate schedulerAuthCandidate) string {
	plan := firstNonEmptyString(
		candidate.Attributes["plan_type"], candidate.Attributes["plan"],
		stringFromAny(candidate.Metadata["plan_type"]), stringFromAny(candidate.Metadata["plan"]),
	)
	if plan != "" {
		return normalizedProtectionPlan(plan)
	}
	aliases := schedulerCandidateAliases(candidate)
	for _, account := range readConfiguredAuthAccounts() {
		if aliasesOverlap(aliases, configuredAliases(account)) {
			return normalizedProtectionPlan(account.PlanType)
		}
	}
	return "plus"
}

func aliasesOverlap(left, right []string) bool {
	set := make(map[string]struct{}, len(left))
	for _, value := range left {
		if value = normalizeAccountAlias(value); value != "" {
			set[value] = struct{}{}
		}
	}
	for _, value := range right {
		if value = normalizeAccountAlias(value); value != "" {
			if _, ok := set[value]; ok {
				return true
			}
		}
	}
	return false
}

func protectionCandidateFor(candidate schedulerAuthCandidate, cfg pluginConfig) protectionCandidate {
	identity := schedulerCandidateIdentity(candidate)
	if identity.AuthIndex == "" {
		identity.AuthIndex = identity.AuthID
	}
	plan := schedulerCandidatePlan(candidate)
	return protectionCandidate{
		Candidate: candidate,
		AuthID:    identity.AuthID,
		AuthIndex: identity.AuthIndex,
		Source:    identity.Source,
		PlanType:  plan,
		Limit:     protectionConcurrencyLimit(cfg, plan),
		Threshold: protectionTokenLimit(cfg, plan),
	}
}

func (s *store) pickProtectedAuth(ctx context.Context, db *sql.DB, candidates []schedulerAuthCandidate, cfg pluginConfig) (schedulerAuthCandidate, error) {
	globalAccountProtection.pickMu.Lock()
	defer globalAccountProtection.pickMu.Unlock()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return schedulerAuthCandidate{}, err
	}
	defer tx.Rollback()
	now := time.Now().Unix()
	if _, err = tx.ExecContext(ctx, `DELETE FROM account_protection_reservations WHERE expires_at <= ?`, now); err != nil {
		return schedulerAuthCandidate{}, err
	}
	states := make([]protectionCandidate, 0, len(candidates))
	for _, candidate := range candidates {
		state := protectionCandidateFor(candidate, cfg)
		state.InFlight, err = reservationCount(ctx, tx, state)
		if err != nil {
			return schedulerAuthCandidate{}, err
		}
		state.Tokens, err = rollingCandidateTokens(ctx, tx, state, now-int64(cfg.AccountProtectionTokenWindowSeconds))
		if err != nil {
			return schedulerAuthCandidate{}, err
		}
		states = append(states, state)
	}
	chosen := chooseProtectedCandidate(states)
	if _, err = tx.ExecContext(ctx, `
INSERT INTO account_protection_reservations (auth_id, auth_index, source, plan_type, created_at, expires_at)
VALUES (?, ?, ?, ?, ?, ?)`, chosen.AuthID, chosen.AuthIndex, chosen.Source, chosen.PlanType, now, now+int64(cfg.AccountProtectionReservationTTLSeconds)); err != nil {
		return schedulerAuthCandidate{}, err
	}
	if err = tx.Commit(); err != nil {
		return schedulerAuthCandidate{}, err
	}
	return chosen.Candidate, nil
}

func chooseProtectedCandidate(states []protectionCandidate) protectionCandidate {
	available := make([]protectionCandidate, 0, len(states))
	for _, state := range states {
		if state.InFlight < state.Limit {
			available = append(available, state)
		}
	}
	if len(available) > 0 {
		sort.SliceStable(available, func(i, j int) bool {
			return protectionPriorityLess(available[i], available[j], false)
		})
		return available[0]
	}
	sort.SliceStable(states, func(i, j int) bool {
		if states[i].InFlight != states[j].InFlight {
			return states[i].InFlight < states[j].InFlight
		}
		return protectionPriorityLess(states[i], states[j], true)
	})
	return states[0]
}

func protectionPriorityLess(left, right protectionCandidate, ignoreToken bool) bool {
	leftDemoted := !ignoreToken && left.Threshold > 0 && left.Tokens >= left.Threshold
	rightDemoted := !ignoreToken && right.Threshold > 0 && right.Tokens >= right.Threshold
	if leftDemoted != rightDemoted {
		return !leftDemoted
	}
	if left.Candidate.Priority != right.Candidate.Priority {
		return left.Candidate.Priority > right.Candidate.Priority
	}
	return left.Candidate.ID < right.Candidate.ID
}

type reservationQueryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func reservationCount(ctx context.Context, db reservationQueryer, state protectionCandidate) (int, error) {
	aliases := schedulerCandidateAliases(state.Candidate)
	if len(aliases) == 0 {
		aliases = normalizeAccountAliases(state.AuthID, state.AuthIndex, state.Source)
	}
	if len(aliases) == 0 {
		return 0, nil
	}
	args := make([]any, 0, len(aliases)*3)
	for _, column := range []string{"auth_id", "auth_index", "source"} {
		_ = column
		for _, alias := range aliases {
			args = append(args, alias)
		}
	}
	query := `SELECT COUNT(*) FROM account_protection_reservations WHERE lower(auth_id) IN (` + sqlPlaceholders(len(aliases)) + `)
OR lower(auth_index) IN (` + sqlPlaceholders(len(aliases)) + `)
OR lower(source) IN (` + sqlPlaceholders(len(aliases)) + `)`
	var count int
	err := db.QueryRowContext(ctx, query, args...).Scan(&count)
	return count, err
}

func rollingCandidateTokens(ctx context.Context, db reservationQueryer, state protectionCandidate, since int64) (int64, error) {
	aliases := schedulerCandidateAliases(state.Candidate)
	if len(aliases) == 0 {
		aliases = normalizeAccountAliases(state.AuthID, state.AuthIndex, state.Source)
	}
	if len(aliases) == 0 {
		return 0, nil
	}
	args := make([]any, 0, 1+len(aliases)*3)
	args = append(args, since)
	for range []string{"auth_id", "auth_index", "source"} {
		for _, alias := range aliases {
			args = append(args, alias)
		}
	}
	query := `SELECT COALESCE(SUM(total_tokens),0) FROM usage_events
WHERE requested_at >= ? AND lower(provider)='codex' AND (
lower(auth_id) IN (` + sqlPlaceholders(len(aliases)) + `) OR
lower(auth_index) IN (` + sqlPlaceholders(len(aliases)) + `) OR
lower(source) IN (` + sqlPlaceholders(len(aliases)) + `))`
	var tokens int64
	err := db.QueryRowContext(ctx, query, args...).Scan(&tokens)
	return tokens, err
}

func releaseProtectionReservation(ctx context.Context, db *sql.DB, rec usageRecord) error {
	if provider := strings.TrimSpace(rec.Provider); provider != "" && !strings.EqualFold(provider, "codex") {
		return nil
	}
	rows, err := db.QueryContext(ctx, `
SELECT id, auth_id, auth_index, source
FROM account_protection_reservations
WHERE expires_at > ?
ORDER BY created_at, id`, time.Now().Unix())
	if err != nil {
		return err
	}
	recordAliases := normalizeAccountAliases(rec.AuthID, rec.AuthIndex, rec.Source)
	var matchID int64
	for rows.Next() {
		var id int64
		var authID, authIndex, source string
		if err := rows.Scan(&id, &authID, &authIndex, &source); err != nil {
			return err
		}
		if !aliasesOverlap(recordAliases, normalizeAccountAliases(authID, authIndex, source)) {
			continue
		}
		matchID = id
		break
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if matchID == 0 {
		return nil
	}
	_, err = db.ExecContext(ctx, `DELETE FROM account_protection_reservations WHERE id=?`, matchID)
	return err
}

func applyAccountProtectionState(ctx context.Context, db *sql.DB, accounts []accountRow) {
	cfg := globalAccountProtection.config()
	if !cfg.AccountProtectionEnabled {
		return
	}
	now := time.Now().Unix()
	_, _ = db.ExecContext(ctx, `DELETE FROM account_protection_reservations WHERE expires_at <= ?`, now)
	for i := range accounts {
		account := &accounts[i]
		candidate := schedulerAuthCandidate{
			ID:       firstNonEmptyString(account.AuthID, account.AuthIndex, account.Source),
			Provider: account.Provider,
			Attributes: map[string]string{
				"auth_index": account.AuthIndex,
				"source":     account.Source,
				"auth_file":  account.AuthFile,
				"plan_type":  account.PlanType,
			},
		}
		state := protectionCandidateFor(candidate, cfg)
		inFlight, err := reservationCount(ctx, db, state)
		if err != nil {
			continue
		}
		tokens, err := rollingCandidateTokens(ctx, db, state, now-int64(cfg.AccountProtectionTokenWindowSeconds))
		if err != nil {
			continue
		}
		account.ProtectionPlan = state.PlanType
		account.ProtectionInFlight = inFlight
		account.ProtectionConcurrencyLimit = state.Limit
		account.ProtectionWindowTokens = tokens
		account.ProtectionTokenLimit = state.Threshold
		account.ProtectionTokenDemoted = state.Threshold > 0 && tokens >= state.Threshold
	}
}
