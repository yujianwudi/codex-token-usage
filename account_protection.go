package main

import (
	"context"
	"database/sql"
	"strings"
	"sync"
	"time"
)

type accountProtectionManager struct {
	mu     sync.RWMutex
	pickMu contextMutex
	cfg    pluginConfig

	usageMu       contextMutex
	usageDB       *sql.DB
	usageSince    int64
	usageLoadedAt time.Time
	usage         []protectionUsageSample
}

// contextMutex is a zero-value-ready binary semaphore. Unlike sync.Mutex, a
// scheduler request waiting behind another protection transaction can stop as
// soon as its context is canceled.
type contextMutex struct {
	once sync.Once
	gate chan struct{}
}

func (m *contextMutex) lock(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.once.Do(func() {
		m.gate = make(chan struct{}, 1)
	})
	select {
	case m.gate <- struct{}{}:
		if err := ctx.Err(); err != nil {
			<-m.gate
			return err
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (m *contextMutex) unlock() {
	<-m.gate
}

var globalAccountProtection accountProtectionManager

type protectionCandidate struct {
	Candidate schedulerAuthCandidate
	Aliases   []string
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

func schedulerCandidatePlan(candidate schedulerAuthCandidate, aliases []string, configuredPlans map[string]string) string {
	plan := firstNonEmptyString(
		candidate.Attributes["plan_type"], candidate.Attributes["plan"],
		stringFromAny(candidate.Metadata["plan_type"]), stringFromAny(candidate.Metadata["plan"]),
	)
	if plan != "" {
		return normalizedProtectionPlan(plan)
	}
	for _, alias := range aliases {
		if plan := configuredPlans[normalizeAccountAlias(alias)]; plan != "" {
			return plan
		}
	}
	return "plus"
}

func configuredProtectionPlanIndex(configured []configuredAccount) map[string]string {
	aliases := make([][]string, len(configured))
	counts := make(map[string]int, len(configured)*5)
	for i := range configured {
		aliases[i] = configuredAliases(configured[i])
		for _, alias := range aliases[i] {
			counts[alias]++
		}
	}
	out := make(map[string]string, len(counts))
	for i := range configured {
		plan := normalizedProtectionPlan(configured[i].PlanType)
		for _, alias := range aliases[i] {
			if counts[alias] == 1 {
				out[alias] = plan
			}
		}
	}
	return out
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

func protectionCandidateFor(candidate schedulerAuthCandidate, cfg pluginConfig, configuredPlans map[string]string, aliases []string) protectionCandidate {
	identity := schedulerCandidateIdentity(candidate)
	if identity.AuthIndex == "" {
		identity.AuthIndex = identity.AuthID
	}
	if len(aliases) == 0 {
		aliases = schedulerCandidateAliases(candidate)
	}
	plan := schedulerCandidatePlan(candidate, aliases, configuredPlans)
	return protectionCandidate{
		Candidate: candidate,
		Aliases:   aliases,
		AuthID:    identity.AuthID,
		AuthIndex: identity.AuthIndex,
		Source:    identity.Source,
		PlanType:  plan,
		Limit:     protectionConcurrencyLimit(cfg, plan),
		Threshold: protectionTokenLimit(cfg, plan),
	}
}

func (s *store) pickProtectedAuth(ctx context.Context, db *sql.DB, candidates []schedulerAuthCandidate, cfg pluginConfig, rotationKey string) (schedulerAuthCandidate, error) {
	// File discovery and alias construction do not participate in reservation
	// consistency. Keep them outside the serialized transaction.
	configuredPlans := configuredProtectionPlanIndex(readConfiguredAuthAccounts())
	aliasSets := protectionCandidateAliasSets(candidates)
	now := time.Now().Unix()
	// Token accounting is a soft-demotion signal and does not need to be in the
	// reservation critical section. This is the expensive scan on busy stores.
	usage, err := globalAccountProtection.loadUsageSnapshot(ctx, db, now-int64(cfg.AccountProtectionTokenWindowSeconds))
	if err != nil {
		return schedulerAuthCandidate{}, err
	}
	if err := globalAccountProtection.pickMu.lock(ctx); err != nil {
		return schedulerAuthCandidate{}, err
	}
	defer globalAccountProtection.pickMu.unlock()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return schedulerAuthCandidate{}, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `DELETE FROM account_protection_reservations WHERE expires_at <= ?`, now); err != nil {
		return schedulerAuthCandidate{}, err
	}
	reservations, err := loadProtectionReservationSnapshot(ctx, tx, now)
	if err != nil {
		return schedulerAuthCandidate{}, err
	}
	snapshot := newProtectionSnapshot(reservations, usage)
	states := make([]protectionCandidate, 0, len(candidates))
	for i, candidate := range candidates {
		state := protectionCandidateFor(candidate, cfg, configuredPlans, aliasSets[i])
		state.InFlight, state.Tokens = snapshot.metrics(state.Aliases)
		states = append(states, state)
	}
	chosen := chooseProtectedCandidate(states, rotationKey)
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

func chooseProtectedCandidate(states []protectionCandidate, rotationKey string) protectionCandidate {
	eligible := make([]protectionCandidate, 0, len(states))
	for _, state := range states {
		demoted := state.Threshold > 0 && state.Tokens >= state.Threshold
		if state.InFlight < state.Limit && !demoted {
			eligible = append(eligible, state)
		}
	}
	if len(eligible) > 0 {
		return rotateProtectedCandidate(eligible, rotationKey+"\x00normal")
	}
	for _, state := range states {
		if state.InFlight < state.Limit {
			eligible = append(eligible, state)
		}
	}
	if len(eligible) > 0 {
		return rotateProtectedCandidate(eligible, rotationKey+"\x00demoted")
	}
	minInFlight := states[0].InFlight
	for _, state := range states[1:] {
		if state.InFlight < minInFlight {
			minInFlight = state.InFlight
		}
	}
	for _, state := range states {
		if state.InFlight == minInFlight {
			eligible = append(eligible, state)
		}
	}
	return rotateProtectedCandidate(eligible, rotationKey+"\x00saturated")
}

func rotateProtectedCandidate(states []protectionCandidate, rotationKey string) protectionCandidate {
	candidates := make([]schedulerAuthCandidate, 0, len(states))
	byIdentity := make(map[string]protectionCandidate, len(states))
	for _, state := range states {
		candidate := state.Candidate
		identity := schedulerCandidateRotationIdentity(candidate)
		// Exact identity duplicates are operationally indistinguishable. Keep the
		// first one rather than introducing an input-position suffix.
		if _, exists := byIdentity[identity]; exists {
			continue
		}
		byIdentity[identity] = state
		candidates = append(candidates, candidate)
	}
	chosen := globalSchedulerRotation.pick(rotationKey, candidates)
	return byIdentity[schedulerCandidateRotationIdentity(chosen)]
}

func protectionCandidateAliasSets(candidates []schedulerAuthCandidate) [][]string {
	raw := make([][]string, len(candidates))
	counts := make(map[string]int, len(candidates)*5)
	for i := range candidates {
		raw[i] = schedulerCandidateAliases(candidates[i])
		for _, alias := range raw[i] {
			counts[alias]++
		}
	}
	out := make([][]string, len(candidates))
	for i := range candidates {
		authFile := firstNonEmptyString(
			candidates[i].Attributes["auth_file"],
			stringFromAny(candidates[i].Metadata["auth_file"]),
			candidates[i].Attributes["path"],
			stringFromAny(candidates[i].Metadata["path"]),
		)
		aliases := strictFileIdentityAliases(fileNameIfJSON(authFile))
		for _, alias := range raw[i] {
			if counts[alias] == 1 {
				aliases = append(aliases, alias)
			}
		}
		out[i] = uniqueNonEmptyAliases(aliases)
		if len(out[i]) == 0 {
			out[i] = raw[i]
		}
	}
	return out
}

type protectionRowsQueryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

type protectionUsageSample struct {
	Aliases []string
	Tokens  int64
}

func (m *accountProtectionManager) loadUsageSnapshot(ctx context.Context, db *sql.DB, since int64) ([]protectionUsageSample, error) {
	if err := m.usageMu.lock(ctx); err != nil {
		return nil, err
	}
	defer m.usageMu.unlock()
	if m.usageDB == db && m.usageSince == since && time.Since(m.usageLoadedAt) < 250*time.Millisecond {
		return m.usage, nil
	}
	usage, err := loadProtectionUsageSnapshot(ctx, db, since)
	if err != nil {
		return nil, err
	}
	m.usageDB = db
	m.usageSince = since
	m.usageLoadedAt = time.Now()
	m.usage = usage
	return usage, nil
}

type protectionReservationSample struct {
	Aliases []string
	Count   int
}

type protectionSnapshot struct {
	Reservations              []protectionReservationSample
	Usage                     []protectionUsageSample
	reservationSamplesByAlias map[string][]int
	usageSamplesByAlias       map[string][]int
	reservationMarks          []uint64
	usageMarks                []uint64
	metricGeneration          uint64
}

func loadProtectionSnapshot(ctx context.Context, db protectionRowsQueryer, since int64, now int64) (protectionSnapshot, error) {
	reservations, err := loadProtectionReservationSnapshot(ctx, db, now)
	if err != nil {
		return protectionSnapshot{}, err
	}
	usage, err := loadProtectionUsageSnapshot(ctx, db, since)
	if err != nil {
		return protectionSnapshot{}, err
	}
	return newProtectionSnapshot(reservations, usage), nil
}

func newProtectionSnapshot(reservations []protectionReservationSample, usage []protectionUsageSample) protectionSnapshot {
	snapshot := protectionSnapshot{
		Reservations:              reservations,
		Usage:                     usage,
		reservationSamplesByAlias: make(map[string][]int),
		usageSamplesByAlias:       make(map[string][]int),
		reservationMarks:          make([]uint64, len(reservations)),
		usageMarks:                make([]uint64, len(usage)),
	}
	for sampleIndex, reservation := range reservations {
		seen := make(map[string]struct{}, len(reservation.Aliases))
		for _, alias := range reservation.Aliases {
			if alias = normalizeAccountAlias(alias); alias != "" {
				if _, exists := seen[alias]; exists {
					continue
				}
				seen[alias] = struct{}{}
				snapshot.reservationSamplesByAlias[alias] = append(snapshot.reservationSamplesByAlias[alias], sampleIndex)
			}
		}
	}
	for sampleIndex, sample := range usage {
		seen := make(map[string]struct{}, len(sample.Aliases))
		for _, alias := range sample.Aliases {
			if alias = normalizeAccountAlias(alias); alias != "" {
				if _, exists := seen[alias]; exists {
					continue
				}
				seen[alias] = struct{}{}
				snapshot.usageSamplesByAlias[alias] = append(snapshot.usageSamplesByAlias[alias], sampleIndex)
			}
		}
	}
	return snapshot
}

func loadProtectionReservationSnapshot(ctx context.Context, db protectionRowsQueryer, now int64) ([]protectionReservationSample, error) {
	var snapshot []protectionReservationSample
	rows, err := db.QueryContext(ctx, `
SELECT auth_id, auth_index, source, COUNT(*)
FROM account_protection_reservations
WHERE expires_at > ?
GROUP BY auth_id, auth_index, source`, now)
	if err != nil {
		return snapshot, err
	}
	for rows.Next() {
		var authID, authIndex, source string
		var count int
		if err := rows.Scan(&authID, &authIndex, &source, &count); err != nil {
			_ = rows.Close()
			return snapshot, err
		}
		snapshot = append(snapshot, protectionReservationSample{
			Aliases: normalizeAccountAliases(authID, authIndex, source),
			Count:   count,
		})
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return snapshot, err
	}
	if err := rows.Close(); err != nil {
		return snapshot, err
	}
	return snapshot, nil
}

func loadProtectionUsageSnapshot(ctx context.Context, db protectionRowsQueryer, since int64) ([]protectionUsageSample, error) {
	var snapshot []protectionUsageSample
	rows, err := db.QueryContext(ctx, `
SELECT auth_id, auth_index, source, SUM(total_tokens)
FROM usage_events INDEXED BY idx_usage_events_provider_requested
WHERE provider IN ('codex','Codex','CODEX') AND requested_at >= ?
GROUP BY auth_id, auth_index, source`, since)
	if err != nil {
		return snapshot, err
	}
	defer rows.Close()
	for rows.Next() {
		var authID, authIndex, source string
		var tokens int64
		if err := rows.Scan(&authID, &authIndex, &source, &tokens); err != nil {
			return snapshot, err
		}
		if tokens <= 0 {
			continue
		}
		snapshot = append(snapshot, protectionUsageSample{
			Aliases: normalizeAccountAliases(authID, authIndex, source),
			Tokens:  tokens,
		})
	}
	return snapshot, rows.Err()
}

func (snapshot *protectionSnapshot) metrics(aliases []string) (int, int64) {
	if len(aliases) == 0 {
		return 0, 0
	}
	snapshot.metricGeneration++
	if snapshot.metricGeneration == 0 {
		// Overflow is practically unreachable, but clearing keeps zero available
		// as the never-seen marker and preserves correctness indefinitely.
		clear(snapshot.reservationMarks)
		clear(snapshot.usageMarks)
		snapshot.metricGeneration = 1
	}
	marker := snapshot.metricGeneration
	inFlight := 0
	var tokens int64
	for _, alias := range aliases {
		alias = normalizeAccountAlias(alias)
		if alias == "" {
			continue
		}
		for _, sampleIndex := range snapshot.reservationSamplesByAlias[alias] {
			if snapshot.reservationMarks[sampleIndex] == marker {
				continue
			}
			snapshot.reservationMarks[sampleIndex] = marker
			inFlight += snapshot.Reservations[sampleIndex].Count
		}
		for _, sampleIndex := range snapshot.usageSamplesByAlias[alias] {
			if snapshot.usageMarks[sampleIndex] == marker {
				continue
			}
			snapshot.usageMarks[sampleIndex] = marker
			tokens += snapshot.Usage[sampleIndex].Tokens
		}
	}
	return inFlight, tokens
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
	recordAliases := normalizeAccountAliases(rec.AuthID, rec.AuthIndex, rec.Source, rec.AuthFile)
	var matchIDs []int64
	for rows.Next() {
		var id int64
		var authID, authIndex, source string
		if err := rows.Scan(&id, &authID, &authIndex, &source); err != nil {
			_ = rows.Close()
			return err
		}
		if !aliasesOverlap(recordAliases, normalizeAccountAliases(authID, authIndex, source)) {
			continue
		}
		matchIDs = append(matchIDs, id)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	_, err = deleteFirstProtectionReservation(ctx, db, matchIDs)
	return err
}

// deleteFirstProtectionReservation conditionally deletes one reservation from
// a snapshot of matching IDs. Concurrent usage callbacks may select the same
// oldest row; RowsAffected lets the loser advance to the next row instead of
// reporting success while leaving a reservation behind.
func deleteFirstProtectionReservation(ctx context.Context, db *sql.DB, matchIDs []int64) (bool, error) {
	for _, id := range matchIDs {
		result, err := db.ExecContext(ctx, `DELETE FROM account_protection_reservations WHERE id=?`, id)
		if err != nil {
			return false, err
		}
		affected, err := result.RowsAffected()
		if err != nil {
			return false, err
		}
		if affected > 0 {
			return true, nil
		}
	}
	return false, nil
}

func applyAccountProtectionState(ctx context.Context, db *sql.DB, accounts []accountRow) {
	cfg := globalAccountProtection.config()
	if !cfg.AccountProtectionEnabled {
		return
	}
	now := time.Now().Unix()
	_, _ = db.ExecContext(ctx, `DELETE FROM account_protection_reservations WHERE expires_at <= ?`, now)
	candidates := make([]schedulerAuthCandidate, len(accounts))
	for i := range accounts {
		account := &accounts[i]
		candidates[i] = schedulerAuthCandidate{
			ID:       firstNonEmptyString(account.AuthID, account.AuthIndex, account.Source),
			Provider: account.Provider,
			Attributes: map[string]string{
				"auth_index": account.AuthIndex,
				"source":     account.Source,
				"auth_file":  account.AuthFile,
				"plan_type":  account.PlanType,
			},
		}
	}
	snapshot, err := loadProtectionSnapshot(ctx, db, now-int64(cfg.AccountProtectionTokenWindowSeconds), now)
	if err != nil {
		return
	}
	aliasSets := protectionCandidateAliasSets(candidates)
	for i := range accounts {
		account := &accounts[i]
		state := protectionCandidateFor(candidates[i], cfg, nil, aliasSets[i])
		inFlight, tokens := snapshot.metrics(state.Aliases)
		account.ProtectionPlan = state.PlanType
		account.ProtectionInFlight = inFlight
		account.ProtectionConcurrencyLimit = state.Limit
		account.ProtectionWindowTokens = tokens
		account.ProtectionTokenLimit = state.Threshold
		account.ProtectionTokenDemoted = state.Threshold > 0 && tokens >= state.Threshold
	}
}
