package main

import (
	"context"
	"database/sql"
	"net/http"
	"strings"
	"sync"
	"time"
)

type accountProtectionManager struct {
	planLifecycleMu sync.Mutex
	mu              sync.RWMutex
	pickMu          contextMutex
	cfg             pluginConfig
	plans           map[string]string

	plansLoadedAt       time.Time
	plansRefreshing     bool
	plansGeneration     uint64
	plansRefreshStarted uint64
	plansCtx            context.Context
	plansCancel         context.CancelFunc
	plansRefreshDone    <-chan struct{}
	plansLoader         func(context.Context) map[string]string

	reservationCleanupDB *sql.DB
	reservationCleanupAt int64

	usageMu          contextMutex
	usageCacheMu     sync.RWMutex
	usageDB          *sql.DB
	usageSince       int64
	usageLoadedAt    time.Time
	usage            *protectionUsageIndex
	usageRefreshing  bool
	usageGeneration  uint64
	usageCtx         context.Context
	usageCancel      context.CancelFunc
	usageRefreshDone <-chan struct{}
}

const (
	accountProtectionPlanRefreshInterval        = 30 * time.Second
	accountProtectionPlanRefreshStopTimeout     = 100 * time.Millisecond
	accountProtectionReservationCleanupInterval = 30 * time.Second
	accountProtectionUsageRefreshInterval       = 500 * time.Millisecond
	accountProtectionUsageMaxWindowAdvance      = 5 * time.Second
	accountProtectionUsageRefreshTimeout        = 2 * time.Second
	accountProtectionUsageRefreshStopTimeout    = 100 * time.Millisecond
)

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
	m.planLifecycleMu.Lock()
	defer m.planLifecycleMu.Unlock()
	m.stopPlanRefreshLocked()
	m.stopUsageRefreshLocked()

	// Auth-file discovery is intentionally a lifecycle/configuration cost. The
	// scheduler hot path only reads this immutable alias-to-plan snapshot.
	var plans map[string]string
	if cfg.AccountProtectionEnabled {
		plans = configuredProtectionPlanIndex(readConfiguredAuthAccounts())
	}
	var plansCtx context.Context
	var plansCancel context.CancelFunc
	var usageCtx context.Context
	var usageCancel context.CancelFunc
	if cfg.AccountProtectionEnabled {
		plansCtx, plansCancel = context.WithCancel(context.Background())
		usageCtx, usageCancel = context.WithCancel(context.Background())
	}
	m.mu.Lock()
	m.cfg = cfg
	m.plans = plans
	m.plansLoadedAt = time.Now()
	m.plansRefreshing = false
	m.plansGeneration++
	m.plansCtx = plansCtx
	m.plansCancel = plansCancel
	m.mu.Unlock()
	m.usageCacheMu.Lock()
	m.usageDB = nil
	m.usageSince = 0
	m.usageLoadedAt = time.Time{}
	m.usage = nil
	m.usageRefreshing = false
	m.usageGeneration++
	m.usageCtx = usageCtx
	m.usageCancel = usageCancel
	m.usageRefreshDone = nil
	m.usageCacheMu.Unlock()
}

func (m *accountProtectionManager) stop() {
	m.planLifecycleMu.Lock()
	defer m.planLifecycleMu.Unlock()
	m.stopPlanRefreshLocked()
	m.stopUsageRefreshLocked()
}

func (m *accountProtectionManager) stopPlanRefreshLocked() {
	m.mu.Lock()
	cancel := m.plansCancel
	done := m.plansRefreshDone
	m.plansCancel = nil
	m.plansCtx = nil
	m.plansRefreshDone = nil
	m.plansRefreshing = false
	// Invalidate any refresh that began before cancellation so it cannot publish
	// a filesystem snapshot after reconfiguration or plugin shutdown.
	m.plansGeneration++
	m.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if done == nil {
		return
	}
	// Filesystem discovery can enter an OS call that cannot be interrupted by a
	// Go context (for example, a stalled network mount). Give cooperative
	// loaders a short grace period to finish, but do not let shutdown or
	// reconfiguration wait forever. The generation checks in
	// refreshConfiguredPlans prevent an abandoned old generation from
	// publishing if it eventually returns.
	timer := time.NewTimer(accountProtectionPlanRefreshStopTimeout)
	defer timer.Stop()
	select {
	case <-done:
	case <-timer.C:
	}
}

func (m *accountProtectionManager) config() pluginConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cfg
}

func (m *accountProtectionManager) enabled() bool {
	return m.config().AccountProtectionEnabled
}

func (m *accountProtectionManager) configuredPlans() map[string]string {
	m.mu.Lock()
	plans := m.plans
	ctx := m.plansCtx
	if m.cfg.AccountProtectionEnabled && ctx != nil && ctx.Err() == nil && !m.plansRefreshing && time.Since(m.plansLoadedAt) >= accountProtectionPlanRefreshInterval {
		m.plansRefreshing = true
		m.plansRefreshStarted = m.plansGeneration
		generation := m.plansGeneration
		done := make(chan struct{})
		m.plansRefreshDone = done
		go m.refreshConfiguredPlans(ctx, generation, done)
	}
	m.mu.Unlock()
	return plans
}

func (m *accountProtectionManager) loadConfiguredPlans(ctx context.Context) map[string]string {
	m.mu.RLock()
	loader := m.plansLoader
	m.mu.RUnlock()
	if loader != nil {
		return loader(ctx)
	}
	if ctx.Err() != nil {
		return nil
	}
	plans := configuredProtectionPlanIndex(readConfiguredAuthAccounts())
	if ctx.Err() != nil {
		return nil
	}
	return plans
}

func (m *accountProtectionManager) refreshConfiguredPlans(ctx context.Context, generation uint64, done chan<- struct{}) {
	defer close(done)
	if ctx.Err() != nil {
		return
	}
	plans := m.loadConfiguredPlans(ctx)
	if ctx.Err() != nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if ctx.Err() != nil || m.plansCtx != ctx || m.plansGeneration != generation || m.plansRefreshStarted != generation {
		return
	}
	m.plans = plans
	m.plansLoadedAt = time.Now()
	m.plansRefreshing = false
	m.plansRefreshDone = nil
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
		AuthFile:  schedulerCandidateAuthFile(candidate),
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

func (s *store) pickProtectedAuth(ctx context.Context, db *sql.DB, candidates []schedulerAuthCandidate, cfg pluginConfig, rotationKey string, affinityKeys ...string) (schedulerAuthCandidate, error) {
	configuredPlans := globalAccountProtection.configuredPlans()
	aliasSets := protectionCandidateAliasSets(candidates)
	now := time.Now().Unix()
	// Token accounting is a soft-demotion signal and does not need to be in the
	// reservation critical section. This is the expensive scan on busy stores.
	usage, err := globalAccountProtection.loadUsageIndex(ctx, db, now-int64(cfg.AccountProtectionTokenWindowSeconds))
	if err != nil {
		return schedulerAuthCandidate{}, err
	}
	if err := globalAccountProtection.pickMu.lock(ctx); err != nil {
		return schedulerAuthCandidate{}, err
	}
	defer globalAccountProtection.pickMu.unlock()
	reservationDB, closeReservationDB, err := s.reservationTransactionDB(ctx, db)
	if err != nil {
		return schedulerAuthCandidate{}, err
	}
	defer closeReservationDB()
	lockStarted := time.Now()
	tx, err := reservationDB.BeginTx(ctx, nil)
	lockWait := time.Since(lockStarted)
	if err != nil {
		globalSchedulerDiagnostics.recordReservationTiming(lockWait, 0, err)
		return schedulerAuthCandidate{}, err
	}
	defer tx.Rollback()
	cleanupExpired := globalAccountProtection.reservationCleanupDB != db || now-globalAccountProtection.reservationCleanupAt >= int64(accountProtectionReservationCleanupInterval/time.Second)
	var expiredReservations int64
	if cleanupExpired {
		result, cleanupErr := tx.ExecContext(ctx, `DELETE FROM account_protection_reservations WHERE provider=? AND expires_at <= ?`, providerCodex, now)
		if cleanupErr != nil {
			globalSchedulerDiagnostics.recordReservationTiming(lockWait, 0, cleanupErr)
			return schedulerAuthCandidate{}, cleanupErr
		}
		if deleted, rowsErr := result.RowsAffected(); rowsErr == nil {
			expiredReservations = deleted
		}
	}
	reservations, err := loadProtectionReservationSnapshot(ctx, tx, providerCodex, now)
	if err != nil {
		globalSchedulerDiagnostics.recordReservationTiming(lockWait, 0, err)
		return schedulerAuthCandidate{}, err
	}
	snapshot := newProtectionSnapshotWithUsageIndex(reservations, usage)
	states := make([]protectionCandidate, 0, len(candidates))
	for i, candidate := range candidates {
		state := protectionCandidateFor(candidate, cfg, configuredPlans, aliasSets[i])
		state.InFlight, state.Tokens = snapshot.metrics(state.Aliases)
		states = append(states, state)
	}
	chosen, err := chooseProtectedCandidate(states, rotationKey, affinityKeys...)
	if err != nil {
		// A saturated decision is authoritative only after the IMMEDIATE
		// transaction commits. This also makes any expired-reservation cleanup
		// durable; a commit failure must override the semantic rejection and fail
		// closed as scheduler_unavailable.
		if commitErr := tx.Commit(); commitErr != nil {
			globalSchedulerDiagnostics.recordReservationTiming(lockWait, 0, commitErr)
			return schedulerAuthCandidate{}, commitErr
		}
		globalSchedulerDiagnostics.recordReservationTiming(lockWait, 0, nil)
		if cleanupExpired {
			globalSchedulerDiagnostics.recordExpiredReservations(expiredReservations)
			globalAccountProtection.reservationCleanupDB = db
			globalAccountProtection.reservationCleanupAt = now
		}
		return schedulerAuthCandidate{}, err
	}
	chosenIdentity := schedulerCandidateIdentity(chosen.Candidate)
	storedAuthID, storedAuthIndex, storedSource, storedAuthFile, err := privacySafeSchedulerIdentity(
		s.privacyDatabasePath(), chosen.Candidate, chosen.AuthID, chosen.AuthIndex, chosen.Source, chosenIdentity.AuthFile,
	)
	if err != nil {
		globalSchedulerDiagnostics.recordReservationTiming(lockWait, 0, err)
		return schedulerAuthCandidate{}, err
	}
	insertStarted := time.Now()
	if _, err = tx.ExecContext(ctx, `
INSERT INTO account_protection_reservations (provider, auth_id, auth_index, source, auth_file, plan_type, created_at, expires_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, providerCodex, storedAuthID, storedAuthIndex, storedSource, storedAuthFile, chosen.PlanType, now, now+int64(cfg.AccountProtectionReservationTTLSeconds)); err != nil {
		globalSchedulerDiagnostics.recordReservationTiming(lockWait, time.Since(insertStarted), err)
		return schedulerAuthCandidate{}, err
	}
	insertLatency := time.Since(insertStarted)
	// The successful INSERT while this IMMEDIATE transaction owns the writer
	// lock is the linearization point for the global concurrency decision.
	if err = tx.Commit(); err != nil {
		globalSchedulerDiagnostics.recordReservationTiming(lockWait, insertLatency, err)
		return schedulerAuthCandidate{}, err
	}
	globalSchedulerDiagnostics.recordReservationTiming(lockWait, insertLatency, nil)
	if cleanupExpired {
		globalSchedulerDiagnostics.recordExpiredReservations(expiredReservations)
		globalAccountProtection.reservationCleanupDB = db
		globalAccountProtection.reservationCleanupAt = now
	}
	return chosen.Candidate, nil
}

func chooseProtectedCandidate(states []protectionCandidate, rotationKey string, affinityKeys ...string) (protectionCandidate, error) {
	affinityKey := firstNonEmptyString(affinityKeys...)
	if bound, ok := boundProtectedCandidate(states, affinityKey); ok && bound.InFlight < bound.Limit {
		highestPriority, found := highestAvailableProtectionPriority(states)
		if !found || bound.Candidate.Priority == highestPriority {
			return bound, nil
		}
	}
	eligible := make([]protectionCandidate, 0, len(states))
	for _, state := range states {
		demoted := state.Threshold > 0 && state.Tokens >= state.Threshold
		if state.InFlight < state.Limit && !demoted {
			eligible = append(eligible, state)
		}
	}
	if len(eligible) > 0 {
		return rotateProtectedCandidate(eligible, rotationKey+"\x00normal", affinityKey), nil
	}
	for _, state := range states {
		if state.InFlight < state.Limit {
			eligible = append(eligible, state)
		}
	}
	if len(eligible) > 0 {
		return rotateProtectedCandidate(eligible, rotationKey+"\x00demoted", affinityKey), nil
	}
	return protectionCandidate{}, &schedulerRejectError{
		Code:       "account_protection_saturated",
		Message:    "all Codex auth candidates are at their configured concurrency limit; retry after an in-flight request completes",
		HTTPStatus: http.StatusServiceUnavailable,
	}
}

func highestAvailableProtectionPriority(states []protectionCandidate) (int, bool) {
	highest := 0
	found := false
	for _, state := range states {
		if state.InFlight >= state.Limit {
			continue
		}
		if !found || state.Candidate.Priority > highest {
			highest = state.Candidate.Priority
			found = true
		}
	}
	return highest, found
}

func (m *accountProtectionManager) stopUsageRefreshLocked() {
	m.usageCacheMu.Lock()
	cancel := m.usageCancel
	done := m.usageRefreshDone
	m.usageCancel = nil
	m.usageCtx = nil
	m.usageRefreshDone = nil
	m.usageRefreshing = false
	m.usageGeneration++
	m.usageDB = nil
	m.usageSince = 0
	m.usageLoadedAt = time.Time{}
	m.usage = nil
	m.usageCacheMu.Unlock()
	if cancel != nil {
		cancel()
	}
	if done == nil {
		return
	}
	timer := time.NewTimer(accountProtectionUsageRefreshStopTimeout)
	defer timer.Stop()
	select {
	case <-done:
	case <-timer.C:
	}
}

func boundProtectedCandidate(states []protectionCandidate, affinityKey string) (protectionCandidate, bool) {
	candidates, byIdentity := protectionSelectionCandidates(states)
	chosen, ok := globalSchedulerAffinity.pick(affinityKey, candidates)
	if !ok {
		return protectionCandidate{}, false
	}
	state, ok := byIdentity[schedulerCandidateRotationIdentity(chosen)]
	return state, ok
}

func rotateProtectedCandidate(states []protectionCandidate, rotationKey string, affinityKeys ...string) protectionCandidate {
	candidates, byIdentity := protectionSelectionCandidates(states)
	chosen := pickSchedulerCandidate(rotationKey, firstNonEmptyString(affinityKeys...), candidates)
	return byIdentity[schedulerCandidateRotationIdentity(chosen)]
}

func protectionSelectionCandidates(states []protectionCandidate) ([]schedulerAuthCandidate, map[string]protectionCandidate) {
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
	return candidates, byIdentity
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
		needsFilter := false
		for _, alias := range raw[i] {
			if counts[alias] > 1 {
				needsFilter = true
				break
			}
		}
		if !needsFilter {
			out[i] = raw[i]
			continue
		}
		aliases := strictFileIdentityAliases(schedulerCandidateAuthFile(candidates[i]))
		for _, alias := range raw[i] {
			if counts[alias] == 1 {
				seen := false
				for _, existing := range aliases {
					if existing == alias {
						seen = true
						break
					}
				}
				if !seen {
					aliases = append(aliases, alias)
				}
			}
		}
		out[i] = aliases
		if len(out[i]) == 0 {
			out[i] = raw[i]
		}
	}
	return out
}

type protectionRowsQueryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

type protectionReservationStore interface {
	protectionRowsQueryer
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

type protectionUsageSample struct {
	Aliases []string
	Tokens  int64
}

type protectionUsageIndex struct {
	samples        []protectionUsageSample
	samplesByAlias map[string][]int
}

func (m *accountProtectionManager) loadUsageSnapshot(ctx context.Context, db *sql.DB, since int64) ([]protectionUsageSample, error) {
	index, err := m.loadUsageIndex(ctx, db, since)
	if err != nil || index == nil {
		return nil, err
	}
	return index.samples, nil
}

func (m *accountProtectionManager) loadUsageIndex(_ context.Context, db *sql.DB, since int64) (*protectionUsageIndex, error) {
	now := time.Now()
	if usage, fresh, stale := m.cachedUsageIndex(db, since, now); fresh {
		return usage, nil
	} else if stale {
		m.startUsageRefresh(db, since, now)
		return usage, nil
	}
	// Token volume is a soft-demotion signal. An empty cold-start snapshot can
	// temporarily miss a demotion, but it cannot bypass the transactional hard
	// concurrency limit. Serving it immediately keeps SQLite aggregation out of
	// the first-token path while the exact window is loaded in the background.
	usage := m.seedUsageIndex(db, since)
	m.startUsageRefresh(db, since, now)
	return usage, nil
}

func (m *accountProtectionManager) cachedUsageIndex(db *sql.DB, since int64, now time.Time) (*protectionUsageIndex, bool, bool) {
	m.usageCacheMu.RLock()
	defer m.usageCacheMu.RUnlock()
	if m.usageDB != db || m.usage == nil || since < m.usageSince {
		return nil, false, false
	}
	maxAdvance := int64(accountProtectionUsageMaxWindowAdvance/time.Second) + 1
	age := now.Sub(m.usageLoadedAt)
	if age < 0 {
		age = 0
	}
	fresh := since-m.usageSince <= maxAdvance && age < accountProtectionUsageRefreshInterval
	return m.usage, fresh, true
}

func (m *accountProtectionManager) seedUsageIndex(db *sql.DB, since int64) *protectionUsageIndex {
	m.usageCacheMu.Lock()
	defer m.usageCacheMu.Unlock()
	if m.usageDB == db && m.usage != nil && since >= m.usageSince {
		return m.usage
	}
	usage := newProtectionUsageIndex(nil)
	m.usageDB = db
	m.usageSince = since
	m.usageLoadedAt = time.Time{}
	m.usage = usage
	return usage
}

func (m *accountProtectionManager) startUsageRefresh(db *sql.DB, since int64, now time.Time) bool {
	m.usageCacheMu.Lock()
	defer m.usageCacheMu.Unlock()
	if m.usageDB != db || m.usage == nil || since < m.usageSince {
		return false
	}
	maxAdvance := int64(accountProtectionUsageMaxWindowAdvance/time.Second) + 1
	if since-m.usageSince <= maxAdvance && now.Sub(m.usageLoadedAt) < accountProtectionUsageRefreshInterval {
		return true
	}
	if m.usageRefreshing {
		return true
	}
	ctx := m.usageCtx
	if ctx == nil || ctx.Err() != nil {
		return false
	}
	done := make(chan struct{})
	generation := m.usageGeneration
	cachedSince := m.usageSince
	m.usageRefreshing = true
	m.usageRefreshDone = done
	go m.refreshUsageIndex(ctx, generation, db, cachedSince, since, done)
	return true
}

func (m *accountProtectionManager) refreshUsageIndex(ctx context.Context, generation uint64, db *sql.DB, cachedSince, targetSince int64, done chan struct{}) {
	defer close(done)
	defer m.finishUsageRefresh(ctx, generation, done)
	refreshCtx, cancel := context.WithTimeout(ctx, accountProtectionUsageRefreshTimeout)
	defer cancel()
	if err := m.usageMu.lock(refreshCtx); err != nil {
		return
	}
	defer m.usageMu.unlock()
	if refreshCtx.Err() != nil || !m.usageRefreshCurrent(ctx, generation, done) {
		return
	}
	usage, err := loadProtectionUsageSnapshot(refreshCtx, db, targetSince)
	if err != nil || refreshCtx.Err() != nil {
		return
	}
	index := newProtectionUsageIndex(usage)
	m.usageCacheMu.Lock()
	// cachedSince describes the stale snapshot served while this worker loads
	// targetSince. Keep them separate: an advanced-window refresh may publish
	// only if no other request replaced the source cache in the meantime.
	if m.usageCtx == ctx && m.usageGeneration == generation && m.usageRefreshDone == done && m.usageDB == db && m.usageSince == cachedSince && ctx.Err() == nil {
		m.usageDB = db
		m.usageSince = targetSince
		m.usageLoadedAt = time.Now()
		m.usage = index
	}
	m.usageCacheMu.Unlock()
}

func (m *accountProtectionManager) usageRefreshCurrent(ctx context.Context, generation uint64, done <-chan struct{}) bool {
	m.usageCacheMu.RLock()
	defer m.usageCacheMu.RUnlock()
	return m.usageCtx == ctx && m.usageGeneration == generation && m.usageRefreshDone == done && ctx.Err() == nil
}

func (m *accountProtectionManager) finishUsageRefresh(ctx context.Context, generation uint64, done <-chan struct{}) {
	m.usageCacheMu.Lock()
	defer m.usageCacheMu.Unlock()
	if m.usageCtx == ctx && m.usageGeneration == generation && m.usageRefreshDone == done {
		m.usageRefreshing = false
		m.usageRefreshDone = nil
	}
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
	reservations, err := loadProtectionReservationSnapshot(ctx, db, providerCodex, now)
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
	return newProtectionSnapshotWithUsageIndex(reservations, newProtectionUsageIndex(usage))
}

func newProtectionUsageIndex(usage []protectionUsageSample) *protectionUsageIndex {
	index := &protectionUsageIndex{
		samples:        usage,
		samplesByAlias: make(map[string][]int),
	}
	for sampleIndex, sample := range usage {
		seen := make(map[string]struct{}, len(sample.Aliases))
		for _, alias := range sample.Aliases {
			if alias = normalizeAccountAlias(alias); alias != "" {
				if _, exists := seen[alias]; exists {
					continue
				}
				seen[alias] = struct{}{}
				index.samplesByAlias[alias] = append(index.samplesByAlias[alias], sampleIndex)
			}
		}
	}
	return index
}

func newProtectionSnapshotWithUsageIndex(reservations []protectionReservationSample, usage *protectionUsageIndex) protectionSnapshot {
	if usage == nil {
		usage = newProtectionUsageIndex(nil)
	}
	snapshot := protectionSnapshot{
		Reservations:              reservations,
		Usage:                     usage.samples,
		reservationSamplesByAlias: make(map[string][]int),
		usageSamplesByAlias:       usage.samplesByAlias,
		reservationMarks:          make([]uint64, len(reservations)),
		usageMarks:                make([]uint64, len(usage.samples)),
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
	return snapshot
}

func loadProtectionReservationSnapshot(ctx context.Context, db protectionRowsQueryer, provider string, now int64) ([]protectionReservationSample, error) {
	var snapshot []protectionReservationSample
	rows, err := db.QueryContext(ctx, `
SELECT auth_id, auth_index, source, auth_file, COUNT(*)
FROM account_protection_reservations
WHERE provider=? AND expires_at > ?
GROUP BY auth_id, auth_index, source, auth_file`, provider, now)
	if err != nil {
		return snapshot, err
	}
	for rows.Next() {
		var authID, authIndex, source, authFile string
		var count int
		if err := rows.Scan(&authID, &authIndex, &source, &authFile, &count); err != nil {
			_ = rows.Close()
			return snapshot, err
		}
		snapshot = append(snapshot, protectionReservationSample{
			Aliases: normalizeAccountAliases(authID, authIndex, source, authFile),
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
WHERE provider IN ('codex','Codex','CODEX') AND generate=1 AND requested_at >= ?
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

func releaseProtectionReservation(ctx context.Context, db protectionReservationStore, rec usageRecord) (bool, error) {
	provider := strings.ToLower(strings.TrimSpace(rec.Provider))
	if provider != "codex" {
		return false, nil
	}
	column, identity := protectionReservationReleaseIdentity(rec)
	if column == "" || identity == "" {
		return false, nil
	}
	rows, err := db.QueryContext(ctx, `
SELECT id
FROM account_protection_reservations
WHERE provider=? AND expires_at > ?
AND lower(`+column+`)=?
ORDER BY created_at, id`, provider, time.Now().Unix(), identity)
	if err != nil {
		return false, err
	}
	var matchIDs []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return false, err
		}
		matchIDs = append(matchIDs, id)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return false, err
	}
	if err := rows.Close(); err != nil {
		return false, err
	}
	return deleteFirstProtectionReservation(ctx, db, provider, matchIDs)
}

func protectionReservationReleaseIdentity(rec usageRecord) (string, string) {
	for _, value := range []string{rec.AuthFile, rec.AuthIndex, rec.AuthID, rec.Source} {
		if file := fileNameIfJSON(value); file != "" {
			return "auth_file", normalizeAccountAlias(file)
		}
	}
	for _, candidate := range []struct {
		column string
		value  string
	}{
		{column: "auth_index", value: rec.AuthIndex},
		{column: "auth_id", value: rec.AuthID},
		{column: "source", value: rec.Source},
	} {
		if identity := normalizeAccountAlias(candidate.value); identity != "" {
			return candidate.column, identity
		}
	}
	return "", ""
}

// deleteFirstProtectionReservation conditionally deletes one reservation from
// a snapshot of matching IDs. Concurrent usage callbacks may select the same
// oldest row; RowsAffected lets the loser advance to the next row instead of
// reporting success while leaving a reservation behind.
func deleteFirstProtectionReservation(ctx context.Context, db protectionReservationStore, provider string, matchIDs []int64) (bool, error) {
	for _, id := range matchIDs {
		result, err := db.ExecContext(ctx, `DELETE FROM account_protection_reservations WHERE id=? AND provider=?`, id, provider)
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
	_, _ = db.ExecContext(ctx, `DELETE FROM account_protection_reservations WHERE provider=? AND expires_at <= ?`, providerCodex, now)
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
