package main

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"sync"
	"time"
)

// schedulerStateCache publishes immutable, identity-aware restriction
// snapshots. Healthy providers and providers with known restrictions can both
// stay off SQLite; only unknown or expired snapshots must be refreshed.
type schedulerStateCache struct {
	mu sync.RWMutex

	codexInitialized bool
	xaiInitialized   bool
	codexSnapshot    *codexSchedulerSnapshot
	xaiSnapshot      *xaiSchedulerSnapshot
	codexGeneration  uint64
	xaiGeneration    uint64
	codexPending     int
	xaiPending       int
}

type schedulerStateGeneration struct {
	codex uint64
	xai   uint64
}

// codexSchedulerSnapshot retains the rows needed for rejection messages and
// pre-indexes broad and file-strict aliases for candidate filtering. Once
// published, the snapshot and all of its maps/slices are immutable.
type codexSchedulerSnapshot struct {
	restrictions    []autobanRow
	broadByAlias    map[string][]int
	strictByAlias   map[string][]int
	earliestResetAt int64
	expiresAt       time.Time
}

// xaiSchedulerSnapshot is immutable after publication for the same reason.
type xaiSchedulerSnapshot struct {
	states          []xaiAccountStateRow
	broadByAlias    map[string][]int
	strictByAlias   map[string][]int
	earliestResetAt int64
	expiresAt       time.Time
}

const (
	schedulerRestrictedSnapshotTTL = 2 * time.Second
	schedulerHealthySnapshotTTL    = 30 * time.Second
	schedulerSnapshotStaleGrace    = 5 * time.Second
)

var globalSchedulerState schedulerStateCache

var errSchedulerStateChanged = errors.New("scheduler restriction state changed during refresh")

func newCodexSchedulerSnapshot(bans []autobanRow, invalids []invalidAuthRow, now int64) *codexSchedulerSnapshot {
	restrictions := mergeEffectiveAutobans(bans, invalids)
	snapshot := &codexSchedulerSnapshot{
		restrictions:  restrictions,
		broadByAlias:  make(map[string][]int, len(restrictions)*3),
		strictByAlias: make(map[string][]int, len(restrictions)*2),
	}
	for i := range restrictions {
		restriction := restrictions[i]
		if restriction.ResetAt > now && (snapshot.earliestResetAt == 0 || restriction.ResetAt < snapshot.earliestResetAt) {
			snapshot.earliestResetAt = restriction.ResetAt
		}
		aliases := normalizeAccountAliases(restriction.AuthID, restriction.AuthIndex, restriction.Source, restriction.AuthFile)
		index := snapshot.broadByAlias
		if strict := strictAuthStateAliasesForValues(restriction.AuthID, restriction.AuthIndex, restriction.Source, restriction.AuthFile); len(strict) > 0 {
			aliases = strict
			index = snapshot.strictByAlias
		}
		for _, alias := range aliases {
			index[alias] = append(index[alias], i)
		}
	}
	ttl := schedulerHealthySnapshotTTL
	if len(restrictions) > 0 {
		ttl = schedulerRestrictedSnapshotTTL
	}
	snapshot.expiresAt = time.Now().Add(ttl)
	return snapshot
}

func newXAISchedulerSnapshot(states []xaiAccountStateRow, now int64) *xaiSchedulerSnapshot {
	snapshot := &xaiSchedulerSnapshot{
		states:        states,
		broadByAlias:  make(map[string][]int, len(states)*3),
		strictByAlias: make(map[string][]int, len(states)*2),
	}
	for i := range states {
		state := states[i]
		if state.ResetAt > now && (snapshot.earliestResetAt == 0 || state.ResetAt < snapshot.earliestResetAt) {
			snapshot.earliestResetAt = state.ResetAt
		}
		aliases := xaiStateAliases(state)
		index := snapshot.broadByAlias
		strict := strictAuthStateAliasesForValues(state.AuthID, state.AuthIndex, state.Source, state.AuthFile)
		if stateKeyFile := fileNameIfJSON(state.StateKey); stateKeyFile != "" {
			strict = normalizeAccountAliases(append(strict, stateKeyFile)...)
		}
		if len(strict) > 0 {
			aliases = strict
			index = snapshot.strictByAlias
		}
		for _, alias := range aliases {
			index[alias] = append(index[alias], i)
		}
	}
	ttl := schedulerHealthySnapshotTTL
	if len(states) > 0 {
		ttl = schedulerRestrictedSnapshotTTL
	}
	snapshot.expiresAt = time.Now().Add(ttl)
	return snapshot
}

func (s *codexSchedulerSnapshot) empty() bool {
	return s == nil || len(s.restrictions) == 0
}

func (s *codexSchedulerSnapshot) matchIndexes(candidate schedulerAuthCandidate) (bool, []int) {
	if s == nil || len(s.restrictions) == 0 {
		return false, nil
	}
	var matched []int
	appendMatches := func(aliases []string, index map[string][]int) {
		for _, alias := range aliases {
			for _, restrictionIndex := range index[normalizeAccountAlias(alias)] {
				seen := false
				for _, matchedIndex := range matched {
					if matchedIndex == restrictionIndex {
						seen = true
						break
					}
				}
				if seen {
					continue
				}
				matched = append(matched, restrictionIndex)
			}
		}
	}
	appendMatches(schedulerCandidateAliases(candidate), s.broadByAlias)
	appendMatches(schedulerCandidateStrictAliases(candidate), s.strictByAlias)
	return len(matched) > 0, matched
}

func (s *xaiSchedulerSnapshot) matches(candidate schedulerAuthCandidate) bool {
	if s == nil || len(s.states) == 0 {
		return false
	}
	for _, alias := range schedulerCandidateAliases(candidate) {
		if len(s.broadByAlias[normalizeAccountAlias(alias)]) > 0 {
			return true
		}
	}
	for _, alias := range schedulerCandidateStrictAliases(candidate) {
		if len(s.strictByAlias[normalizeAccountAlias(alias)]) > 0 {
			return true
		}
	}
	return false
}

func (c *schedulerStateCache) invalidate() {
	c.mu.Lock()
	c.codexInitialized = false
	c.xaiInitialized = false
	c.codexSnapshot = nil
	c.xaiSnapshot = nil
	// Invalidate any refresh that started before this call. Otherwise a slow
	// database read can repopulate the cache after an open/query failure marked
	// it unknown.
	c.codexGeneration++
	c.xaiGeneration++
	c.mu.Unlock()
}

func (c *schedulerStateCache) invalidateProvider(provider string) {
	c.mu.Lock()
	changed := false
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "codex":
		c.codexInitialized = false
		c.codexSnapshot = nil
		c.codexGeneration++
		changed = true
	case "xai":
		c.xaiInitialized = false
		c.xaiSnapshot = nil
		c.xaiGeneration++
		changed = true
	}
	c.mu.Unlock()
	if changed && c == &globalSchedulerState {
		globalSchedulerStateRefresher.requestRefresh()
	}
}

// needsDatabase reports whether the provider lacks a usable identity snapshot.
// protectionEnabled still requires SQLite for reservation consistency, even
// when restriction filtering itself is fully cached.
func (c *schedulerStateCache) needsDatabase(provider string, protectionEnabled bool) bool {
	if protectionEnabled && strings.EqualFold(strings.TrimSpace(provider), "codex") {
		return true
	}
	now := time.Now().Unix()
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "codex":
		_, ok := c.codex(now)
		return !ok
	case "xai":
		_, ok := c.xai(now)
		return !ok
	default:
		return false
	}
}

func (c *schedulerStateCache) codex(now int64) (*codexSchedulerSnapshot, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if !c.codexInitialized || c.codexSnapshot == nil {
		return nil, false
	}
	if resetAt := c.codexSnapshot.earliestResetAt; resetAt > 0 && resetAt <= now {
		return nil, false
	}
	if !c.codexSnapshot.expiresAt.IsZero() && !time.Now().Before(c.codexSnapshot.expiresAt) {
		return nil, false
	}
	return c.codexSnapshot, true
}

// codexForPick returns an initialized immutable snapshot for a bounded grace
// period after its refresh TTL or earliest reset has elapsed. Callers serve
// that snapshot for the current pick and request a single background refresh.
// A real state mutation clears the snapshot through invalidateProvider, so
// unknown state remains fail-closed and is never treated as stale.
func (c *schedulerStateCache) codexForPick(now int64) (snapshot *codexSchedulerSnapshot, stale bool, ok bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if !c.codexInitialized || c.codexSnapshot == nil {
		return nil, false, false
	}
	snapshot = c.codexSnapshot
	stale, ok = schedulerSnapshotStaleState(snapshot.expiresAt, snapshot.earliestResetAt, now)
	if !ok {
		return nil, stale, false
	}
	return snapshot, stale, true
}

func (c *schedulerStateCache) xai(now int64) (*xaiSchedulerSnapshot, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if !c.xaiInitialized || c.xaiSnapshot == nil {
		return nil, false
	}
	if resetAt := c.xaiSnapshot.earliestResetAt; resetAt > 0 && resetAt <= now {
		return nil, false
	}
	if !c.xaiSnapshot.expiresAt.IsZero() && !time.Now().Before(c.xaiSnapshot.expiresAt) {
		return nil, false
	}
	return c.xaiSnapshot, true
}

func (c *schedulerStateCache) xaiForPick(now int64) (snapshot *xaiSchedulerSnapshot, stale bool, ok bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if !c.xaiInitialized || c.xaiSnapshot == nil {
		return nil, false, false
	}
	snapshot = c.xaiSnapshot
	stale, ok = schedulerSnapshotStaleState(snapshot.expiresAt, snapshot.earliestResetAt, now)
	if !ok {
		return nil, stale, false
	}
	return snapshot, stale, true
}

// schedulerSnapshotStaleState permits a short stale-while-revalidate window
// so normal TTL renewal never blocks a pick. If the single background worker
// is stuck beyond that bounded grace period, picks return to the fail-closed
// database path instead of trusting an old healthy snapshot indefinitely.
func schedulerSnapshotStaleState(expiresAt time.Time, earliestResetAt, now int64) (stale, usable bool) {
	observedAt := time.Now()
	logicalNow := time.Unix(now, 0)
	if logicalNow.After(observedAt) {
		observedAt = logicalNow
	}
	var staleSince time.Time
	if earliestResetAt > 0 && earliestResetAt <= now {
		staleSince = time.Unix(earliestResetAt, 0)
	}
	if !expiresAt.IsZero() && !observedAt.Before(expiresAt) && (staleSince.IsZero() || expiresAt.Before(staleSince)) {
		staleSince = expiresAt
	}
	if staleSince.IsZero() {
		return false, true
	}
	return true, observedAt.Sub(staleSince) <= schedulerSnapshotStaleGrace
}

func (c *schedulerStateCache) generations() schedulerStateGeneration {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return schedulerStateGeneration{
		codex: c.codexGeneration,
		xai:   c.xaiGeneration,
	}
}

func (c *schedulerStateCache) beginRefresh() schedulerStateGeneration {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.codexGeneration++
	c.xaiGeneration++
	return schedulerStateGeneration{codex: c.codexGeneration, xai: c.xaiGeneration}
}

func (c *schedulerStateCache) providerGeneration(provider string) uint64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "codex":
		return c.codexGeneration
	case "xai":
		return c.xaiGeneration
	default:
		return 0
	}
}

func (c *schedulerStateCache) publishCodexIfGeneration(generation uint64, snapshot *codexSchedulerSnapshot) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.codexGeneration != generation || c.codexPending > 0 {
		return false
	}
	c.codexGeneration++
	c.codexInitialized = true
	c.codexSnapshot = snapshot
	return true
}

func (c *schedulerStateCache) publishXAIIfGeneration(generation uint64, snapshot *xaiSchedulerSnapshot) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.xaiGeneration != generation || c.xaiPending > 0 {
		return false
	}
	c.xaiGeneration++
	c.xaiInitialized = true
	c.xaiSnapshot = snapshot
	return true
}

// publishCodexOrCurrent resolves benign refresh races without surfacing a
// scheduler error. If another reader published the same database generation
// first, its immutable snapshot is equally fresh and safe to use. A genuine
// intervening restriction mutation leaves the cache unknown and still fails
// closed.
func (c *schedulerStateCache) publishCodexOrCurrent(generation uint64, snapshot *codexSchedulerSnapshot, now int64) (*codexSchedulerSnapshot, bool) {
	if c.publishCodexIfGeneration(generation, snapshot) {
		return snapshot, true
	}
	return c.codex(now)
}

func (c *schedulerStateCache) publishXAIOrCurrent(generation uint64, snapshot *xaiSchedulerSnapshot, now int64) (*xaiSchedulerSnapshot, bool) {
	if c.publishXAIIfGeneration(generation, snapshot) {
		return snapshot, true
	}
	return c.xai(now)
}

// clearRestrictedIfGeneration publishes an empty database result only when no
// newer restriction event was recorded after the caller began its query.
func (c *schedulerStateCache) clearRestrictedIfGeneration(provider string, generation uint64) bool {
	now := time.Now().Unix()
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "codex":
		return c.publishCodexIfGeneration(generation, newCodexSchedulerSnapshot(nil, nil, now))
	case "xai":
		return c.publishXAIIfGeneration(generation, newXAISchedulerSnapshot(nil, now))
	default:
		return false
	}
}

func (c *schedulerStateCache) applySnapshotRefresh(
	generation schedulerStateGeneration,
	codex *codexSchedulerSnapshot,
	xai *xaiSchedulerSnapshot,
) {
	c.mu.Lock()
	defer c.mu.Unlock()
	// Restriction writes and invalidation are authoritative. Providers are
	// committed independently so activity on one provider cannot suppress the
	// other provider's fresh database snapshot.
	if c.codexGeneration == generation.codex && c.codexPending == 0 {
		c.codexInitialized = true
		c.codexSnapshot = codex
	}
	if c.xaiGeneration == generation.xai && c.xaiPending == 0 {
		c.xaiInitialized = true
		c.xaiSnapshot = xai
	}
}

// applyRefresh keeps the generation-only state transition used by older
// callers and tests. A restricted boolean does not contain enough identity
// information to filter safely, so it deliberately publishes an unknown
// provider state that must be populated from SQLite before scheduling.
func (c *schedulerStateCache) applyRefresh(
	generation schedulerStateGeneration,
	codexRestricted bool,
	codexResetAt int64,
	xaiRestricted bool,
	xaiResetAt int64,
) {
	now := time.Now().Unix()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.codexGeneration == generation.codex && c.codexPending == 0 {
		if codexRestricted {
			c.codexInitialized = false
			c.codexSnapshot = nil
		} else {
			c.codexInitialized = true
			c.codexSnapshot = newCodexSchedulerSnapshot(nil, nil, now)
		}
	}
	if c.xaiGeneration == generation.xai && c.xaiPending == 0 {
		if xaiRestricted {
			c.xaiInitialized = false
			c.xaiSnapshot = nil
		} else {
			c.xaiInitialized = true
			c.xaiSnapshot = newXAISchedulerSnapshot(nil, now)
		}
	}
}

func (c *schedulerStateCache) refresh(ctx context.Context, db *sql.DB) error {
	generation := c.beginRefresh()
	now := time.Now().Unix()
	bans, err := queryActiveAutobans(ctx, db, providerCodex, now)
	if err != nil {
		return err
	}
	invalids, err := queryActiveInvalidAuths(ctx, db, providerCodex)
	if err != nil {
		return err
	}
	states, err := queryActiveXAIStates(ctx, db, providerXAI, now)
	if err != nil {
		return err
	}
	c.applySnapshotRefresh(
		generation,
		newCodexSchedulerSnapshot(bans, invalids, now),
		newXAISchedulerSnapshot(states, now),
	)
	return nil
}

// setRestricted is an event notification, not a complete identity snapshot.
// A newly recorded restriction therefore makes the provider unknown until one
// database refresh has captured the exact affected identity. Clearing is safe
// to publish directly as an empty snapshot.
func (c *schedulerStateCache) setRestricted(provider string, restricted bool) {
	if restricted {
		c.invalidateProvider(provider)
		return
	}
	now := time.Now().Unix()
	c.mu.Lock()
	defer c.mu.Unlock()
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "codex":
		if c.codexPending > 0 {
			return
		}
		c.codexGeneration++
		c.codexInitialized = true
		c.codexSnapshot = newCodexSchedulerSnapshot(nil, nil, now)
	case "xai":
		if c.xaiPending > 0 {
			return
		}
		c.xaiGeneration++
		c.xaiInitialized = true
		c.xaiSnapshot = newXAISchedulerSnapshot(nil, now)
	}
}

// beginRestrictionWrite makes a provider fail closed before a durable
// restriction row is written. Without the pending marker, a concurrent
// scheduler refresh can publish an empty snapshot between the SQL commit and
// the writer's post-commit invalidation.
func (c *schedulerStateCache) beginRestrictionWrite(provider string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "codex":
		c.codexGeneration++
		c.codexPending++
		c.codexInitialized = false
		c.codexSnapshot = nil
	case "xai":
		c.xaiGeneration++
		c.xaiPending++
		c.xaiInitialized = false
		c.xaiSnapshot = nil
	}
}

// finishRestrictionWrite keeps the provider unknown until a fresh immutable
// snapshot has observed the committed row (or confirmed that a failed write
// changed nothing). Each completion advances the generation so a query that
// raced the write can never publish its older result.
func (c *schedulerStateCache) finishRestrictionWrite(provider string) {
	c.mu.Lock()
	changed := false
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "codex":
		if c.codexPending > 0 {
			c.codexPending--
		}
		c.codexGeneration++
		c.codexInitialized = false
		c.codexSnapshot = nil
		changed = true
	case "xai":
		if c.xaiPending > 0 {
			c.xaiPending--
		}
		c.xaiGeneration++
		c.xaiInitialized = false
		c.xaiSnapshot = nil
		changed = true
	}
	c.mu.Unlock()
	if changed && c == &globalSchedulerState {
		globalSchedulerStateRefresher.requestRefresh()
	}
}

func (s *store) refreshSchedulerState(ctx context.Context) error {
	db, _, err := s.open(ctx)
	if err != nil {
		return err
	}
	if err := globalSchedulerState.refresh(ctx, db); err != nil {
		return err
	}
	return nil
}

func resetSchedulerStateForTest() {
	globalSchedulerState = schedulerStateCache{}
}
