package main

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
	"strings"
	"sync"
)

const (
	schedulerRevisionCodexKey   = "scheduler_revision_codex"
	schedulerRevisionXAIKey     = "scheduler_revision_xai"
	schedulerRevisionPrivacyKey = "scheduler_revision_privacy"
	privacySnapshotMaxAttempts  = 8
)

type persistentSchedulerRevisions struct {
	Codex   int64
	XAI     int64
	Privacy int64
}

type persistentSchedulerRevisionState struct {
	mu               sync.Mutex
	privacyRefreshMu sync.Mutex
	initialized      bool
	observed         persistentSchedulerRevisions
}

func (s *persistentSchedulerRevisionState) reset(revisions persistentSchedulerRevisions) {
	s.mu.Lock()
	s.initialized = true
	s.observed = revisions
	s.mu.Unlock()
}

func (s *persistentSchedulerRevisionState) clear() {
	s.mu.Lock()
	s.initialized = false
	s.observed = persistentSchedulerRevisions{}
	s.mu.Unlock()
}

// reconcileProviders publishes provider invalidation before marking a
// revision as observed. The callback runs while s.mu is held so a concurrent
// picker cannot consume the same revision and continue with the old snapshot
// before the first picker has invalidated it.
func (s *persistentSchedulerRevisionState) reconcileProviders(revisions persistentSchedulerRevisions, invalidate func(string)) (privacyChanged bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.initialized {
		s.initialized = true
		s.observed = revisions
		return false
	}
	codexChanged := revisions.Codex != s.observed.Codex
	xaiChanged := revisions.XAI != s.observed.XAI
	privacyChanged = revisions.Privacy != s.observed.Privacy
	if invalidate != nil {
		if codexChanged {
			invalidate(providerCodex)
		}
		if xaiChanged {
			invalidate(providerXAI)
		}
	}
	s.observed.Codex = revisions.Codex
	s.observed.XAI = revisions.XAI
	return privacyChanged
}

func (s *persistentSchedulerRevisionState) privacyChanged(revision int64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return !s.initialized || revision != s.observed.Privacy
}

func (s *persistentSchedulerRevisionState) observePrivacy(revision int64) {
	s.mu.Lock()
	if s.initialized {
		s.observed.Privacy = revision
	}
	s.mu.Unlock()
}

func queryPersistentSchedulerRevisions(ctx context.Context, db *sql.DB) (persistentSchedulerRevisions, error) {
	rows, err := db.QueryContext(ctx, `
SELECT key,value
FROM store_state
WHERE key IN (?,?,?)`, schedulerRevisionCodexKey, schedulerRevisionXAIKey, schedulerRevisionPrivacyKey)
	if err != nil {
		return persistentSchedulerRevisions{}, err
	}
	defer rows.Close()
	var revisions persistentSchedulerRevisions
	seen := map[string]bool{}
	for rows.Next() {
		var key, raw string
		if err := rows.Scan(&key, &raw); err != nil {
			return persistentSchedulerRevisions{}, err
		}
		value, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
		if err != nil || value < 0 {
			return persistentSchedulerRevisions{}, fmt.Errorf("invalid persistent scheduler revision %s=%q", key, raw)
		}
		switch key {
		case schedulerRevisionCodexKey:
			revisions.Codex = value
			seen[key] = true
		case schedulerRevisionXAIKey:
			revisions.XAI = value
			seen[key] = true
		case schedulerRevisionPrivacyKey:
			revisions.Privacy = value
			seen[key] = true
		}
	}
	if err := rows.Err(); err != nil {
		return persistentSchedulerRevisions{}, err
	}
	for _, key := range []string{schedulerRevisionCodexKey, schedulerRevisionXAIKey, schedulerRevisionPrivacyKey} {
		if !seen[key] {
			return persistentSchedulerRevisions{}, fmt.Errorf("missing persistent scheduler revision %s", key)
		}
	}
	return revisions, nil
}

// stabilizePrivacySnapshot binds the in-memory quarantine snapshot to a
// privacy revision that remained unchanged for the complete refresh. If a
// different process commits a marker while refresh is reading, retry instead
// of marking the newer revision observed with an older snapshot.
func stabilizePrivacySnapshot(
	ctx context.Context,
	readRevisions func(context.Context) (persistentSchedulerRevisions, error),
	refresh func(context.Context) error,
) (persistentSchedulerRevisions, error) {
	if readRevisions == nil || refresh == nil {
		return persistentSchedulerRevisions{}, fmt.Errorf("stabilize API key privacy quarantine: missing revision reader or refresher")
	}
	for attempt := 0; attempt < privacySnapshotMaxAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return persistentSchedulerRevisions{}, err
		}
		before, err := readRevisions(ctx)
		if err != nil {
			return persistentSchedulerRevisions{}, err
		}
		if err := refresh(ctx); err != nil {
			return persistentSchedulerRevisions{}, err
		}
		after, err := readRevisions(ctx)
		if err != nil {
			return persistentSchedulerRevisions{}, err
		}
		if before.Privacy == after.Privacy {
			return after, nil
		}
	}
	return persistentSchedulerRevisions{}, fmt.Errorf("stabilize API key privacy quarantine: revision changed during %d refresh attempts", privacySnapshotMaxAttempts)
}

func (s *persistentSchedulerRevisionState) refreshStablePrivacySnapshot(
	ctx context.Context,
	readRevisions func(context.Context) (persistentSchedulerRevisions, error),
	refresh func(context.Context) error,
) (persistentSchedulerRevisions, error) {
	stable, err := stabilizePrivacySnapshot(ctx, readRevisions, refresh)
	if err != nil {
		return persistentSchedulerRevisions{}, err
	}
	s.observePrivacy(stable.Privacy)
	return stable, nil
}

// reconcilePersistentSchedulerRevisions is intentionally read-only and only
// uses an already-open database handle. Cached scheduler picks therefore keep
// working without reopening SQLite after store.close, while normal multi-
// process operation observes committed external mutations before selection.
func (s *store) reconcilePersistentSchedulerRevisions(ctx context.Context) error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	db, dbPath := s.db, s.dbPath
	s.mu.Unlock()
	if db == nil {
		return nil
	}
	revisions, err := queryPersistentSchedulerRevisions(ctx, db)
	if err != nil {
		return fmt.Errorf("read persistent scheduler revisions: %w", err)
	}
	var invalidate func(string)
	if s == globalStore {
		invalidate = globalSchedulerState.invalidateProvider
	}
	privacyChanged := s.providerRevisions.reconcileProviders(revisions, invalidate)
	if privacyChanged {
		// Serialize refreshes and re-read the revision after taking the lock. A
		// slower picker must not overwrite a newer quarantine snapshot and then
		// mark the newer revision as observed.
		s.providerRevisions.privacyRefreshMu.Lock()
		defer s.providerRevisions.privacyRefreshMu.Unlock()
		latest, err := queryPersistentSchedulerRevisions(ctx, db)
		if err != nil {
			return fmt.Errorf("re-read persistent scheduler revisions: %w", err)
		}
		if s.providerRevisions.privacyChanged(latest.Privacy) {
			if _, err := s.providerRevisions.refreshStablePrivacySnapshot(
				ctx,
				func(ctx context.Context) (persistentSchedulerRevisions, error) {
					return queryPersistentSchedulerRevisions(ctx, db)
				},
				func(ctx context.Context) error {
					return s.refreshAPIKeyPrivacyQuarantine(ctx, db, dbPath)
				},
			); err != nil {
				return fmt.Errorf("refresh API key privacy quarantine revision: %w", err)
			}
		}
	}
	return nil
}
