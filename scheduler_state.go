package main

import (
	"context"
	"database/sql"
	"strings"
	"sync"
	"time"
)

// schedulerStateCache lets the common, healthy-account path avoid SQLite.
// Unknown state deliberately falls back to the database so failures never
// disable account filtering.
type schedulerStateCache struct {
	mu               sync.RWMutex
	codexInitialized bool
	xaiInitialized   bool
	codexRestricted  bool
	xaiRestricted    bool
	codexResetAt     int64
	xaiResetAt       int64
	codexGeneration  uint64
	xaiGeneration    uint64
}

type schedulerStateGeneration struct {
	codex uint64
	xai   uint64
}

var globalSchedulerState schedulerStateCache

func (c *schedulerStateCache) invalidate() {
	c.mu.Lock()
	c.codexInitialized = false
	c.xaiInitialized = false
	// Invalidate any refresh that started before this call. Otherwise a slow
	// database read can repopulate the cache after an open/query failure marked
	// it unknown.
	c.codexGeneration++
	c.xaiGeneration++
	c.mu.Unlock()
}

func (c *schedulerStateCache) needsDatabase(provider string, protectionEnabled bool) bool {
	if protectionEnabled && strings.EqualFold(strings.TrimSpace(provider), "codex") {
		return true
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	now := time.Now().Unix()
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "codex":
		if !c.codexInitialized {
			return true
		}
		if c.codexRestricted && c.codexResetAt > 0 && c.codexResetAt <= now {
			return true
		}
		return c.codexRestricted
	case "xai":
		if !c.xaiInitialized {
			return true
		}
		if c.xaiRestricted && c.xaiResetAt > 0 && c.xaiResetAt <= now {
			return true
		}
		return c.xaiRestricted
	default:
		return false
	}
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

// clearRestrictedIfGeneration publishes an empty database result only when no
// newer restriction event was recorded after the caller began its query.
func (c *schedulerStateCache) clearRestrictedIfGeneration(provider string, generation uint64) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "codex":
		if c.codexGeneration != generation {
			return false
		}
		c.codexGeneration++
		c.codexInitialized = true
		c.codexRestricted = false
		c.codexResetAt = 0
		return true
	case "xai":
		if c.xaiGeneration != generation {
			return false
		}
		c.xaiGeneration++
		c.xaiInitialized = true
		c.xaiRestricted = false
		c.xaiResetAt = 0
		return true
	default:
		return false
	}
}

func (c *schedulerStateCache) applyRefresh(
	generation schedulerStateGeneration,
	codexRestricted bool,
	codexResetAt int64,
	xaiRestricted bool,
	xaiResetAt int64,
) {
	c.mu.Lock()
	defer c.mu.Unlock()
	// setRestricted and invalidate are authoritative writes. Only publish a
	// provider's database snapshot when no newer write happened while refresh
	// was querying SQLite. Providers are committed independently so activity on
	// one provider does not leave the other permanently uninitialized.
	if c.codexGeneration == generation.codex {
		c.codexInitialized = true
		c.codexRestricted = codexRestricted
		c.codexResetAt = codexResetAt
	}
	if c.xaiGeneration == generation.xai {
		c.xaiInitialized = true
		c.xaiRestricted = xaiRestricted
		c.xaiResetAt = xaiResetAt
	}
}

func (c *schedulerStateCache) refresh(ctx context.Context, db *sql.DB) error {
	generation := c.beginRefresh()
	now := time.Now().Unix()
	var activeBans, activeInvalids, activeXAI int
	var codexResetAt, xaiResetAt int64
	if err := db.QueryRowContext(ctx, `
SELECT COUNT(*), COALESCE(MIN(reset_at),0) FROM autoban_bans WHERE active=1 AND reset_at>?`, now).Scan(&activeBans, &codexResetAt); err != nil {
		return err
	}
	if err := db.QueryRowContext(ctx, `
SELECT COUNT(*) FROM invalid_auths WHERE active=1`).Scan(&activeInvalids); err != nil {
		return err
	}
	if err := db.QueryRowContext(ctx, `
SELECT COUNT(*), COALESCE(MIN(CASE WHEN reset_at>0 THEN reset_at END),0)
FROM xai_account_states WHERE active=1 AND (reset_at=0 OR reset_at>?)`, now).Scan(&activeXAI, &xaiResetAt); err != nil {
		return err
	}
	c.applyRefresh(
		generation,
		activeBans > 0 || activeInvalids > 0,
		codexResetAt,
		activeXAI > 0,
		xaiResetAt,
	)
	return nil
}

func (c *schedulerStateCache) setRestricted(provider string, restricted bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "codex":
		c.codexGeneration++
		c.codexInitialized = true
		c.codexRestricted = restricted
		if !restricted {
			c.codexResetAt = 0
		}
	case "xai":
		c.xaiGeneration++
		c.xaiInitialized = true
		c.xaiRestricted = restricted
		if !restricted {
			c.xaiResetAt = 0
		}
	}
}

func (s *store) refreshSchedulerState(ctx context.Context) error {
	db, _, err := s.open(ctx)
	if err != nil {
		globalSchedulerState.invalidate()
		return err
	}
	if err := globalSchedulerState.refresh(ctx, db); err != nil {
		globalSchedulerState.invalidate()
		return err
	}
	return nil
}

func resetSchedulerStateForTest() {
	globalSchedulerState = schedulerStateCache{}
}
