package main

import (
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	schedulerRotationMaxCursors = 1024
	schedulerRotationCursorTTL  = 30 * time.Minute
)

type schedulerRotationCursor struct {
	next     uint64
	lastUsed int64
}

type schedulerRotationChoice struct {
	candidate schedulerAuthCandidate
	identity  string
}

// schedulerRotationManager mirrors CPA's built-in round-robin behavior for
// requests the plugin must handle itself after applying bans or protection.
// CPA builds scheduler candidates from a map, so their incoming slice order is
// not a usable rotation order.
type schedulerRotationManager struct {
	mu         sync.Mutex
	cursors    map[string]schedulerRotationCursor
	operations uint64
}

var globalSchedulerRotation schedulerRotationManager

func schedulerRotationKey(req schedulerPickRequest, provider string) string {
	provider = strings.ToLower(strings.TrimSpace(provider))
	if provider == "" {
		provider = strings.ToLower(strings.TrimSpace(req.Provider))
	}
	return provider + "\x00" + strings.ToLower(strings.TrimSpace(req.Model))
}

func (m *schedulerRotationManager) pick(key string, candidates []schedulerAuthCandidate) schedulerAuthCandidate {
	ordered := highestPrioritySchedulerChoices(candidates)
	if len(ordered) == 0 {
		return schedulerAuthCandidate{}
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now().UnixNano()
	if m.cursors == nil {
		m.cursors = make(map[string]schedulerRotationCursor)
	}
	m.operations++
	cursor, exists := m.cursors[key]
	if !exists && len(m.cursors) >= schedulerRotationMaxCursors {
		m.pruneLocked(now, true)
	} else if m.operations%256 == 0 {
		m.pruneLocked(now, false)
	}
	chosen := ordered[cursor.next%uint64(len(ordered))].candidate
	cursor.next++
	cursor.lastUsed = now
	m.cursors[key] = cursor
	return chosen
}

func highestPrioritySchedulerChoices(candidates []schedulerAuthCandidate) []schedulerRotationChoice {
	if len(candidates) == 0 {
		return nil
	}
	highest := candidates[0].Priority
	for _, candidate := range candidates[1:] {
		if candidate.Priority > highest {
			highest = candidate.Priority
		}
	}
	ordered := make([]schedulerRotationChoice, 0, len(candidates))
	for _, candidate := range candidates {
		if candidate.Priority == highest {
			ordered = append(ordered, schedulerRotationChoice{
				candidate: candidate,
				identity:  schedulerCandidateRotationIdentity(candidate),
			})
		}
	}
	sort.SliceStable(ordered, func(i, j int) bool {
		return ordered[i].identity < ordered[j].identity
	})
	return ordered
}

func (m *schedulerRotationManager) pruneLocked(now int64, requireSpace bool) {
	expiresBefore := now - schedulerRotationCursorTTL.Nanoseconds()
	oldestKey := ""
	oldestUsed := int64(0)
	for key, cursor := range m.cursors {
		if cursor.lastUsed <= expiresBefore {
			delete(m.cursors, key)
			continue
		}
		if oldestKey == "" || cursor.lastUsed < oldestUsed {
			oldestKey = key
			oldestUsed = cursor.lastUsed
		}
	}
	if requireSpace && len(m.cursors) >= schedulerRotationMaxCursors && oldestKey != "" {
		delete(m.cursors, oldestKey)
	}
}

func (m *schedulerRotationManager) reset() {
	m.mu.Lock()
	m.cursors = nil
	m.operations = 0
	m.mu.Unlock()
}

func highestPrioritySchedulerCandidates(candidates []schedulerAuthCandidate) []schedulerAuthCandidate {
	if len(candidates) == 0 {
		return nil
	}
	highest := candidates[0].Priority
	for _, candidate := range candidates[1:] {
		if candidate.Priority > highest {
			highest = candidate.Priority
		}
	}
	ordered := make([]schedulerAuthCandidate, 0, len(candidates))
	for _, candidate := range candidates {
		if candidate.Priority == highest {
			ordered = append(ordered, candidate)
		}
	}
	sort.SliceStable(ordered, func(i, j int) bool {
		return schedulerCandidateRotationIdentity(ordered[i]) < schedulerCandidateRotationIdentity(ordered[j])
	})
	return ordered
}

// schedulerCandidateRotationIdentity distinguishes auth files that share the
// same CPA candidate ID. It intentionally uses only stable identity fields so
// map iteration/input order cannot change round-robin order.
func schedulerCandidateRotationIdentity(candidate schedulerAuthCandidate) string {
	return strings.Join([]string{
		normalizeAccountAlias(candidate.ID),
		normalizeAccountAlias(candidate.Provider),
		normalizeAccountAlias(firstNonEmptyString(candidate.Attributes["auth_index"], stringFromAny(candidate.Metadata["auth_index"]))),
		normalizeAccountAlias(firstNonEmptyString(candidate.Attributes["source"], stringFromAny(candidate.Metadata["source"]))),
		normalizeAccountAlias(firstNonEmptyString(
			candidate.Attributes["auth_file"],
			candidate.Attributes["path"],
			candidate.Attributes["file"],
			stringFromAny(candidate.Metadata["auth_file"]),
			stringFromAny(candidate.Metadata["path"]),
			stringFromAny(candidate.Metadata["file"]),
		)),
		normalizeAccountAlias(firstNonEmptyString(candidate.Attributes["email"], stringFromAny(candidate.Metadata["email"]))),
	}, "\x1f")
}
