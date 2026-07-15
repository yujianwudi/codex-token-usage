package main

import (
	"sort"
	"strings"
	"sync"
)

// schedulerRotationManager mirrors CPA's built-in round-robin behavior for
// requests the plugin must handle itself after applying bans or protection.
// CPA builds scheduler candidates from a map, so their incoming slice order is
// not a usable rotation order.
type schedulerRotationManager struct {
	mu      sync.Mutex
	cursors map[string]uint64
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
	ordered := highestPrioritySchedulerCandidates(candidates)
	if len(ordered) == 0 {
		return schedulerAuthCandidate{}
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cursors == nil {
		m.cursors = make(map[string]uint64)
	}
	cursor := m.cursors[key]
	chosen := ordered[cursor%uint64(len(ordered))]
	m.cursors[key] = cursor + 1
	return chosen
}

func (m *schedulerRotationManager) reset() {
	m.mu.Lock()
	m.cursors = nil
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
