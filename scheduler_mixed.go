package main

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"strings"
	"time"
)

// isMixedSchedulerRequest recognizes the host contract for provider=mixed:
// Provider is empty, Providers contains every eligible provider, and Candidates
// may contain auths from more than one provider.
func isMixedSchedulerRequest(req schedulerPickRequest) bool {
	if req.filter != nil {
		return req.filter.mixed()
	}
	provider := strings.TrimSpace(req.Provider)
	if provider != "" && !strings.EqualFold(provider, "mixed") {
		return false
	}
	firstProvider := ""
	add := func(value string) bool {
		value = strings.TrimSpace(value)
		if value == "" || strings.EqualFold(value, "mixed") {
			return false
		}
		if firstProvider == "" {
			firstProvider = value
			return false
		}
		return !strings.EqualFold(firstProvider, value)
	}
	for _, value := range req.Providers {
		if add(value) {
			return true
		}
	}
	return false
}

func (s *store) pickMixedAuthOnce(ctx context.Context, req schedulerPickRequest) (schedulerPickResponse, error) {
	if len(req.Candidates) == 0 {
		return schedulerPickResponse{Handled: false}, nil
	}

	hasCodex := false
	hasXAI := false
	for _, candidate := range req.Candidates {
		switch strings.ToLower(strings.TrimSpace(candidate.Provider)) {
		case "codex":
			hasCodex = true
		case "xai":
			hasXAI = true
		}
	}
	if !hasCodex && !hasXAI {
		if req.filter != nil && req.filter.forceHandle() {
			chosen := pickSchedulerCandidate(schedulerRotationKey(req, "mixed"), schedulerAffinityKey(req, "mixed"), req.Candidates)
			return schedulerPickResponse{AuthID: chosen.ID, Handled: true}, nil
		}
		return schedulerPickResponse{Handled: false}, nil
	}

	protectionCfg := globalAccountProtection.config()
	protectCodex := hasCodex && protectionCfg.AccountProtectionEnabled
	now := time.Now().Unix()
	var codexSnapshot *codexSchedulerSnapshot
	var xaiSnapshot *xaiSchedulerSnapshot
	var codexReady, xaiReady bool
	if s == globalStore {
		refreshNeeded := false
		if hasCodex {
			var stale bool
			codexSnapshot, stale, codexReady = globalSchedulerState.codexForPick(now)
			refreshNeeded = refreshNeeded || stale || !codexReady
		}
		if hasXAI {
			var stale bool
			xaiSnapshot, stale, xaiReady = globalSchedulerState.xaiForPick(now)
			refreshNeeded = refreshNeeded || stale || !xaiReady
		}
		if refreshNeeded {
			globalSchedulerStateRefresher.requestRefresh()
		}
	}

	var db *sql.DB
	openDB := func() (*sql.DB, error) {
		if db != nil {
			return db, nil
		}
		opened, _, err := s.open(ctx)
		if err != nil {
			return nil, err
		}
		db = opened
		return db, nil
	}

	if hasCodex && !codexReady {
		opened, err := openDB()
		if err != nil {
			return schedulerPickResponse{Handled: false}, err
		}
		generation := uint64(0)
		if s == globalStore {
			generation = globalSchedulerState.providerGeneration("codex")
		}
		bans, err := queryActiveAutobans(ctx, opened, providerCodex, now)
		if err != nil {
			return schedulerPickResponse{Handled: false}, err
		}
		invalids, err := queryActiveInvalidAuths(ctx, opened, providerCodex)
		if err != nil {
			return schedulerPickResponse{Handled: false}, err
		}
		codexSnapshot = newCodexSchedulerSnapshot(bans, invalids, now)
		if s == globalStore {
			var published bool
			codexSnapshot, published = globalSchedulerState.publishCodexOrCurrent(generation, codexSnapshot, now)
			if !published {
				return schedulerPickResponse{Handled: false}, errSchedulerStateChanged
			}
		}
	}

	if hasXAI && !xaiReady {
		opened, err := openDB()
		if err != nil {
			return schedulerPickResponse{Handled: false}, err
		}
		generation := uint64(0)
		if s == globalStore {
			generation = globalSchedulerState.providerGeneration("xai")
		}
		states, err := queryActiveXAIStates(ctx, opened, providerXAI, now)
		if err != nil {
			return schedulerPickResponse{Handled: false}, err
		}
		xaiSnapshot = newXAISchedulerSnapshot(states, now)
		if s == globalStore {
			var published bool
			xaiSnapshot, published = globalSchedulerState.publishXAIOrCurrent(generation, xaiSnapshot, now)
			if !published {
				return schedulerPickResponse{Handled: false}, errSchedulerStateChanged
			}
		}
	}

	available := make([]schedulerAuthCandidate, 0, len(req.Candidates))
	filteredCodex := 0
	filteredXAI := 0
	matchedCodexIndexes := map[int]bool{}
	for _, candidate := range req.Candidates {
		switch strings.ToLower(strings.TrimSpace(candidate.Provider)) {
		case "codex":
			if matched, indexes := codexSnapshot.matchIndexes(candidate); matched {
				filteredCodex++
				for _, index := range indexes {
					matchedCodexIndexes[index] = true
				}
				continue
			}
		case "xai":
			if xaiSnapshot.matches(candidate) {
				filteredXAI++
				continue
			}
		}
		available = append(available, candidate)
	}
	if filteredCodex > 0 {
		restrictionCount := len(codexSnapshot.restrictions)
		globalSchedulerDiagnostics.record(restrictionCount, filteredCodex, maxInt(0, restrictionCount-len(matchedCodexIndexes)))
	}
	filtered := filteredCodex+filteredXAI > 0
	if !filtered && !protectCodex && (req.filter == nil || !req.filter.forceHandle()) {
		return schedulerPickResponse{Handled: false}, nil
	}
	if len(available) == 0 {
		if req.filter != nil {
			if provider, reason, ok := firstQuarantinedProvider(req.filter.quarantinedProviders); ok {
				return schedulerPickResponse{}, newSchedulerPrivacyQuarantineError(provider, reason)
			}
		}
		return schedulerPickResponse{}, newNoAvailableMixedAuthError(codexSnapshot, xaiSnapshot, filteredCodex, filteredXAI, now)
	}

	rotationKey := schedulerRotationKey(req, "mixed")
	affinityKey := schedulerAffinityKey(req, "mixed")
	remaining := available
	var saturatedErr error
	for len(remaining) > 0 {
		eligible := highestPrioritySchedulerCandidates(remaining)
		chosen := pickSchedulerCandidate(rotationKey, affinityKey, eligible)
		if !protectCodex || canonicalProvider(chosen.Provider) != providerCodex {
			return schedulerPickResponse{AuthID: chosen.ID, Handled: true}, nil
		}
		codexEligible := make([]schedulerAuthCandidate, 0, len(eligible))
		for _, candidate := range eligible {
			if canonicalProvider(candidate.Provider) == providerCodex {
				codexEligible = append(codexEligible, candidate)
			}
		}
		opened, err := openDB()
		if err != nil {
			return schedulerPickResponse{Handled: false}, err
		}
		chosen, err = s.pickProtectedAuth(ctx, opened, codexEligible, protectionCfg, rotationKey+"\x00codex", affinityKey)
		if err == nil {
			return schedulerPickResponse{AuthID: chosen.ID, Handled: true}, nil
		}
		var reject *schedulerRejectError
		if !errors.As(err, &reject) || reject.Code != "account_protection_saturated" {
			return schedulerPickResponse{Handled: false}, err
		}
		saturatedErr = err

		// Capacity is authoritative only for the Codex candidates in this
		// highest-priority tier. Remove exactly that tier and re-evaluate the
		// remaining healthy candidates so a same-tier non-Codex candidate or a
		// lower-priority protected Codex candidate can still be selected safely.
		highestPriority := eligible[0].Priority
		next := make([]schedulerAuthCandidate, 0, len(remaining)-len(codexEligible))
		for _, candidate := range remaining {
			if canonicalProvider(candidate.Provider) == providerCodex && candidate.Priority == highestPriority {
				continue
			}
			next = append(next, candidate)
		}
		remaining = next
	}
	if saturatedErr != nil {
		return schedulerPickResponse{Handled: false}, saturatedErr
	}
	return schedulerPickResponse{Handled: false}, &schedulerRejectError{
		Code:       "auth_unavailable",
		Message:    "no healthy scheduler candidates remain",
		HTTPStatus: http.StatusServiceUnavailable,
	}
}

func newNoAvailableMixedAuthError(codex *codexSchedulerSnapshot, xai *xaiSchedulerSnapshot, filteredCodex, filteredXAI int, now int64) error {
	providers := make([]string, 0, 2)
	if filteredCodex > 0 {
		providers = append(providers, "Codex")
	}
	if filteredXAI > 0 {
		providers = append(providers, "xAI")
	}
	message := "no available mixed-provider auth candidates: all " + strings.Join(providers, " and ") + " candidates are unavailable by active credential or quota restrictions"
	earliest := int64(0)
	if codex != nil {
		earliest = earliestActiveBanReset(codex.restrictions, now)
	}
	if xai != nil {
		if resetAt := earliestXAIStateReset(xai.states, now); resetAt > 0 && (earliest == 0 || resetAt < earliest) {
			earliest = resetAt
		}
	}
	if earliest > 0 {
		message += "; earliest retry at " + unixTime(earliest)
	}
	return &schedulerRejectError{Code: "auth_unavailable", Message: message, HTTPStatus: http.StatusServiceUnavailable}
}
