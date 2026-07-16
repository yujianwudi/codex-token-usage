package main

import (
	"net/http"
	"sort"
	"strings"
)

// schedulerRequestFilter is attached only to the immutable request copy used
// by the plugin. It records why the plugin must make an authoritative choice
// instead of delegating to the host with the original, unfiltered candidates.
type schedulerRequestFilter struct {
	allowed              map[string]struct{}
	allowedList          []string
	routeFiltered        int
	statusFiltered       int
	quarantinedProviders map[string]string
}

func (f *schedulerRequestFilter) forceHandle() bool {
	return f != nil && (f.routeFiltered > 0 || f.statusFiltered > 0 || len(f.quarantinedProviders) > 0)
}

func (f *schedulerRequestFilter) mixed() bool {
	return f != nil && len(f.allowed) > 1
}

func normalizeSchedulerProvider(value string) string {
	return canonicalProvider(value)
}

func schedulerCandidateActive(candidate schedulerAuthCandidate) bool {
	status := normalizeSchedulerProvider(candidate.Status)
	// Empty status is accepted for compatibility with older CPA payloads and
	// hand-written ABI fixtures. Any explicit non-active state is unavailable.
	return status == "" || status == "active"
}

func schedulerAllowedProviders(req schedulerPickRequest) (map[string]struct{}, []string, error) {
	routeProvider := normalizeSchedulerProvider(req.Provider)
	declared := make(map[string]struct{}, len(req.Providers))
	declaredList := make([]string, 0, len(req.Providers))
	for _, raw := range req.Providers {
		provider := normalizeSchedulerProvider(raw)
		if provider == "" || provider == "mixed" {
			continue
		}
		if _, exists := declared[provider]; exists {
			continue
		}
		declared[provider] = struct{}{}
		declaredList = append(declaredList, provider)
	}

	if routeProvider != "" && routeProvider != "mixed" {
		for provider := range declared {
			if provider != routeProvider {
				return nil, nil, &schedulerRejectError{
					Code:       "auth_unavailable",
					Message:    "scheduler route provider declarations conflict",
					HTTPStatus: http.StatusServiceUnavailable,
				}
			}
		}
		return map[string]struct{}{routeProvider: {}}, []string{routeProvider}, nil
	}

	if len(declared) == 0 {
		if len(req.Candidates) == 0 {
			return nil, nil, nil
		}
		return nil, nil, &schedulerRejectError{
			Code:       "auth_unavailable",
			Message:    "scheduler route does not declare an allowed provider",
			HTTPStatus: http.StatusServiceUnavailable,
		}
	}
	sort.Strings(declaredList)
	return declared, declaredList, nil
}

func (s *store) prepareSchedulerRequest(req schedulerPickRequest) (schedulerPickRequest, error) {
	allowed, allowedList, err := schedulerAllowedProviders(req)
	if err != nil || len(allowed) == 0 {
		return req, err
	}
	filter := &schedulerRequestFilter{
		allowed:     allowed,
		allowedList: append([]string(nil), allowedList...),
	}

	var quarantine *apiKeyPrivacyQuarantineSnapshot
	if s != nil {
		quarantine = s.privacyQuarantine.snapshot.Load()
	}
	filtered := make([]schedulerAuthCandidate, 0, len(req.Candidates))
	for _, candidate := range req.Candidates {
		provider := normalizeSchedulerProvider(candidate.Provider)
		if provider == "" {
			filter.routeFiltered++
			continue
		}
		if _, ok := allowed[provider]; !ok {
			filter.routeFiltered++
			continue
		}
		if !schedulerCandidateActive(candidate) {
			filter.statusFiltered++
			continue
		}
		if reason, quarantined := apiKeyPrivacyQuarantineReasonFromSnapshot(quarantine, provider); quarantined {
			if filter.quarantinedProviders == nil {
				filter.quarantinedProviders = make(map[string]string)
			}
			filter.quarantinedProviders[provider] = reason
			continue
		}
		candidate.Provider = provider
		filtered = append(filtered, candidate)
	}

	// A single-provider quarantine is authoritative even when a malformed host
	// payload contains no candidate for that provider.
	if len(allowed) == 1 {
		for provider := range allowed {
			if reason, quarantined := apiKeyPrivacyQuarantineReasonFromSnapshot(quarantine, provider); quarantined {
				return req, newSchedulerPrivacyQuarantineError(provider, reason)
			}
		}
	}

	if len(filtered) == 0 && len(req.Candidates) > 0 {
		if provider, reason, ok := firstQuarantinedProvider(filter.quarantinedProviders); ok {
			return req, newSchedulerPrivacyQuarantineError(provider, reason)
		}
		return req, &schedulerRejectError{
			Code:       "auth_unavailable",
			Message:    "no scheduler candidates remain after route and status validation",
			HTTPStatus: http.StatusServiceUnavailable,
		}
	}

	prepared := req
	prepared.Provider = normalizeSchedulerProvider(req.Provider)
	prepared.Providers = append([]string(nil), allowedList...)
	prepared.Candidates = filtered
	prepared.filter = filter
	return prepared, nil
}

func firstQuarantinedProvider(providers map[string]string) (string, string, bool) {
	if len(providers) == 0 {
		return "", "", false
	}
	keys := make([]string, 0, len(providers))
	for provider := range providers {
		keys = append(keys, provider)
	}
	sort.Strings(keys)
	provider := keys[0]
	return provider, providers[provider], true
}

func newSchedulerPrivacyQuarantineError(provider, reason string) error {
	provider = normalizeSchedulerProvider(provider)
	message := provider + ": provider privacy quarantine is active"
	if strings.TrimSpace(reason) != "" {
		message += "; " + strings.TrimSpace(reason)
	}
	message += "; restore the configured API key or explicitly release the legacy restriction"
	return &schedulerRejectError{
		Code:       "privacy_quarantine",
		Message:    message,
		HTTPStatus: http.StatusServiceUnavailable,
	}
}
