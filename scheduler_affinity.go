package main

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	schedulerAffinityTTL         = time.Hour
	schedulerAffinityMaxBindings = 10_000
	schedulerAffinityEvictSample = 16
)

type schedulerAffinityBinding struct {
	CandidateIdentity string
	ExpiresAt         time.Time
}

type schedulerAffinityManager struct {
	mu       sync.Mutex
	bindings map[string]schedulerAffinityBinding
}

var globalSchedulerAffinity schedulerAffinityManager

const schedulerSelectionKeyPrefix = "scheduler-selection:v1:"

func schedulerSelectionKey(rotationKey, affinityKey string) string {
	base, existingAffinity := splitSchedulerSelectionKey(rotationKey)
	affinityKey = strings.TrimSpace(affinityKey)
	if affinityKey == "" {
		if existingAffinity != "" {
			return rotationKey
		}
		return base
	}
	return schedulerSelectionKeyPrefix + strconv.Itoa(len(base)) + ":" + base + affinityKey
}

func splitSchedulerSelectionKey(key string) (string, string) {
	if !strings.HasPrefix(key, schedulerSelectionKeyPrefix) {
		return key, ""
	}
	remainder := strings.TrimPrefix(key, schedulerSelectionKeyPrefix)
	separator := strings.IndexByte(remainder, ':')
	if separator <= 0 {
		return key, ""
	}
	baseLength, err := strconv.Atoi(remainder[:separator])
	if err != nil || baseLength < 0 {
		return key, ""
	}
	remainder = remainder[separator+1:]
	if baseLength > len(remainder) {
		return key, ""
	}
	base := remainder[:baseLength]
	affinityKey := strings.TrimSpace(remainder[baseLength:])
	if affinityKey == "" {
		return key, ""
	}
	return base, affinityKey
}

func schedulerAffinityKey(req schedulerPickRequest, provider string) string {
	sessionID := schedulerSessionID(req)
	if sessionID == "" {
		return ""
	}
	provider = strings.ToLower(strings.TrimSpace(firstNonEmptyString(provider, req.Provider)))
	model := strings.ToLower(strings.TrimSpace(req.Model))
	digest := sha256.Sum256([]byte(sessionID))
	return provider + "\x00" + model + "\x00" + hex.EncodeToString(digest[:16])
}

func schedulerSessionID(req schedulerPickRequest) string {
	for _, item := range []struct {
		Prefix string
		Value  string
	}{
		{Prefix: "header:", Value: headerValue(req.Options.Headers, "X-Session-ID")},
		{Prefix: "codex:", Value: firstNonEmptyString(headerValue(req.Options.Headers, "Session-Id"), headerValue(req.Options.Headers, "Session_id"))},
		{Prefix: "clientreq:", Value: headerValue(req.Options.Headers, "X-Client-Request-Id")},
		{Prefix: "metadata:", Value: schedulerMetadataString(req.Options.Metadata, "session_id", "conversation_id", "user_id")},
	} {
		if value := strings.TrimSpace(item.Value); value != "" {
			return item.Prefix + value
		}
	}
	return ""
}

func schedulerMetadataString(metadata map[string]any, keys ...string) string {
	for _, key := range keys {
		for candidate, value := range metadata {
			if strings.EqualFold(strings.TrimSpace(candidate), key) {
				if text := strings.TrimSpace(stringFromAny(value)); text != "" {
					return text
				}
			}
		}
	}
	return ""
}

func pickSchedulerCandidate(rotationKey, affinityKey string, candidates []schedulerAuthCandidate) schedulerAuthCandidate {
	return globalSchedulerRotation.pick(schedulerSelectionKey(rotationKey, affinityKey), candidates)
}

func (m *schedulerAffinityManager) pickOrBind(key string, candidates []schedulerAuthCandidate, choose func() schedulerAuthCandidate) schedulerAuthCandidate {
	key = strings.TrimSpace(key)
	if key == "" || len(candidates) == 0 {
		return choose()
	}
	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	if binding, ok := m.bindings[key]; ok {
		if binding.ExpiresAt.After(now) {
			for _, candidate := range candidates {
				if schedulerCandidateRotationIdentity(candidate) == binding.CandidateIdentity {
					binding.ExpiresAt = now.Add(schedulerAffinityTTL)
					m.bindings[key] = binding
					return candidate
				}
			}
		}
		delete(m.bindings, key)
	}
	chosen := choose()
	candidateIdentity := strings.TrimSpace(schedulerCandidateRotationIdentity(chosen))
	if candidateIdentity == "" {
		return chosen
	}
	if m.bindings == nil {
		m.bindings = make(map[string]schedulerAffinityBinding)
	}
	if len(m.bindings) >= schedulerAffinityMaxBindings {
		m.evictOneLocked(now)
	}
	m.bindings[key] = schedulerAffinityBinding{CandidateIdentity: candidateIdentity, ExpiresAt: now.Add(schedulerAffinityTTL)}
	return chosen
}

func (m *schedulerAffinityManager) pick(key string, candidates []schedulerAuthCandidate) (schedulerAuthCandidate, bool) {
	key = strings.TrimSpace(key)
	if key == "" || len(candidates) == 0 {
		return schedulerAuthCandidate{}, false
	}
	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	binding, ok := m.bindings[key]
	if !ok {
		return schedulerAuthCandidate{}, false
	}
	if !binding.ExpiresAt.After(now) {
		delete(m.bindings, key)
		return schedulerAuthCandidate{}, false
	}
	for _, candidate := range candidates {
		if schedulerCandidateRotationIdentity(candidate) == binding.CandidateIdentity {
			binding.ExpiresAt = now.Add(schedulerAffinityTTL)
			m.bindings[key] = binding
			return candidate, true
		}
	}
	delete(m.bindings, key)
	return schedulerAuthCandidate{}, false
}

func (m *schedulerAffinityManager) bind(key, candidateIdentity string) {
	key = strings.TrimSpace(key)
	candidateIdentity = strings.TrimSpace(candidateIdentity)
	if key == "" || candidateIdentity == "" {
		return
	}
	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.bindings == nil {
		m.bindings = make(map[string]schedulerAffinityBinding)
	}
	if _, exists := m.bindings[key]; !exists && len(m.bindings) >= schedulerAffinityMaxBindings {
		m.evictOneLocked(now)
	}
	m.bindings[key] = schedulerAffinityBinding{CandidateIdentity: candidateIdentity, ExpiresAt: now.Add(schedulerAffinityTTL)}
}

func (m *schedulerAffinityManager) evictOneLocked(now time.Time) {
	oldestKey := ""
	var oldestExpiry time.Time
	examined := 0
	for key, binding := range m.bindings {
		if !binding.ExpiresAt.After(now) {
			delete(m.bindings, key)
			return
		}
		if oldestKey == "" || binding.ExpiresAt.Before(oldestExpiry) {
			oldestKey = key
			oldestExpiry = binding.ExpiresAt
		}
		examined++
		if examined >= schedulerAffinityEvictSample {
			break
		}
	}
	if oldestKey != "" {
		delete(m.bindings, oldestKey)
	}
}

func (m *schedulerAffinityManager) reset() {
	m.mu.Lock()
	m.bindings = nil
	m.mu.Unlock()
}
