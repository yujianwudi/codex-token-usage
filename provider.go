package main

import (
	"errors"
	"strings"
)

const (
	providerCodex = "codex"
	providerXAI   = "xai"
)

func canonicalProvider(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func canonicalProviderOr(value, fallback string) string {
	if provider := canonicalProvider(value); provider != "" {
		return provider
	}
	return canonicalProvider(fallback)
}

func requiredCanonicalProvider(value string) (string, error) {
	provider := canonicalProvider(value)
	if provider == "" {
		return "", errors.New("provider is required")
	}
	return provider, nil
}
