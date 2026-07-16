package main

import (
	"errors"
	"strings"
)

func hostAuthDiagnosticStatus(err error) string {
	switch {
	case err == nil:
		return "ok"
	case errors.Is(err, errCodexHostAuthListInvalid), errors.Is(err, errXAIHostAuthListInvalid):
		return "invalid_response"
	default:
		return "unavailable"
	}
}

func authSourceFallbackDiagnostic(hostStatus, fallbackStatus string) string {
	hostStatus = strings.TrimSpace(hostStatus)
	fallbackStatus = strings.TrimSpace(fallbackStatus)
	if hostStatus == "" {
		hostStatus = "unavailable"
	}
	if fallbackStatus == "" {
		fallbackStatus = "unknown"
	}
	return "host_" + hostStatus + ";filesystem_" + fallbackStatus
}
