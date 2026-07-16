package main

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
)

type xaiErrorKind string

const (
	xaiErrorUnknown            xaiErrorKind = "unknown"
	xaiErrorUnauthorized       xaiErrorKind = "unauthorized"
	xaiErrorTokenExpired       xaiErrorKind = "token_expired"
	xaiErrorTokenRevoked       xaiErrorKind = "token_revoked"
	xaiErrorPermissionDenied   xaiErrorKind = "permission_denied"
	xaiErrorAccountUnavailable xaiErrorKind = "account_unavailable"
	xaiErrorFreeUsageExhausted xaiErrorKind = "free_usage_exhausted"
	xaiErrorRateLimited        xaiErrorKind = "rate_limited"
	xaiErrorModelUnavailable   xaiErrorKind = "model_unavailable"
	xaiErrorUpstreamTransient  xaiErrorKind = "upstream_transient"
)

type xaiParsedError struct {
	Kind    xaiErrorKind
	Code    string
	Message string
}

func parseXAIError(status int, body string) xaiParsedError {
	parsed := extractXAIError(body)
	text := strings.ToLower(strings.TrimSpace(parsed.Code + " " + parsed.Message))

	// HTTP status defines the only allowed classification family. Response-body
	// markers may refine that family, but must never turn (for example) a 5xx or
	// 404 into a credential restriction. Status 0 is the compatibility path for
	// callers that have body evidence but no HTTP status at all.
	switch status {
	case 0:
		parsed.Kind = classifyXAIErrorBody(text)
	case http.StatusUnauthorized:
		switch {
		case containsXAIErrorMarker(text, "token has been invalidated", "token invalidated", "token_invalidated", "token revoked", "token_revoked", "revoked token", "credential revoked"):
			parsed.Kind = xaiErrorTokenRevoked
		case containsXAIErrorMarker(text, "token is expired", "token expired", "token_expired", "expired token", "expired_token", "jwt expired", "invalid_grant"):
			parsed.Kind = xaiErrorTokenExpired
		default:
			parsed.Kind = xaiErrorUnauthorized
		}
	case http.StatusPaymentRequired, http.StatusForbidden:
		if containsXAIErrorMarker(text, "account suspended", "account_suspended", "account banned", "account_banned", "user suspended", "user banned", "suspended", "banned", "deactivated", "workspace disabled") {
			parsed.Kind = xaiErrorAccountUnavailable
		} else {
			parsed.Kind = xaiErrorPermissionDenied
		}
	case http.StatusNotFound:
		parsed.Kind = xaiErrorModelUnavailable
	case http.StatusTooManyRequests:
		if containsXAIErrorMarker(text, "free-usage-exhausted", "included free usage", "usage_limit_reached", "quota exhausted") {
			parsed.Kind = xaiErrorFreeUsageExhausted
		} else {
			parsed.Kind = xaiErrorRateLimited
		}
	default:
		if status >= http.StatusInternalServerError {
			parsed.Kind = xaiErrorUpstreamTransient
		} else {
			parsed.Kind = xaiErrorUnknown
		}
	}
	return parsed
}

func containsXAIErrorMarker(text string, markers ...string) bool {
	for _, marker := range markers {
		if strings.Contains(text, marker) {
			return true
		}
	}
	return false
}

func classifyXAIErrorBody(text string) xaiErrorKind {
	switch {
	case containsXAIErrorMarker(text, "free-usage-exhausted", "included free usage", "usage_limit_reached", "quota exhausted"):
		return xaiErrorFreeUsageExhausted
	case containsXAIErrorMarker(text, "token has been invalidated", "token invalidated", "token_invalidated", "token revoked", "token_revoked", "revoked token", "credential revoked"):
		return xaiErrorTokenRevoked
	case containsXAIErrorMarker(text, "token is expired", "token expired", "token_expired", "expired token", "expired_token", "jwt expired", "invalid_grant"):
		return xaiErrorTokenExpired
	case containsXAIErrorMarker(text, "invalid token", "invalid bearer", "invalid credential", "invalid authentication", "unauthorized"):
		return xaiErrorUnauthorized
	case containsXAIErrorMarker(text, "account suspended", "account_suspended", "account banned", "account_banned", "user suspended", "user banned", "suspended", "banned", "deactivated", "workspace disabled"):
		return xaiErrorAccountUnavailable
	case containsXAIErrorMarker(text, "model unavailable", "model_unavailable", "model-unavailable", "model_not_found", "model not found", "unknown model", "model does not exist"):
		return xaiErrorModelUnavailable
	case containsXAIErrorMarker(text, "permission-denied", "permission_denied", "permission denied", "insufficient permissions", "insufficient_scope", "access denied", "endpoint is denied", "not allowed", "forbidden"):
		return xaiErrorPermissionDenied
	case containsXAIErrorMarker(text, "rate_limit", "rate-limit", "rate limited", "rate_limited", "rate limit", "too many requests", "temporarily throttled", "throttling"):
		return xaiErrorRateLimited
	case containsXAIErrorMarker(text, "upstream error", "upstream_error", "upstream failure", "upstream_failure", "upstream timeout", "upstream_timeout", "internal_server_error", "service unavailable", "temporarily unavailable", "bad gateway", "gateway timeout", "request timeout"):
		return xaiErrorUpstreamTransient
	default:
		return xaiErrorUnknown
	}
}

func extractXAIError(body string) xaiParsedError {
	body = strings.TrimSpace(body)
	if body == "" {
		return xaiParsedError{}
	}
	var data map[string]any
	if err := json.Unmarshal([]byte(body), &data); err != nil {
		return xaiParsedError{Message: body}
	}
	parsed := xaiParsedError{Code: xaiErrorString(data["code"])}
	switch value := data["error"].(type) {
	case map[string]any:
		parsed.Code = xaiFirstNonEmpty(parsed.Code, xaiErrorString(value["code"]))
		parsed.Message = xaiFirstNonEmpty(xaiErrorString(value["message"]), xaiErrorString(value["error"]))
	case string:
		parsed.Message = strings.TrimSpace(value)
	}
	parsed.Message = xaiFirstNonEmpty(parsed.Message, xaiErrorString(data["message"]))
	if parsed.Message == "" && parsed.Code == "" {
		parsed.Message = body
	}
	return parsed
}

func xaiFirstNonEmpty(values ...string) string {
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return ""
}

func xaiErrorString(value any) string {
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	case float64:
		return strconv.FormatFloat(typed, 'f', -1, 64)
	case json.Number:
		return typed.String()
	case bool:
		return strconv.FormatBool(typed)
	default:
		return ""
	}
}
