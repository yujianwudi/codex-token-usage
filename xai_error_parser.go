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
	contains := func(markers ...string) bool {
		for _, marker := range markers {
			if strings.Contains(text, marker) {
				return true
			}
		}
		return false
	}

	switch {
	case contains("free-usage-exhausted", "included free usage", "usage_limit_reached", "quota exhausted"):
		parsed.Kind = xaiErrorFreeUsageExhausted
	case contains("token has been invalidated", "token invalidated", "token_invalidated", "token revoked", "token_revoked", "revoked token", "credential revoked"):
		parsed.Kind = xaiErrorTokenRevoked
	case contains("token is expired", "token expired", "token_expired", "expired token", "expired_token", "jwt expired", "invalid_grant"):
		parsed.Kind = xaiErrorTokenExpired
	case contains("invalid token", "invalid bearer", "invalid credential", "invalid authentication", "unauthorized"):
		parsed.Kind = xaiErrorUnauthorized
	case contains("account suspended", "account_suspended", "account banned", "account_banned", "user suspended", "user banned", "suspended", "banned", "deactivated", "workspace disabled"):
		parsed.Kind = xaiErrorAccountUnavailable
	case contains("model unavailable", "model_unavailable", "model-unavailable", "model_not_found", "model not found", "unknown model", "model does not exist"):
		parsed.Kind = xaiErrorModelUnavailable
	case contains("permission-denied", "permission_denied", "permission denied", "insufficient permissions", "insufficient_scope", "access denied", "endpoint is denied", "not allowed", "forbidden"):
		parsed.Kind = xaiErrorPermissionDenied
	case contains("rate_limit", "rate-limit", "rate limited", "rate_limited", "rate limit", "too many requests", "temporarily throttled", "throttling"):
		parsed.Kind = xaiErrorRateLimited
	case contains("upstream error", "upstream_error", "upstream failure", "upstream_failure", "upstream timeout", "upstream_timeout", "internal_server_error", "service unavailable", "temporarily unavailable", "bad gateway", "gateway timeout", "request timeout"):
		parsed.Kind = xaiErrorUpstreamTransient
	default:
		switch {
		case status == http.StatusUnauthorized:
			parsed.Kind = xaiErrorUnauthorized
		case status == http.StatusForbidden || status == http.StatusPaymentRequired:
			parsed.Kind = xaiErrorPermissionDenied
		case status == http.StatusTooManyRequests:
			parsed.Kind = xaiErrorRateLimited
		case status == http.StatusNotFound:
			parsed.Kind = xaiErrorModelUnavailable
		case status >= http.StatusInternalServerError:
			parsed.Kind = xaiErrorUpstreamTransient
		default:
			parsed.Kind = xaiErrorUnknown
		}
	}
	return parsed
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
