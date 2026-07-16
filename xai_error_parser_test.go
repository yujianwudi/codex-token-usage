package main

import (
	"net/http"
	"testing"
)

func TestExtractXAIErrorStructures(t *testing.T) {
	tests := []struct {
		name        string
		body        string
		wantCode    string
		wantMessage string
	}{
		{name: "top-level code", body: `{"code":"token_expired","message":"Token is expired"}`, wantCode: "token_expired", wantMessage: "Token is expired"},
		{name: "nested error", body: `{"error":{"code":"permission-denied","message":"Access denied"}}`, wantCode: "permission-denied", wantMessage: "Access denied"},
		{name: "string error", body: `{"error":"account suspended"}`, wantMessage: "account suspended"},
		{name: "top-level message", body: `{"message":"temporary upstream failure"}`, wantMessage: "temporary upstream failure"},
		{name: "plain text", body: `gateway timeout`, wantMessage: "gateway timeout"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := extractXAIError(test.body)
			if got.Code != test.wantCode || got.Message != test.wantMessage {
				t.Fatalf("parsed=%+v, want code=%q message=%q", got, test.wantCode, test.wantMessage)
			}
		})
	}
}

func TestParseXAIErrorKinds(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
		want   xaiErrorKind
	}{
		{name: "token expired", status: http.StatusUnauthorized, body: `{"error":{"message":"Token is expired"}}`, want: xaiErrorTokenExpired},
		{name: "token expired code", status: http.StatusUnauthorized, body: `{"code":"token_expired"}`, want: xaiErrorTokenExpired},
		{name: "token revoked", status: http.StatusUnauthorized, body: `{"error":"Token has been invalidated"}`, want: xaiErrorTokenRevoked},
		{name: "permission denied", status: http.StatusForbidden, body: `{"code":"permission-denied"}`, want: xaiErrorPermissionDenied},
		{name: "account suspended", status: http.StatusForbidden, body: `{"message":"Account suspended"}`, want: xaiErrorAccountUnavailable},
		{name: "free usage exhausted", status: http.StatusTooManyRequests, body: `{"error":{"code":"subscription:free-usage-exhausted"}}`, want: xaiErrorFreeUsageExhausted},
		{name: "ordinary rate limit", status: http.StatusTooManyRequests, body: `{"error":"too many requests"}`, want: xaiErrorRateLimited},
		{name: "model unavailable", status: http.StatusNotFound, body: `{"error":{"code":"model_not_found"}}`, want: xaiErrorModelUnavailable},
		{name: "upstream transient", status: http.StatusServiceUnavailable, body: `{"message":"temporarily unavailable"}`, want: xaiErrorUpstreamTransient},
		{name: "401 ignores account marker", status: http.StatusUnauthorized, body: `{"message":"account suspended"}`, want: xaiErrorUnauthorized},
		{name: "403 ignores token marker", status: http.StatusForbidden, body: `{"message":"token expired"}`, want: xaiErrorPermissionDenied},
		{name: "404 ignores credential marker", status: http.StatusNotFound, body: `{"message":"invalid token"}`, want: xaiErrorModelUnavailable},
		{name: "429 ignores credential marker", status: http.StatusTooManyRequests, body: `{"message":"token revoked"}`, want: xaiErrorRateLimited},
		{name: "5xx ignores credential marker", status: http.StatusBadGateway, body: `{"message":"unauthorized"}`, want: xaiErrorUpstreamTransient},
		{name: "other status ignores rate marker", status: http.StatusBadRequest, body: `{"message":"rate limited"}`, want: xaiErrorUnknown},
		{name: "status zero uses body token marker", status: 0, body: `{"message":"token expired"}`, want: xaiErrorTokenExpired},
		{name: "status zero uses body quota marker", status: 0, body: `{"message":"included free usage exhausted"}`, want: xaiErrorFreeUsageExhausted},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := parseXAIError(test.status, test.body); got.Kind != test.want {
				t.Fatalf("parsed=%+v, want kind=%q", got, test.want)
			}
		})
	}
}
