package main

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
)

var dashboardCSP = buildDashboardContentSecurityPolicy(dashboardHTML)

func buildDashboardContentSecurityPolicy(html string) string {
	scriptHash := inlineAssetSHA256(html, "<script>", "</script>")
	scriptSource := "'self'"
	if scriptHash != "" {
		scriptSource += " 'sha256-" + scriptHash + "'"
	}
	return "default-src 'self'; script-src " + scriptSource + "; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
}

func inlineAssetSHA256(html, open, close string) string {
	start := strings.Index(html, open)
	if start < 0 {
		return ""
	}
	start += len(open)
	end := strings.Index(html[start:], close)
	if end < 0 {
		return ""
	}
	digest := sha256.Sum256([]byte(html[start : start+end]))
	return base64.StdEncoding.EncodeToString(digest[:])
}
