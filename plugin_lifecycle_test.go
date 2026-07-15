package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestMaxPluginRequestLimitFitsAuthImportEnvelope(t *testing.T) {
	if maxPluginRequestBytes < 16<<20 {
		t.Fatalf("max plugin request bytes = %d, too small for an 8 MiB auth import envelope", maxPluginRequestBytes)
	}
}

func TestPluginOperationContextCancelsAndResets(t *testing.T) {
	resetPluginOperationContext()
	t.Cleanup(resetPluginOperationContext)
	first := currentPluginOperationContext()
	cancelPluginOperationContext()
	select {
	case <-first.Done():
	case <-time.After(time.Second):
		t.Fatal("plugin operation context was not canceled")
	}
	resetPluginOperationContext()
	second := currentPluginOperationContext()
	if second == first {
		t.Fatal("plugin operation context was not replaced")
	}
	select {
	case <-second.Done():
		t.Fatal("reset plugin operation context is already canceled")
	default:
	}
}

func TestUsageHandleHonorsCanceledPluginOperationContext(t *testing.T) {
	t.Setenv("CPA_TOKEN_USAGE_DIR", t.TempDir())
	previousStore := globalStore
	globalStore = &store{}
	t.Cleanup(func() { globalStore = previousStore })
	resetPluginOperationContext()
	t.Cleanup(resetPluginOperationContext)
	cancelPluginOperationContext()

	raw, err := json.Marshal(usageRecord{Provider: "codex", RequestedAt: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	response, err := handleMethod("usage.handle", raw)
	if err != nil {
		t.Fatal(err)
	}
	var env envelope
	if err := json.Unmarshal(response, &env); err != nil {
		t.Fatal(err)
	}
	var result map[string]any
	if err := json.Unmarshal(env.Result, &result); err != nil {
		t.Fatal(err)
	}
	if result["stored"] != false || !strings.Contains(strings.ToLower(stringFromAny(result["error"])), "context canceled") {
		t.Fatalf("usage.handle result = %#v, want canceled stored=false", result)
	}
}
