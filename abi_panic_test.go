package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestABIPluginPanicEnvelopeIsGeneric(t *testing.T) {
	raw := abiPluginPanicEnvelope()
	if strings.Contains(string(raw), "ABI_PANIC_HARNESS_SECRET") || strings.Contains(strings.ToLower(string(raw)), "stack") {
		t.Fatalf("panic envelope leaked internal details: %s", raw)
	}
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	if env.OK || env.Error == nil || env.Error.Code != abiPluginPanicCode || env.Error.Message != abiPluginPanicMessage {
		t.Fatalf("panic envelope = %#v", env)
	}
}

func TestABIBestEffortRecoversAndShutdownContinues(t *testing.T) {
	steps := make([]int, 0, 3)
	abiBestEffort(func() {
		steps = append(steps, 1)
		panic("must stay inside ABI boundary")
	})
	abiBestEffort(func() { steps = append(steps, 2) })
	if len(steps) != 2 || steps[0] != 1 || steps[1] != 2 {
		t.Fatalf("best-effort steps = %v, want [1 2]", steps)
	}
}
