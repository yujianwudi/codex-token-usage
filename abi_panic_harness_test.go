//go:build abi_panic_harness

package main

import "testing"

func TestABIPanicHarnessHookIsOneShot(t *testing.T) {
	setABIPanicPointForHarness(abiPanicCall)
	panicked := false
	func() {
		defer func() { panicked = recover() != nil }()
		runABIPanicHook(abiPanicCall)
	}()
	if !panicked {
		t.Fatal("tagged ABI panic hook did not panic")
	}
	// The hook consumes the injection before panicking so a recovered native
	// caller can retry safely without an explicit reset.
	runABIPanicHook(abiPanicCall)
}

func TestABIShutdownStepsContinueAfterInjectedPanic(t *testing.T) {
	setABIPanicPointForHarness(abiPanicShutdownSummaryMaintenance)
	failedStepRan := false
	abiShutdownStep(abiPanicShutdownSummaryMaintenance, func() { failedStepRan = true })
	if failedStepRan {
		t.Fatal("panic-injected shutdown step ran after its injected failure")
	}
	nextStepRan := false
	abiShutdownStep(abiPanicShutdownSummaryPrecompute, func() { nextStepRan = true })
	if !nextStepRan {
		t.Fatal("shutdown did not continue after a recovered component panic")
	}
}
