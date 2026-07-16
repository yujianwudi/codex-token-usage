package main

const (
	abiPluginPanicCode    = "plugin_panic"
	abiPluginPanicMessage = "plugin encountered an internal failure"
)

// abiPanicPoint is intentionally numeric. Human-readable injection names and
// the exported injection control exist only in the abi_panic_harness build.
// Release libraries therefore contain neither an environment switch nor a
// callable panic-injection symbol.
type abiPanicPoint uint32

const (
	abiPanicNone abiPanicPoint = iota
	abiPanicInit
	abiPanicCall
	abiPanicFree
	abiPanicShutdownBoundary
	abiPanicShutdownCancelOperations
	abiPanicShutdownSchedulerState
	abiPanicShutdownAccountProtection
	abiPanicShutdownQuotaTrigger
	abiPanicShutdownModelPrices
	abiPanicShutdownRetention
	abiPanicShutdownDBHealth
	abiPanicShutdownSummaryMaintenance
	abiPanicShutdownSummaryPrecompute
	abiPanicShutdownSchedulerInvalidate
	abiPanicShutdownAffinity
	abiPanicShutdownStore
	abiPanicInitAfterPublish
	abiPanicCallAfterResponse
)

func abiPluginPanicEnvelope() []byte {
	return errorEnvelope(abiPluginPanicCode, abiPluginPanicMessage)
}

// abiBestEffort is used only at an ABI recovery/cleanup boundary. It must not
// expose the recovered value or stack to the native caller.
func abiBestEffort(fn func()) {
	defer func() {
		_ = recover()
	}()
	if fn != nil {
		fn()
	}
}

func abiShutdownStep(point abiPanicPoint, stop func()) {
	abiBestEffort(func() {
		runABIPanicHook(point)
		if stop != nil {
			stop()
		}
	})
}
