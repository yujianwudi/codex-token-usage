//go:build abi_panic_harness

package main

/*
#include <stdint.h>
*/
import "C"

import "sync/atomic"

var abiHarnessPanicPoint atomic.Uint32

func setABIPanicPointForHarness(point abiPanicPoint) {
	abiHarnessPanicPoint.Store(uint32(point))
}

//export cliproxyTestSetPanicPoint
func cliproxyTestSetPanicPoint(point C.uint32_t) {
	setABIPanicPointForHarness(abiPanicPoint(point))
}

//export cliproxyTestGetPanicPoint
func cliproxyTestGetPanicPoint() C.uint32_t {
	return C.uint32_t(abiHarnessPanicPoint.Load())
}

func runABIPanicHook(point abiPanicPoint) {
	if point == abiPanicNone {
		return
	}
	if abiHarnessPanicPoint.CompareAndSwap(uint32(point), uint32(abiPanicNone)) {
		panic("ABI_PANIC_HARNESS_SECRET")
	}
}
