package main

import (
	"context"
	"sync"
	"time"
)

const maxPluginRequestBytes = 64 << 20

const (
	summaryPrecomputeStartupGrace  = 30 * time.Second
	summaryMaintenanceStartupGrace = 45 * time.Second
	quotaTriggerStartupGrace       = 75 * time.Second
	schedulerRefreshRetryInitial   = 100 * time.Millisecond
	schedulerRefreshRetryMax       = 5 * time.Second
)

var pluginLifecycleGate sync.RWMutex
var pluginLifecycleStopped = true

var pluginOperationState struct {
	sync.RWMutex
	ctx    context.Context
	cancel context.CancelFunc
}

func resetPluginOperationContext() {
	pluginOperationState.Lock()
	if pluginOperationState.cancel != nil {
		pluginOperationState.cancel()
	}
	pluginOperationState.ctx, pluginOperationState.cancel = context.WithCancel(context.Background())
	pluginOperationState.Unlock()
}

func currentPluginOperationContext() context.Context {
	pluginOperationState.RLock()
	ctx := pluginOperationState.ctx
	pluginOperationState.RUnlock()
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

func cancelPluginOperationContext() {
	pluginOperationState.Lock()
	if pluginOperationState.cancel != nil {
		pluginOperationState.cancel()
	}
	pluginOperationState.Unlock()
}

// sync.RWMutex gives a pending writer priority over subsequent readers.
// Shutdown publishes pluginLifecycleStopped and closes the store while holding
// the write side, so an invocation queued behind shutdown must observe
// running=false before it can execute code that opens the store.
func beginPluginInvocation(method string) (unlock func(), running bool) {
	if method == "plugin.register" || method == "plugin.reconfigure" {
		pluginLifecycleGate.Lock()
		return pluginLifecycleGate.Unlock, !pluginLifecycleStopped
	}
	pluginLifecycleGate.RLock()
	return pluginLifecycleGate.RUnlock, !pluginLifecycleStopped
}

// beginPluginInvocationBefore is a test synchronization seam. It keeps test
// scheduling outside the production path and avoids inspecting sync.RWMutex
// internals to decide when an invocation has reached the lifecycle gate.
func beginPluginInvocationBefore(method string, beforeLock func()) (func(), bool) {
	if beforeLock != nil {
		beforeLock()
	}
	return beginPluginInvocation(method)
}

type schedulerStateRefreshManager struct {
	opMu      sync.Mutex
	requestMu sync.Mutex
	cancel    context.CancelFunc
	wake      chan struct{}
	wg        sync.WaitGroup
	refresh   func(context.Context, *store) error

	retryInitial time.Duration
	retryMax     time.Duration
}

func (m *schedulerStateRefreshManager) configure(target *store) {
	m.opMu.Lock()
	defer m.opMu.Unlock()
	m.stopLocked()

	// Unknown is the fail-closed scheduler state: picks must consult SQLite and
	// return unavailable on failure until this background snapshot is published.
	globalSchedulerState.invalidate()
	ctx, cancel := context.WithCancel(context.Background())
	wake := make(chan struct{}, 1)
	m.cancel = cancel
	m.requestMu.Lock()
	m.wake = wake
	m.requestMu.Unlock()
	refresh := m.refresh
	if refresh == nil {
		refresh = func(ctx context.Context, target *store) error {
			return target.refreshSchedulerState(ctx)
		}
	}
	retryInitial := m.retryInitial
	if retryInitial <= 0 {
		retryInitial = schedulerRefreshRetryInitial
	}
	retryMax := m.retryMax
	if retryMax <= 0 {
		retryMax = schedulerRefreshRetryMax
	}
	if retryMax < retryInitial {
		retryMax = retryInitial
	}
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		m.loop(ctx, target, wake, refresh, retryInitial, retryMax)
	}()
}

// requestRefresh coalesces stale-snapshot and mutation notifications into the
// capacity-one wake channel. The single worker guarantees one active refresh;
// a notification that arrives during that refresh is retained for one
// follow-up pass so an intervening invalidation cannot be lost.
func (m *schedulerStateRefreshManager) requestRefresh() {
	m.requestMu.Lock()
	defer m.requestMu.Unlock()
	if m.wake == nil {
		return
	}
	select {
	case m.wake <- struct{}{}:
	default:
	}
}

func (m *schedulerStateRefreshManager) loop(
	ctx context.Context,
	target *store,
	wake chan struct{},
	refresh func(context.Context, *store) error,
	retryInitial time.Duration,
	retryMax time.Duration,
) {
	retryDelay := retryInitial
	for {
		err := refresh(ctx, target)
		if ctx.Err() != nil {
			return
		}
		if err == nil {
			retryDelay = retryInitial
			select {
			case <-ctx.Done():
				return
			case <-wake:
				continue
			}
		}
		if !waitForBackgroundStartup(ctx, retryDelay) {
			return
		}
		if retryDelay < retryMax {
			retryDelay = minDuration(retryDelay*2, retryMax)
		}
	}
}

func (m *schedulerStateRefreshManager) stop() {
	m.opMu.Lock()
	defer m.opMu.Unlock()
	m.stopLocked()
}

func (m *schedulerStateRefreshManager) stopLocked() {
	cancel := m.cancel
	m.cancel = nil
	m.requestMu.Lock()
	m.wake = nil
	m.requestMu.Unlock()
	if cancel != nil {
		cancel()
	}
	m.wg.Wait()
}

func minDuration(left, right time.Duration) time.Duration {
	if left < right {
		return left
	}
	return right
}

func waitForBackgroundStartup(ctx context.Context, delay time.Duration) bool {
	if delay <= 0 {
		return ctx.Err() == nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
