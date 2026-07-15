package main

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestModelPriceUpdateManagerConcurrentConfigureAndStop(t *testing.T) {
	priceFile := filepath.Join(t.TempDir(), "model-prices.json")
	if err := os.WriteFile(priceFile, []byte(`{"model":{"input_cost_per_token":0.1}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CPA_MODEL_PRICE_FILE", priceFile)

	enabled := defaultPluginConfig()
	enabled.ModelPriceAutoUpdateEnabled = true
	enabled.ModelPriceUpdateIntervalHours = 1
	enabled.ModelPriceUpdateTimeoutSeconds = 3
	disabled := enabled
	disabled.ModelPriceAutoUpdateEnabled = false

	var manager modelPriceUpdateManager
	const workers = 8
	const iterations = 40
	start := make(chan struct{})
	done := make(chan struct{})
	var wg sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		worker := worker
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for iteration := 0; iteration < iterations; iteration++ {
				switch (worker + iteration) % 3 {
				case 0:
					manager.stop()
				case 1:
					manager.configure(enabled)
				default:
					manager.configure(disabled)
				}
			}
		}()
	}
	close(start)
	go func() {
		wg.Wait()
		manager.stop()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("concurrent model price updater lifecycle did not quiesce")
	}

	manager.mu.Lock()
	defer manager.mu.Unlock()
	if manager.ctx != nil || manager.cancel != nil || manager.updating {
		t.Fatalf("model price updater remained active after stop: ctx=%v cancel=%v updating=%v", manager.ctx != nil, manager.cancel != nil, manager.updating)
	}
}
