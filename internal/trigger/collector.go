package trigger

import (
	"sync"

	"procir/internal/types"
)

// CollectResult holds all trigger entries from all sources.
type CollectResult struct {
	Entries []*types.TriggerEntry
}

// CollectAll runs all trigger collectors and returns unified results.
func CollectAll() *CollectResult {
	var mu sync.Mutex
	var all []*types.TriggerEntry

	var wg sync.WaitGroup

	collectors := []func() []*types.TriggerEntry{
		collectRunKeys,
		collectStartup,
		collectTasks,
		collectServices,
		collectWMI,
		collectIFEO,
		collectWinlogon,
	}

	for _, fn := range collectors {
		wg.Add(1)
		go func(collect func() []*types.TriggerEntry) {
			defer wg.Done()
			entries := collect()
			if len(entries) > 0 {
				mu.Lock()
				all = append(all, entries...)
				mu.Unlock()
			}
		}(fn)
	}

	wg.Wait()

	return &CollectResult{Entries: all}
}
