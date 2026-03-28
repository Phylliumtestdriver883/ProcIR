package forensic

import (
	"sort"
	"sync"

	"procir/internal/types"
)

// CollectResult holds all forensic entries from all sources.
type CollectResult struct {
	Entries []*types.ForensicEntry
	Modules []*types.ForensicEntry
}

// CollectAll runs all forensic collectors and returns unified results.
// pids is the list of active process PIDs for module analysis.
func CollectAll(pids []uint32) *CollectResult {
	var mu sync.Mutex
	var all []*types.ForensicEntry
	var modules []*types.ForensicEntry

	var wg sync.WaitGroup

	// Prefetch
	wg.Add(1)
	go func() {
		defer wg.Done()
		entries := collectPrefetch()
		mu.Lock()
		all = append(all, entries...)
		mu.Unlock()
	}()

	// Recent files
	wg.Add(1)
	go func() {
		defer wg.Done()
		entries := collectRecentFiles()
		mu.Lock()
		all = append(all, entries...)
		mu.Unlock()
	}()

	// Event logs
	wg.Add(1)
	go func() {
		defer wg.Done()
		entries := collectEventLogs()
		mu.Lock()
		all = append(all, entries...)
		mu.Unlock()
	}()

	// DLL modules
	wg.Add(1)
	go func() {
		defer wg.Done()
		entries := collectModules(pids)
		mu.Lock()
		modules = entries
		all = append(all, entries...)
		mu.Unlock()
	}()

	wg.Wait()

	// Score all entries
	ScoreAll(all)

	// Sort by score descending
	sort.Slice(all, func(i, j int) bool {
		return all[i].Score > all[j].Score
	})

	sort.Slice(modules, func(i, j int) bool {
		return modules[i].Score > modules[j].Score
	})

	return &CollectResult{
		Entries: all,
		Modules: modules,
	}
}
