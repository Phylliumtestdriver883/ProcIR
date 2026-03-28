package yara

import (
	"fmt"
	"os"
	"sync"
)

// ScanCache caches YARA scan results to avoid redundant scans.
type ScanCache struct {
	mu      sync.RWMutex
	entries map[string][]YaraHit // key → hits
	ruleHash string
}

func NewScanCache(ruleHash string) *ScanCache {
	return &ScanCache{
		entries:  make(map[string][]YaraHit),
		ruleHash: ruleHash,
	}
}

// cacheKey generates a unique key for a file based on path + size + mtime + rulehash.
func (c *ScanCache) cacheKey(path string) string {
	info, err := os.Stat(path)
	if err != nil {
		return path
	}
	return fmt.Sprintf("%s|%d|%d|%s", path, info.Size(), info.ModTime().UnixNano(), c.ruleHash)
}

// Get retrieves cached results for a file. Returns nil, false if not cached.
func (c *ScanCache) Get(path string) ([]YaraHit, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	key := c.cacheKey(path)
	hits, ok := c.entries[key]
	return hits, ok
}

// Set stores scan results for a file.
func (c *ScanCache) Set(path string, hits []YaraHit) {
	c.mu.Lock()
	defer c.mu.Unlock()
	key := c.cacheKey(path)
	c.entries[key] = hits
}
