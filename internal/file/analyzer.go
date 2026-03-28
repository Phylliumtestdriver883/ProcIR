package file

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"sync"
)

// FileInfo holds file metadata and hashes.
type FileInfo struct {
	Exists  bool
	Size    int64
	ModTime string
	SHA256  string
	MD5     string
}

// Analyzer caches file analysis results to avoid redundant I/O.
type Analyzer struct {
	mu    sync.Mutex
	cache map[string]*FileInfo
}

func NewAnalyzer() *Analyzer {
	return &Analyzer{cache: make(map[string]*FileInfo)}
}

// Analyze returns file info for the given path, using cache when available.
func (a *Analyzer) Analyze(path string) *FileInfo {
	if path == "" {
		return &FileInfo{}
	}

	a.mu.Lock()
	if cached, ok := a.cache[path]; ok {
		a.mu.Unlock()
		return cached
	}
	a.mu.Unlock()

	info := &FileInfo{}
	stat, err := os.Stat(path)
	if err != nil {
		a.mu.Lock()
		a.cache[path] = info
		a.mu.Unlock()
		return info
	}

	info.Exists = true
	info.Size = stat.Size()
	info.ModTime = stat.ModTime().Format("2006-01-02 15:04:05")

	f, err := os.Open(path)
	if err != nil {
		a.mu.Lock()
		a.cache[path] = info
		a.mu.Unlock()
		return info
	}
	defer f.Close()

	sha256Hash := sha256.New()
	md5Hash := md5.New()
	writer := io.MultiWriter(sha256Hash, md5Hash)

	if _, err := io.Copy(writer, f); err == nil {
		info.SHA256 = hex.EncodeToString(sha256Hash.Sum(nil))
		info.MD5 = hex.EncodeToString(md5Hash.Sum(nil))
	}

	a.mu.Lock()
	a.cache[path] = info
	a.mu.Unlock()
	return info
}
