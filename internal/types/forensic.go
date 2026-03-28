package types

// ForensicSource identifies the origin of a forensic artifact.
type ForensicSource string

const (
	ForensicPrefetch   ForensicSource = "Prefetch"
	ForensicRecentFile ForensicSource = "RecentFile"
	ForensicEventLog   ForensicSource = "EventLog"
	ForensicModule     ForensicSource = "Module"
)

// ForensicEntry represents a single historical execution artifact.
type ForensicEntry struct {
	Source ForensicSource
	Path   string
	Detail string

	// Prefetch
	ExeName     string
	RunCount    int
	LastRunTime string
	FirstSeen   string

	// Event log
	EventID     int
	EventTime   string
	EventSource string
	CommandLine string

	// Module (DLL)
	ProcessPID  uint32
	ProcessName string
	ModulePath  string
	ModuleSigned bool
	ModuleSigner string

	// Recent file
	FileModTime string
	FileSize    int64
	FileType    string // exe / dll / script

	Score   int
	Reasons []string
}

// ModuleRecord represents a loaded DLL in a process with analysis results.
type ModuleRecord struct {
	PID         uint32
	ProcessName string
	ModulePath  string
	ModuleName  string

	Signed       bool
	SignValid    bool
	Signer       string
	IsUserPath   bool
	IsTempPath   bool
	IsMasquerade bool

	Score   int
	Reasons []string
}
