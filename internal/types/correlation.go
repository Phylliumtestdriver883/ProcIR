package types

// TimelineEvent represents a single event on the investigation timeline.
type TimelineEvent struct {
	Time       string // 2006-01-02 15:04:05
	Type       string // execution / trigger / file / network / module / eventlog
	ObjectPath string
	ObjectName string
	Detail     string
	Score      int
	Source     string // which collector produced this
}

// BehaviorChain represents a detected attack pattern.
type BehaviorChain struct {
	PatternName  string
	PatternScore int
	Evidence     []string // human-readable evidence lines
	ObjectPaths  []string // involved file paths
}

// Indicator represents an extracted IOC.
type Indicator struct {
	Type         string // ip / domain / url / base64 / filepath
	Value        string
	SourceObject string // which object/cmdline it came from
	Context      string // brief context
}

// ProcessNode represents a node in the process tree.
type ProcessNode struct {
	PID      uint32
	PPID     uint32
	Name     string
	Path     string
	Score    int
	Level    string
	Children []*ProcessNode
}

// DirCluster represents a group of suspicious files in the same directory.
type DirCluster struct {
	Directory string
	Files     []string
	FileTypes []string // exe, dll, script
	Count     int
	Score     int
	Reasons   []string
}

// CorrelationResult holds all phase-4 analysis results.
type CorrelationResult struct {
	Timeline   []*TimelineEvent
	Chains     []*BehaviorChain
	Indicators []*Indicator
	ProcessTree []*ProcessNode
	DirClusters []*DirCluster
}
