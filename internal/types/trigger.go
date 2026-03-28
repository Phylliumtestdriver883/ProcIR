package types

import "time"

// TriggerType represents the source of a trigger entry.
type TriggerType string

const (
	TriggerRunKey   TriggerType = "RunKey"
	TriggerStartup  TriggerType = "Startup"
	TriggerTask     TriggerType = "Task"
	TriggerService  TriggerType = "Service"
	TriggerWMI      TriggerType = "WMI"
	TriggerIFEO     TriggerType = "IFEO"
	TriggerWinlogon TriggerType = "Winlogon"
)

// TriggerEntry represents a single persistence/trigger mechanism.
type TriggerEntry struct {
	Type        TriggerType
	Name        string // registry key name, task name, service name, etc.
	Path        string // extracted executable path
	CommandLine string // full command line or value
	Detail      string // human-readable detail

	// Task-specific fields
	TaskAuthor      string
	TaskDescription string
	TaskTriggerType string // logon / time / idle / event / boot
	TaskRunAs       string
	TaskHidden      bool
	TaskLastRun     string
	TaskNextRun     string
	TaskLastResult  string
	TaskInterval    string // repeat interval if applicable

	// Service-specific fields
	ServiceStartType string // Auto / Manual / Disabled / Boot / System
	ServiceAccount   string
	ServiceState     string // Running / Stopped
	ServiceDLL       string // for svchost-based services

	// WMI-specific fields
	WMIFilterName   string
	WMIFilterQuery  string
	WMIConsumerName string
	WMIConsumerCmd  string

	// Scoring
	Score   int
	Reasons []string
}

// ExecutionObject is the unified model that merges process data and trigger data.
type ExecutionObject struct {
	// Identity
	Path        string
	CommandLine string
	ObjType     string // exe / dll / script / command

	// Source tracking
	Sources      []string // "process", "RunKey", "Task", "Service", "WMI", etc.
	SourceDetail string   // human-readable multi-source description

	// File info
	Exists   bool
	FileSize int64
	SHA256   string
	MD5      string

	// Signature
	Signed       bool
	SignValid    bool
	Signer       string
	Company      string
	Product      string
	OriginalName string

	// Location
	LocationType string // System32 / ProgramFiles / UserDir / Temp / ProgramData / Other
	IsLOLBin     bool

	// Runtime state (from active process if running)
	IsRunning       bool
	PIDs            []uint32
	ProcessNames    []string
	NetworkObserved bool
	RemoteIPs       []string
	HasPublicIP     bool

	// Trigger aggregation
	TriggerCount int
	TriggerTypes []string
	Triggers     []*TriggerEntry

	// Linked process records
	Processes []*ProcessRecord

	// Forensic data
	ForensicHits   int
	ForensicScore  int
	HasPrefetch    bool
	HasEventLog    bool
	HasRecentFile  bool
	SuspiciousModules int
	Forensics      []*ForensicEntry

	// Module abuse
	ModuleAnalyses      []*ModuleAnalysis `json:"ModuleAnalyses,omitempty"`
	SuspiciousModuleCount int
	HasDLLHijack        bool
	DLLHijackScore      int

	// YARA
	YaraMatched bool
	YaraHits    interface{} `json:"YaraHits,omitempty"`
	YaraScore   int

	// Event evidence
	EventCount     int
	EventScore     int
	FirstEventTime string
	LastEventTime  string
	Events         []*EventEvidence `json:"Events,omitempty"`

	// Scoring
	ExecutionScore int
	TriggerScore   int
	SynergyBonus   int
	WhiteReduction int
	FinalScore     int
	RiskLevel      string
	Reasons        []string

	// Timestamps
	FirstSeen time.Time
	LastSeen  time.Time
}
