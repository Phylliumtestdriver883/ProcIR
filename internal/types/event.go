package types

// EventEvidence represents a single high-value Windows event log entry.
type EventEvidence struct {
	Source      string `json:"Source"`      // Security / System / PowerShell / TaskScheduler / WMI / Sysmon
	EventID     int    `json:"EventID"`
	Time        string `json:"Time"`
	Computer    string `json:"Computer"`
	User        string `json:"User"`
	Description string `json:"Description"` // short human-readable description

	// Process fields (4688, Sysmon 1)
	ProcessPath string `json:"ProcessPath,omitempty"`
	CommandLine string `json:"CommandLine,omitempty"`
	ParentPath  string `json:"ParentPath,omitempty"`
	ProcessID   string `json:"ProcessID,omitempty"`

	// Target fields (service/task/file)
	TargetPath  string `json:"TargetPath,omitempty"`
	ServiceName string `json:"ServiceName,omitempty"`
	TaskName    string `json:"TaskName,omitempty"`

	// Network fields (Sysmon 3, 4624)
	IPAddress string `json:"IPAddress,omitempty"`
	Port      string `json:"Port,omitempty"`
	Domain    string `json:"Domain,omitempty"`

	// Login fields
	LogonType string `json:"LogonType,omitempty"`

	// Scoring
	Score   int      `json:"Score"`
	Reasons []string `json:"Reasons"`

	// Linked object path (set by correlator)
	LinkedObject string `json:"LinkedObject,omitempty"`
}

// EventCollectConfig controls what events to collect.
type EventCollectConfig struct {
	MaxAgeDays  int  // only events within N days (default 3)
	MaxEvents   int  // max events per source (default 2000)
	OfflinePath string // optional: path to offline .evtx file
	IncludeSysmon bool
}
