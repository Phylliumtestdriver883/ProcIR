package types

// MemoryRegion represents a single virtual memory region of a process.
type MemoryRegion struct {
	BaseAddress  string `json:"BaseAddress"`  // hex string
	Size         uint64 `json:"Size"`
	SizeHuman    string `json:"SizeHuman"`    // e.g. "4.0 KB"
	Protect      string `json:"Protect"`      // e.g. "PAGE_EXECUTE_READWRITE"
	ProtectRaw   uint32 `json:"-"`
	Type         string `json:"Type"`         // MEM_PRIVATE / MEM_IMAGE / MEM_MAPPED
	TypeRaw      uint32 `json:"-"`
	State        string `json:"State"`        // MEM_COMMIT / MEM_RESERVE / MEM_FREE
	IsExecutable bool   `json:"IsExecutable"`
	IsWritable   bool   `json:"IsWritable"`
	IsRWX        bool   `json:"IsRWX"`

	// Flags
	IsPrivateExec bool `json:"IsPrivateExec"` // MEM_PRIVATE + executable
	IsNoImageExec bool `json:"IsNoImageExec"` // not MEM_IMAGE but executable
	IsSuspicious  bool `json:"IsSuspicious"`
	Reason        string `json:"Reason,omitempty"`
}

// MemoryAnalysis holds the complete memory analysis result for a process.
type MemoryAnalysis struct {
	PID         uint32 `json:"PID"`
	ProcessName string `json:"ProcessName"`
	Path        string `json:"Path"`
	User        string `json:"User"`
	Signed      bool   `json:"Signed"`
	Signer      string `json:"Signer"`

	TotalRegions     int `json:"TotalRegions"`
	CommittedRegions int `json:"CommittedRegions"`
	ExecutableRegions int `json:"ExecutableRegions"`

	RWXCount         int `json:"RWXCount"`
	PrivateExecCount int `json:"PrivateExecCount"`
	NoImageExecCount int `json:"NoImageExecCount"`
	SuspiciousCount  int `json:"SuspiciousCount"`

	AllRegions        []*MemoryRegion `json:"AllRegions"`
	SuspiciousRegions []*MemoryRegion `json:"SuspiciousRegions"`

	Score     int      `json:"Score"`
	RiskLevel string   `json:"RiskLevel"`
	Reasons   []string `json:"Reasons"`

	Error string `json:"Error,omitempty"`
}
