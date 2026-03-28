package types

// IOCEntry represents a single IOC for monitoring.
type IOCEntry struct {
	Value      string `json:"Value"`
	Type       string `json:"Type"`       // ip / domain
	Confidence string `json:"Confidence"` // high / medium / low
	Source     string `json:"Source"`
	Comment    string `json:"Comment"`
}

// IOCHit represents a single IOC match event.
type IOCHit struct {
	Time        string `json:"Time"`
	IOC         string `json:"IOC"`
	IOCType     string `json:"IOCType"`
	IOCComment  string `json:"IOCComment"`

	PID         uint32 `json:"PID"`
	ProcessName string `json:"ProcessName"`
	ProcessPath string `json:"ProcessPath"`
	CommandLine string `json:"CommandLine"`
	ParentName  string `json:"ParentName"`
	User        string `json:"User"`
	Signed      bool   `json:"Signed"`
	Signer      string `json:"Signer"`

	RemoteIP    string `json:"RemoteIP"`
	RemotePort  uint16 `json:"RemotePort"`
	Protocol    string `json:"Protocol"`

	MatchSource string `json:"MatchSource"` // tcp / udp / dns
	Confidence  string `json:"Confidence"`

	IsLOLBin    bool   `json:"IsLOLBin"`
	IsUserPath  bool   `json:"IsUserPath"`
}

// MonitorStatus holds the current session state.
type MonitorStatus struct {
	Running     bool   `json:"Running"`
	StartTime   string `json:"StartTime"`
	Elapsed     string `json:"Elapsed"`
	Duration    int    `json:"Duration"`    // configured duration in seconds
	IOCCount    int    `json:"IOCCount"`
	HitCount    int    `json:"HitCount"`
	HitPIDs     int    `json:"HitPIDs"`
	CycleCount  int    `json:"CycleCount"`  // number of poll cycles completed
}
