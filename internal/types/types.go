package types

// ProcessRecord holds all collected and analyzed data for a single process.
type ProcessRecord struct {
	PID         uint32
	PPID        uint32
	Name        string
	Path        string
	CommandLine string
	User        string
	StartTime   string

	FileExists  bool
	FileSize    int64
	FileModTime string
	SHA256      string
	MD5         string

	Signed       bool
	SignValid    bool
	Signer       string
	Company      string
	Product      string
	OriginalName string
	FileVersion  string

	ParentName           string
	IsLOLBin             bool
	PathAbnormal         bool
	IsMasquerade         bool
	OriginalNameMismatch bool
	AbnormalParentChain  bool

	HasNetwork  bool
	RemoteIPs   []string
	RemotePorts []uint16
	HasPublicIP bool

	Persistence []string

	RiskScore int
	RiskLevel string
	Reasons   []string
}

// CalcRiskLevel returns risk level string from score.
func CalcRiskLevel(score int) string {
	switch {
	case score >= 80:
		return "Critical"
	case score >= 60:
		return "High"
	case score >= 40:
		return "Medium"
	case score >= 20:
		return "Suspicious"
	default:
		return "Low"
	}
}
