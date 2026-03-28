package types

// ModuleInfo represents an analyzed DLL loaded by a process.
type ModuleInfo struct {
	Path   string `json:"Path"`
	Name   string `json:"Name"`

	Signed bool   `json:"Signed"`
	Signer string `json:"Signer"`

	IsSystemDLLName bool `json:"IsSystemDLLName"` // name matches a known system DLL
	IsSystemPath    bool `json:"IsSystemPath"`     // loaded from System32/SysWOW64
	IsUserPath      bool `json:"IsUserPath"`       // loaded from C:\Users\...
	IsTempPath      bool `json:"IsTempPath"`       // loaded from Temp/Tmp
	IsSameDirAsExe  bool `json:"IsSameDirAsExe"`   // same directory as the host EXE

	Score   int      `json:"Score"`
	Reasons []string `json:"Reasons"`
}

// ModuleAnalysis holds the module-level analysis result for a process.
type ModuleAnalysis struct {
	PID       uint32 `json:"PID"`
	ExeName   string `json:"ExeName"`
	ExePath   string `json:"ExePath"`
	ExeSigned bool   `json:"ExeSigned"`
	ExeSigner string `json:"ExeSigner"`

	SuspiciousModules []*ModuleInfo `json:"SuspiciousModules"`
	TotalModules      int           `json:"TotalModules"`
	SuspiciousCount   int           `json:"SuspiciousCount"`

	HasDLLHijack bool `json:"HasDLLHijack"`
	DLLHijackScore int `json:"DLLHijackScore"`

	Score   int      `json:"Score"`
	Reasons []string `json:"Reasons"`
}
