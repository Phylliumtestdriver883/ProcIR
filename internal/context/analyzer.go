package context

import (
	"path/filepath"
	"strings"
)

// Low risk LOLBins (commonly used legitimately) - tier 1
var lolbinLow = map[string]bool{
	"cmd.exe": true, "powershell.exe": true, "pwsh.exe": true,
	"wscript.exe": true, "cscript.exe": true, "msiexec.exe": true,
	"schtasks.exe": true, "mmc.exe": true, "msconfig.exe": true,
	"tar.exe": true, "expand.exe": true, "makecab.exe": true,
}

// Medium risk LOLBins - tier 2
var lolbinMedium = map[string]bool{
	"mshta.exe": true, "certutil.exe": true, "bitsadmin.exe": true,
	"regsvr32.exe": true, "ftp.exe": true, "curl.exe": true,
	"finger.exe": true, "wsl.exe": true, "bash.exe": true,
	"forfiles.exe": true, "pcalua.exe": true, "esentutl.exe": true,
	"extrac32.exe": true, "hh.exe": true, "control.exe": true,
	"pktmon.exe": true, "replace.exe": true, "diantz.exe": true,
	"ie4uinit.exe": true, "presentationhost.exe": true,
	"syncappvpublishingserver.exe": true,
}

// High risk LOLBins (commonly used in attacks) - tier 3
var lolbinHigh = map[string]bool{
	"rundll32.exe": true, "msbuild.exe": true, "installutil.exe": true,
	"wmic.exe": true, "regasm.exe": true, "regsvcs.exe": true,
	"cmstp.exe": true, "odbcconf.exe": true, "msxsl.exe": true,
	"ieexec.exe": true, "mavinject.exe": true, "tracker.exe": true,
	"te.exe": true, "xwizard.exe": true, "pcwrun.exe": true,
	"scriptrunner.exe": true, "msdeploy.exe": true, "msdt.exe": true,
	"microsoft.workflow.compiler.exe": true,
}

// lolbins is a combined map for backward compatibility with IsLOLBin.
var lolbins = func() map[string]bool {
	m := make(map[string]bool)
	for k := range lolbinLow {
		m[k] = true
	}
	for k := range lolbinMedium {
		m[k] = true
	}
	for k := range lolbinHigh {
		m[k] = true
	}
	return m
}()

// LOLBinRisk returns the risk tier for a LOLBin: 0=none, 1=low, 2=medium, 3=high.
func LOLBinRisk(name string) int {
	n := strings.ToLower(name)
	if lolbinHigh[n] {
		return 3
	}
	if lolbinMedium[n] {
		return 2
	}
	if lolbinLow[n] {
		return 1
	}
	return 0
}

// IsLOLBin checks if the given process name is a known LOLBin.
func IsLOLBin(name string) bool {
	return lolbins[strings.ToLower(name)]
}

// knownElectronApps lists well-known Electron/desktop apps to reduce false positives.
var knownElectronApps = map[string]bool{
	"code.exe": true, "teams.exe": true, "slack.exe": true,
	"discord.exe": true, "obsidian.exe": true, "notion.exe": true,
	"atom.exe": true, "gitkraken.exe": true, "postman.exe": true,
	"figma.exe": true, "spotify.exe": true, "whatsapp.exe": true,
	"telegram.exe": true, "wechat.exe": true, "dingtalk.exe": true,
}

// IsElectronApp checks if a process name is a known Electron/desktop application.
func IsElectronApp(name string) bool {
	return knownElectronApps[strings.ToLower(name)]
}

// systemNamePaths lists legitimate directory patterns for system process names.
// Checked with hasSuffix so they work regardless of drive letter.
var systemNamePaths = map[string][]string{
	"svchost.exe":   {`\windows\system32\svchost.exe`},
	"csrss.exe":     {`\windows\system32\csrss.exe`},
	"lsass.exe":     {`\windows\system32\lsass.exe`},
	"services.exe":  {`\windows\system32\services.exe`},
	"smss.exe":      {`\windows\system32\smss.exe`},
	"wininit.exe":   {`\windows\system32\wininit.exe`},
	"winlogon.exe":  {`\windows\system32\winlogon.exe`},
	"explorer.exe":  {`\windows\explorer.exe`, `\windows\syswow64\explorer.exe`},
	"spoolsv.exe":   {`\windows\system32\spoolsv.exe`},
	"taskhost.exe":  {`\windows\system32\taskhost.exe`},
	"taskhostw.exe": {`\windows\system32\taskhostw.exe`},
	"conhost.exe":   {`\windows\system32\conhost.exe`},
	"dllhost.exe":   {`\windows\system32\dllhost.exe`, `\windows\syswow64\dllhost.exe`},
	"dwm.exe":       {`\windows\system32\dwm.exe`},
}

// Expected parent process relationships.
var expectedParents = map[string][]string{
	"svchost.exe":   {"services.exe", "microsoftedgeupdate.exe"},
	"lsass.exe":     {"wininit.exe"},
	"csrss.exe":     {"smss.exe"},
	"services.exe":  {"wininit.exe"},
	"wininit.exe":   {"smss.exe"},
	"winlogon.exe":  {"smss.exe"},
	"smss.exe":      {"smss.exe", "system", "[system process]"},
	"taskhostw.exe": {"svchost.exe"},
	"taskhost.exe":  {"svchost.exe"},
	"spoolsv.exe":   {"services.exe"},
	"dllhost.exe":   {"svchost.exe", "services.exe"},
}

// Known trusted vendors for Anti-FP.
var trustedVendors = []string{
	"microsoft",
	"google",
	"adobe",
	"mozilla",
	"apple",
	"oracle",
	"tencent", "腾讯",
	"alibaba", "阿里",
	"baidu", "百度",
	"huawei", "华为",
	"kingsoft", "金山",
	"360", "奇虎", "qihu",
	"sangfor", "深信服",
	"vmware",
	"citrix",
	"intel",
	"nvidia",
	"amd",
	"realtek",
	"logitech",
	"dell",
	"hp ", "hewlett",
	"lenovo", "联想",
}

// PathCategory classifies the executable path.
type PathCategory int

const (
	PathUnknown      PathCategory = iota
	PathSystem32                  // C:\Windows\System32, SysWOW64
	PathWindows                   // C:\Windows\*
	PathProgramFiles              // C:\Program Files\*, C:\Program Files (x86)\*
	PathWindowsApps               // C:\Program Files\WindowsApps\*
	PathProgramData               // C:\ProgramData\*
	PathUserDir                   // C:\Users\*\AppData, Temp, Downloads, Desktop, etc.
	PathTemp                      // C:\Windows\Temp, C:\Temp
	PathOther
)

// ContextResult holds contextual analysis results.
type ContextResult struct {
	ParentName          string
	IsLOLBin            bool
	PathAbnormal        bool
	IsMasquerade        bool
	AbnormalParentChain bool
	PathCat             PathCategory
}

// Analyze performs context analysis on a process.
func Analyze(name, path string, parentName string) *ContextResult {
	result := &ContextResult{
		ParentName: parentName,
	}

	nameLower := strings.ToLower(name)
	pathLower := strings.ToLower(path)

	// Check LOLBin
	result.IsLOLBin = lolbins[nameLower]

	// Classify path
	result.PathCat = classifyPath(pathLower)

	// Check path abnormality
	if path != "" {
		result.PathAbnormal = result.PathCat == PathUserDir || result.PathCat == PathTemp
	}

	// Check masquerade: system process name running from non-system path
	if validSuffixes, ok := systemNamePaths[nameLower]; ok && path != "" {
		isMasq := true
		for _, suffix := range validSuffixes {
			if strings.HasSuffix(pathLower, suffix) {
				isMasq = false
				break
			}
		}
		result.IsMasquerade = isMasq
	}

	// Check abnormal parent chain
	if expected, ok := expectedParents[nameLower]; ok && parentName != "" {
		parentLower := strings.ToLower(parentName)
		found := false
		for _, ep := range expected {
			if parentLower == ep {
				found = true
				break
			}
		}
		if !found {
			result.AbnormalParentChain = true
		}
	}

	return result
}

func classifyPath(pathLower string) PathCategory {
	if pathLower == "" {
		return PathUnknown
	}

	dir := strings.ToLower(filepath.Dir(pathLower))

	// System32 / SysWOW64
	if strings.HasPrefix(dir, `c:\windows\system32`) || strings.HasPrefix(dir, `c:\windows\syswow64`) {
		return PathSystem32
	}

	// WindowsApps (before ProgramFiles check)
	if strings.Contains(dir, `\windowsapps\`) {
		return PathWindowsApps
	}

	// Program Files
	if strings.HasPrefix(dir, `c:\program files\`) || strings.HasPrefix(dir, `c:\program files (x86)\`) {
		return PathProgramFiles
	}

	// ProgramData
	if strings.HasPrefix(dir, `c:\programdata\`) {
		return PathProgramData
	}

	// Temp
	if strings.HasPrefix(dir, `c:\windows\temp`) || strings.HasPrefix(dir, `c:\temp`) {
		return PathTemp
	}

	// User directories
	if strings.HasPrefix(dir, `c:\users\`) {
		// Allow some known-good sub-paths
		if strings.Contains(dir, `\appdata\local\microsoft\`) {
			return PathProgramFiles // treat as trusted
		}
		if strings.Contains(dir, `\appdata\local\programs\`) {
			return PathProgramFiles // user-installed programs (e.g. VS Code)
		}
		return PathUserDir
	}

	// Other Windows paths
	if strings.HasPrefix(dir, `c:\windows\`) {
		return PathWindows
	}

	return PathOther
}

// IsOfficeProcess checks if a process name looks like an Office application.
func IsOfficeProcess(name string) bool {
	officeNames := []string{
		"winword.exe", "excel.exe", "powerpnt.exe",
		"outlook.exe", "msaccess.exe", "onenote.exe",
	}
	nameLower := strings.ToLower(name)
	for _, n := range officeNames {
		if nameLower == n {
			return true
		}
	}
	return false
}

// IsBrowser checks if a process name looks like a browser.
func IsBrowser(name string) bool {
	browsers := []string{
		"chrome.exe", "msedge.exe", "firefox.exe",
		"iexplore.exe", "brave.exe", "opera.exe",
	}
	nameLower := strings.ToLower(name)
	for _, b := range browsers {
		if nameLower == b {
			return true
		}
	}
	return false
}

// IsScriptEngine checks if a process is a scripting engine.
func IsScriptEngine(name string) bool {
	engines := []string{
		"powershell.exe", "pwsh.exe", "cmd.exe",
		"wscript.exe", "cscript.exe", "mshta.exe",
	}
	nameLower := strings.ToLower(name)
	for _, e := range engines {
		if nameLower == e {
			return true
		}
	}
	return false
}

// IsSystemTool checks if a process is a system administration tool.
func IsSystemTool(name string) bool {
	tools := []string{
		"cmd.exe", "powershell.exe", "pwsh.exe",
		"reg.exe", "regedit.exe", "sc.exe",
		"net.exe", "net1.exe", "netsh.exe",
		"schtasks.exe", "at.exe", "wmic.exe",
		"taskkill.exe", "tasklist.exe",
	}
	nameLower := strings.ToLower(name)
	for _, t := range tools {
		if nameLower == t {
			return true
		}
	}
	return false
}

// IsTrustedVendor checks if signer/company matches a known trusted vendor.
func IsTrustedVendor(signer, company string) bool {
	combined := strings.ToLower(signer + " " + company)
	for _, v := range trustedVendors {
		if strings.Contains(combined, v) {
			return true
		}
	}
	return false
}

// IsMicrosoftSigner checks if signer is Microsoft.
func IsMicrosoftSigner(signer string) bool {
	s := strings.ToLower(signer)
	return strings.Contains(s, "microsoft") || strings.Contains(s, "windows")
}
