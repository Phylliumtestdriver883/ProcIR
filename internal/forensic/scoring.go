package forensic

import (
	"strings"
	"time"

	"procir/internal/types"
)

// ScoreAll scores all forensic entries.
func ScoreAll(entries []*types.ForensicEntry) {
	for _, e := range entries {
		scoreEntry(e)
	}
}

func scoreEntry(e *types.ForensicEntry) {
	e.Score = 0
	if e.Reasons == nil {
		e.Reasons = []string{}
	}

	pathLower := strings.ToLower(e.Path)
	cmdLower := strings.ToLower(e.CommandLine)

	switch e.Source {
	case types.ForensicPrefetch:
		scorePrefetch(e, pathLower)
	case types.ForensicRecentFile:
		scoreRecentFile(e, pathLower)
	case types.ForensicEventLog:
		scoreEventLog(e, pathLower, cmdLower)
	case types.ForensicModule:
		scoreModule(e)
	}
}

func scorePrefetch(e *types.ForensicEntry, _ string) {
	exeLower := strings.ToLower(e.ExeName)

	// Check if exe name suggests user directory execution
	// Prefetch doesn't store full path in filename, but unusual names are suspicious
	e.Score += 5
	e.Reasons = append(e.Reasons, "Prefetch历史记录")

	// Recent execution (within 24h)
	if isRecentTime(e.LastRunTime, 24*time.Hour) {
		e.Score += 10
		e.Reasons = append(e.Reasons, "最近24小时执行")
	} else if isRecentTime(e.LastRunTime, 72*time.Hour) {
		e.Score += 5
		e.Reasons = append(e.Reasons, "最近72小时执行")
	}

	// LOLBin prefetch
	if isLOLBinName(exeLower) {
		e.Score += 5
		e.Reasons = append(e.Reasons, "LOLBin执行痕迹")
	}

	// Suspicious names (often malware patterns)
	if len(exeLower) <= 5 || strings.Contains(exeLower, "tmp") ||
		strings.Contains(exeLower, "temp") || strings.HasPrefix(exeLower, "a.") ||
		strings.HasPrefix(exeLower, "1.") || strings.HasPrefix(exeLower, "x.") {
		e.Score += 15
		e.Reasons = append(e.Reasons, "可疑文件名")
	}
}

func scoreRecentFile(e *types.ForensicEntry, pathLower string) {
	// Base score for recent suspicious file
	isRecent24h := isRecentTime(e.FileModTime, 24*time.Hour)

	switch e.FileType {
	case "exe":
		if isRecent24h {
			e.Score += 20
			e.Reasons = append(e.Reasons, "最近24小时新建/修改可执行文件")
		} else {
			e.Score += 15
			e.Reasons = append(e.Reasons, "最近72小时新建/修改可执行文件")
		}
	case "dll":
		if isRecent24h {
			e.Score += 18
			e.Reasons = append(e.Reasons, "最近24小时新建/修改DLL")
		} else {
			e.Score += 12
			e.Reasons = append(e.Reasons, "最近72小时新建/修改DLL")
		}
	case "script":
		if isRecent24h {
			e.Score += 15
			e.Reasons = append(e.Reasons, "最近24小时新建/修改脚本")
		} else {
			e.Score += 10
			e.Reasons = append(e.Reasons, "最近72小时新建/修改脚本")
		}
	}

	// User directory
	if strings.HasPrefix(pathLower, `c:\users\`) {
		e.Score += 10
		e.Reasons = append(e.Reasons, "用户目录")
	}

	// Temp directory
	if strings.Contains(pathLower, `\temp\`) || strings.Contains(pathLower, `\tmp\`) {
		e.Score += 10
		e.Reasons = append(e.Reasons, "临时目录")
	}

	// ProgramData
	if strings.HasPrefix(pathLower, `c:\programdata\`) {
		e.Score += 5
		e.Reasons = append(e.Reasons, "ProgramData目录")
	}
}

func scoreEventLog(e *types.ForensicEntry, pathLower, cmdLower string) {
	switch e.EventID {
	case 4688: // Process creation
		e.Score += 10
		e.Reasons = append(e.Reasons, "历史进程创建事件")

		if strings.Contains(pathLower, `\users\`) || strings.Contains(pathLower, `\temp\`) {
			e.Score += 10
			e.Reasons = append(e.Reasons, "用户/临时目录执行")
		}

		if strings.Contains(cmdLower, "-enc") || strings.Contains(cmdLower, "frombase64") {
			e.Score += 20
			e.Reasons = append(e.Reasons, "命令行包含编码执行")
		}

		if strings.Contains(cmdLower, "downloadstring") || strings.Contains(cmdLower, "invoke-webrequest") ||
			strings.Contains(cmdLower, "net.webclient") {
			e.Score += 20
			e.Reasons = append(e.Reasons, "命令行包含下载行为")
		}

	case 4104: // PowerShell script block
		e.Score += 15
		e.Reasons = append(e.Reasons, "可疑PowerShell脚本执行")

		if strings.Contains(cmdLower, "invoke-mimikatz") || strings.Contains(cmdLower, "invoke-shellcode") ||
			strings.Contains(cmdLower, "amsiutils") {
			e.Score += 30
			e.Reasons = append(e.Reasons, "高危PowerShell工具调用")
		}

	case 7045: // Service installation
		e.Score += 15
		e.Reasons = append(e.Reasons, "服务安装事件")

		if strings.Contains(pathLower, `\users\`) || strings.Contains(pathLower, `\temp\`) {
			e.Score += 15
			e.Reasons = append(e.Reasons, "服务指向用户/临时目录")
		}

		if strings.Contains(cmdLower, "powershell") || strings.Contains(cmdLower, "cmd") ||
			strings.Contains(cmdLower, "mshta") {
			e.Score += 15
			e.Reasons = append(e.Reasons, "服务调用脚本引擎")
		}

	case 4698: // Task creation
		e.Score += 15
		e.Reasons = append(e.Reasons, "任务创建事件")
	}
}

func scoreModule(e *types.ForensicEntry) {
	// Base score from reasons already set in collector
	for _, r := range e.Reasons {
		switch r {
		case "用户目录DLL":
			e.Score += 25
		case "临时目录DLL":
			e.Score += 25
		case "系统DLL名伪装(非系统路径)":
			e.Score += 25
		case "ProgramData目录DLL":
			e.Score += 15
		case "未签名":
			e.Score += 20
		}
	}
}

func isRecentTime(timeStr string, duration time.Duration) bool {
	t, err := time.ParseInLocation("2006-01-02 15:04:05", timeStr, time.Local)
	if err != nil {
		return false
	}
	return time.Since(t) < duration
}

func isLOLBinName(name string) bool {
	lolbins := []string{
		"powershell.exe", "pwsh.exe", "cmd.exe", "mshta.exe",
		"wscript.exe", "cscript.exe", "rundll32.exe", "regsvr32.exe",
		"certutil.exe", "bitsadmin.exe", "msiexec.exe",
	}
	for _, l := range lolbins {
		if name == l {
			return true
		}
	}
	return false
}
