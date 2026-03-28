package trigger

import (
	"strings"

	"procir/internal/types"
)

// ScoreEntry evaluates a single TriggerEntry and assigns score + reasons.
func ScoreEntry(e *types.TriggerEntry) {
	e.Score = 0
	e.Reasons = nil

	cmdLower := strings.ToLower(e.CommandLine)
	pathLower := strings.ToLower(e.Path)

	// Base score by trigger type
	switch e.Type {
	case types.TriggerRunKey:
		e.Score += 15
		e.Reasons = append(e.Reasons, "注册表自启动项")
	case types.TriggerStartup:
		e.Score += 15
		e.Reasons = append(e.Reasons, "启动文件夹项")
	case types.TriggerTask:
		e.Score += 20
		e.Reasons = append(e.Reasons, "计划任务")
	case types.TriggerService:
		e.Score += 20
		e.Reasons = append(e.Reasons, "系统服务")
	case types.TriggerWMI:
		e.Score += 30
		e.Reasons = append(e.Reasons, "WMI事件订阅")
	case types.TriggerIFEO:
		e.Score += 25
		e.Reasons = append(e.Reasons, "IFEO调试器劫持")
	case types.TriggerWinlogon:
		e.Score += 25
		e.Reasons = append(e.Reasons, "Winlogon劫持")
	}

	// --- Path checks ---

	// User directory
	if isUserPath(pathLower) || isUserPath(strings.ToLower(e.CommandLine)) {
		e.Score += 20
		e.Reasons = append(e.Reasons, "指向用户目录")
	}

	// Temp directory
	if isTempPath(pathLower) {
		e.Score += 20
		e.Reasons = append(e.Reasons, "指向临时目录")
	}

	// --- Command line checks ---

	// PowerShell / cmd / mshta usage
	if containsLOLBin(cmdLower) {
		e.Score += 20
		e.Reasons = append(e.Reasons, "使用LOLBin执行")
	}

	// Encoded / Base64
	if strings.Contains(cmdLower, "-enc") || strings.Contains(cmdLower, "-encodedcommand") ||
		strings.Contains(cmdLower, "frombase64") || strings.Contains(cmdLower, "base64") {
		e.Score += 30
		e.Reasons = append(e.Reasons, "包含编码/Base64")
	}

	// URL download
	if strings.Contains(cmdLower, "http://") || strings.Contains(cmdLower, "https://") {
		e.Score += 25
		e.Reasons = append(e.Reasons, "包含URL")
	}

	// IEX / Invoke-Expression
	if strings.Contains(cmdLower, "invoke-expression") || strings.Contains(cmdLower, "iex ") ||
		strings.Contains(cmdLower, "iex(") {
		e.Score += 30
		e.Reasons = append(e.Reasons, "包含IEX内存执行")
	}

	// Download commands
	if strings.Contains(cmdLower, "downloadstring") || strings.Contains(cmdLower, "downloadfile") ||
		strings.Contains(cmdLower, "invoke-webrequest") || strings.Contains(cmdLower, "net.webclient") ||
		strings.Contains(cmdLower, "start-bitstransfer") || strings.Contains(cmdLower, "certutil") ||
		strings.Contains(cmdLower, "bitsadmin") {
		e.Score += 20
		e.Reasons = append(e.Reasons, "包含下载行为")
	}

	// --- Task-specific rules ---
	if e.Type == types.TriggerTask {
		if e.TaskHidden {
			e.Score += 10
			e.Reasons = append(e.Reasons, "隐藏任务")
		}

		runAsLower := strings.ToLower(e.TaskRunAs)
		if strings.Contains(runAsLower, "system") || strings.Contains(runAsLower, "s-1-5-18") {
			e.Score += 10
			e.Reasons = append(e.Reasons, "SYSTEM权限运行")
		}

		// Frequent execution (interval like PT5M = every 5 min)
		if e.TaskInterval != "" && isFrequentInterval(e.TaskInterval) {
			e.Score += 10
			e.Reasons = append(e.Reasons, "高频执行")
		}

		// Task name masquerade
		if isTaskNameMasquerade(e.Name) {
			e.Score += 10
			e.Reasons = append(e.Reasons, "任务名伪装系统任务")
		}
	}

	// --- Service-specific rules ---
	if e.Type == types.TriggerService {
		if e.ServiceStartType == "Auto" && isUserPath(pathLower) {
			e.Score += 25
			e.Reasons = append(e.Reasons, "自动启动+用户目录")
		}

		if e.ServiceStartType == "Auto" && e.ServiceState == "Stopped" {
			e.Score += 10
			e.Reasons = append(e.Reasons, "自动启动但已停止")
		}

		// Service binary is PowerShell/cmd
		pathBase := strings.ToLower(e.Path)
		if strings.HasSuffix(pathBase, "powershell.exe") || strings.HasSuffix(pathBase, "cmd.exe") ||
			strings.HasSuffix(pathBase, "mshta.exe") || strings.HasSuffix(pathBase, "pwsh.exe") {
			e.Score += 20
			e.Reasons = append(e.Reasons, "服务指向脚本引擎")
		}
	}

	// --- WMI-specific rules ---
	if e.Type == types.TriggerWMI {
		if strings.Contains(cmdLower, "powershell") || strings.Contains(cmdLower, "cmd") ||
			strings.Contains(cmdLower, "mshta") || strings.Contains(cmdLower, "wscript") ||
			strings.Contains(cmdLower, "cscript") {
			e.Score += 20
			e.Reasons = append(e.Reasons, "WMI调用脚本引擎")
		}
	}
}

// ScoreAll scores all trigger entries.
func ScoreAll(entries []*types.TriggerEntry) {
	for _, e := range entries {
		ScoreEntry(e)
	}
}

func isUserPath(p string) bool {
	return strings.HasPrefix(p, `c:\users\`) ||
		strings.Contains(p, `\appdata\`) ||
		strings.Contains(p, `\downloads\`) ||
		strings.Contains(p, `\desktop\`)
}

func isTempPath(p string) bool {
	return strings.Contains(p, `\temp\`) || strings.Contains(p, `\tmp\`)
}

func containsLOLBin(cmd string) bool {
	lolbins := []string{
		"powershell", "pwsh", "cmd.exe", "mshta", "wscript",
		"cscript", "rundll32", "regsvr32", "certutil", "bitsadmin",
		"msiexec", "msbuild", "installutil",
	}
	for _, l := range lolbins {
		if strings.Contains(cmd, l) {
			return true
		}
	}
	return false
}

func isFrequentInterval(interval string) bool {
	// PT5M, PT10M, PT1H etc - flag intervals under 1 hour
	interval = strings.ToUpper(interval)
	if strings.Contains(interval, "PT") {
		// Has minutes but no hours
		if strings.Contains(interval, "M") && !strings.Contains(interval, "H") {
			return true
		}
	}
	return false
}

func isTaskNameMasquerade(name string) bool {
	// Common masquerade patterns
	lower := strings.ToLower(name)
	masqueradePatterns := []string{
		"microsoft", "windows", "system", "update", "defender",
		"google", "chrome", "adobe", "office",
	}
	// If the task is NOT under Microsoft/Windows paths but uses these names
	if !strings.Contains(lower, "/microsoft/") && !strings.Contains(lower, "/windows/") {
		for _, p := range masqueradePatterns {
			if strings.Contains(lower, p) {
				return true
			}
		}
	}
	return false
}
