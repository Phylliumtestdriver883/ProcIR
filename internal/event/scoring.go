package event

import (
	"strings"

	"procir/internal/types"
)

// ScoreAll scores all event evidence entries.
func ScoreAll(events []*types.EventEvidence) {
	for _, e := range events {
		scoreEvent(e)
	}
}

func scoreEvent(e *types.EventEvidence) {
	e.Score = 0
	e.Reasons = nil

	cmdLower := strings.ToLower(e.CommandLine)
	procLower := strings.ToLower(e.ProcessPath)
	targetLower := strings.ToLower(e.TargetPath)

	switch e.EventID {
	case 4688, 1: // Process creation
		e.Score += 5
		e.Reasons = append(e.Reasons, "进程创建事件")

		// User/temp dir execution
		if isUserOrTemp(procLower) {
			e.Score += 15
			e.Reasons = append(e.Reasons, "用户/临时目录执行")
		}

		// Suspicious command line
		if hasSuspiciousCmdLine(cmdLower) {
			e.Score += 20
			e.Reasons = append(e.Reasons, "可疑命令行")
		}

		// LOLBin execution
		if isLOLBinPath(procLower) && hasSuspiciousCmdLine(cmdLower) {
			e.Score += 15
			e.Reasons = append(e.Reasons, "LOLBin可疑用法")
		}

	case 4104: // PowerShell script block
		e.Score += 10
		e.Reasons = append(e.Reasons, "PowerShell脚本块")

		if hasDangerousPSContent(cmdLower) {
			e.Score += 30
			e.Reasons = append(e.Reasons, "高危PowerShell内容")
		} else if hasSuspiciousPSContent(cmdLower) {
			e.Score += 20
			e.Reasons = append(e.Reasons, "可疑PowerShell内容")
		}

	case 4698, 4702: // Task creation/modification
		e.Score += 15
		e.Reasons = append(e.Reasons, "计划任务操作")

		if strings.Contains(cmdLower, "powershell") || strings.Contains(cmdLower, "cmd") ||
			strings.Contains(cmdLower, "mshta") || strings.Contains(cmdLower, "wscript") {
			e.Score += 15
			e.Reasons = append(e.Reasons, "任务调用脚本引擎")
		}
		if strings.Contains(cmdLower, "-enc") || strings.Contains(cmdLower, "http") {
			e.Score += 20
			e.Reasons = append(e.Reasons, "任务包含编码/URL")
		}

	case 4697, 7045: // Service installation
		e.Score += 15
		e.Reasons = append(e.Reasons, "服务安装事件")

		if isUserOrTemp(targetLower) {
			e.Score += 20
			e.Reasons = append(e.Reasons, "服务指向用户/临时目录")
		}
		if strings.Contains(targetLower, "powershell") || strings.Contains(targetLower, "cmd.exe") ||
			strings.Contains(targetLower, "mshta") {
			e.Score += 20
			e.Reasons = append(e.Reasons, "服务调用脚本引擎")
		}

	case 4624: // Logon
		e.Score += 5
		e.Reasons = append(e.Reasons, "登录事件")
		if e.LogonType == "10" {
			e.Score += 10
			e.Reasons = append(e.Reasons, "RDP远程登录")
		} else if e.LogonType == "3" && e.IPAddress != "" {
			e.Score += 5
			e.Reasons = append(e.Reasons, "网络登录")
		}

	case 4625: // Failed logon
		e.Score += 10
		e.Reasons = append(e.Reasons, "登录失败")

	case 4648: // Explicit credentials
		e.Score += 15
		e.Reasons = append(e.Reasons, "显式凭证使用")

	case 4672: // Privilege
		e.Score += 10
		e.Reasons = append(e.Reasons, "特权登录")

	case 3: // Sysmon network
		e.Score += 5
		e.Reasons = append(e.Reasons, "网络连接(Sysmon)")
		if isUserOrTemp(procLower) {
			e.Score += 15
			e.Reasons = append(e.Reasons, "用户目录程序外联")
		}

	case 7: // Sysmon image load
		e.Score += 3
		if isUserOrTemp(targetLower) {
			e.Score += 20
			e.Reasons = append(e.Reasons, "加载用户目录模块(Sysmon)")
		}

	case 11: // Sysmon file create
		e.Score += 3
		if isUserOrTemp(targetLower) && isExecutableExt(targetLower) {
			e.Score += 15
			e.Reasons = append(e.Reasons, "用户目录创建可执行文件(Sysmon)")
		}

	case 13: // Sysmon registry
		e.Score += 3
		if strings.Contains(targetLower, `\run\`) || strings.Contains(targetLower, `\runonce\`) {
			e.Score += 20
			e.Reasons = append(e.Reasons, "修改自启动注册表(Sysmon)")
		}

	case 22: // Sysmon DNS
		e.Score += 2
		if e.Domain != "" && isUserOrTemp(procLower) {
			e.Score += 10
			e.Reasons = append(e.Reasons, "用户目录程序DNS查询(Sysmon)")
		}
	}
}

func isUserOrTemp(path string) bool {
	return strings.HasPrefix(path, `c:\users\`) ||
		strings.Contains(path, `\temp\`) ||
		strings.Contains(path, `\tmp\`) ||
		strings.HasPrefix(path, `c:\programdata\`)
}

func isLOLBinPath(path string) bool {
	lolbins := []string{
		`\powershell.exe`, `\pwsh.exe`, `\cmd.exe`, `\mshta.exe`,
		`\wscript.exe`, `\cscript.exe`, `\rundll32.exe`, `\regsvr32.exe`,
		`\certutil.exe`, `\bitsadmin.exe`, `\msiexec.exe`, `\msbuild.exe`,
	}
	for _, l := range lolbins {
		if strings.HasSuffix(path, l) {
			return true
		}
	}
	return false
}

func hasSuspiciousCmdLine(cmd string) bool {
	patterns := []string{
		"-enc ", "-encodedcommand", "frombase64", "downloadstring",
		"invoke-expression", "iex ", "iex(", "-w hidden",
		"/i:http", "javascript:", "vbscript:", "-urlcache",
		"/transfer", "downloadfile", "invoke-webrequest",
		"net.webclient", "start-bitstransfer",
	}
	for _, p := range patterns {
		if strings.Contains(cmd, p) {
			return true
		}
	}
	return false
}

func hasDangerousPSContent(content string) bool {
	patterns := []string{
		"invoke-mimikatz", "invoke-shellcode", "invoke-kerberoast",
		"invoke-bloodhound", "amsiutils", "getprocaddress",
		"virtualalloc", "reflection.assembly", "invoke-dcomexec",
		"invoke-wmiexec", "invoke-smbexec", "invoke-psremoting",
		"sharphound", "rubeus", "seatbelt",
	}
	for _, p := range patterns {
		if strings.Contains(content, p) {
			return true
		}
	}
	return false
}

func hasSuspiciousPSContent(content string) bool {
	patterns := []string{
		"downloadstring", "downloadfile", "invoke-webrequest",
		"invoke-expression", "iex ", "iex(", "frombase64",
		"encodedcommand", "net.webclient", "bypass",
		"invoke-command", "enter-pssession", "new-pssession",
		"start-process", "start-job",
	}
	for _, p := range patterns {
		if strings.Contains(content, p) {
			return true
		}
	}
	return false
}

func isExecutableExt(path string) bool {
	exts := []string{".exe", ".dll", ".sys", ".scr", ".ps1", ".vbs", ".js", ".bat", ".cmd", ".hta"}
	for _, ext := range exts {
		if strings.HasSuffix(path, ext) {
			return true
		}
	}
	return false
}
