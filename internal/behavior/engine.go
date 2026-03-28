package behavior

import (
	"fmt"
	"strings"

	"procir/internal/types"
)

// Detect scans all data for known attack behavior chains.
func Detect(
	processes []*types.ProcessRecord,
	triggers []*types.TriggerEntry,
	forensics []*types.ForensicEntry,
) []*types.BehaviorChain {
	var chains []*types.BehaviorChain

	// Build lookup maps
	pidMap := make(map[uint32]*types.ProcessRecord)
	childMap := make(map[uint32][]*types.ProcessRecord) // parent PID → children
	for _, p := range processes {
		pidMap[p.PID] = p
		childMap[p.PPID] = append(childMap[p.PPID], p)
	}

	// Chain 1: Office macro attack (Office → script engine → external)
	chains = append(chains, detectOfficeMacro(processes, childMap)...)

	// Chain 2: Browser exploit (browser → cmd/ps → ...)
	chains = append(chains, detectBrowserExploit(processes, childMap)...)

	// Chain 3: Persistence execution (file drop → RunKey/Task → Prefetch execution)
	chains = append(chains, detectPersistenceExec(triggers, forensics)...)

	// Chain 4: WMI backdoor (WMI consumer → script engine → URL)
	chains = append(chains, detectWMIBackdoor(triggers)...)

	// Chain 5: DLL side-loading (legit process → user-dir DLL)
	chains = append(chains, detectDLLSideload(forensics)...)

	// Chain 6: Download-and-execute
	chains = append(chains, detectDownloadExec(processes)...)

	return chains
}

func detectOfficeMacro(procs []*types.ProcessRecord, childMap map[uint32][]*types.ProcessRecord) []*types.BehaviorChain {
	var chains []*types.BehaviorChain

	officeNames := map[string]bool{
		"winword.exe": true, "excel.exe": true, "powerpnt.exe": true,
		"outlook.exe": true, "msaccess.exe": true,
	}
	scriptNames := map[string]bool{
		"powershell.exe": true, "pwsh.exe": true, "cmd.exe": true,
		"wscript.exe": true, "cscript.exe": true, "mshta.exe": true,
	}

	for _, p := range procs {
		if !officeNames[strings.ToLower(p.Name)] {
			continue
		}
		children := childMap[p.PID]
		for _, child := range children {
			if !scriptNames[strings.ToLower(child.Name)] {
				continue
			}
			evidence := []string{
				fmt.Sprintf("Office进程: %s (PID:%d)", p.Name, p.PID),
				fmt.Sprintf("派生脚本引擎: %s (PID:%d)", child.Name, child.PID),
			}
			if child.CommandLine != "" {
				evidence = append(evidence, "命令行: "+truncate(child.CommandLine, 150))
			}
			if child.HasPublicIP {
				evidence = append(evidence, "存在公网连接")
			}

			score := 25
			// Escalate if command line is suspicious
			cmdLower := strings.ToLower(child.CommandLine)
			if strings.Contains(cmdLower, "-enc") || strings.Contains(cmdLower, "downloadstring") ||
				strings.Contains(cmdLower, "iex") {
				score = 40
			}

			chains = append(chains, &types.BehaviorChain{
				PatternName:  "宏攻击链 (Office→脚本引擎)",
				PatternScore: score,
				Evidence:     evidence,
				ObjectPaths:  []string{p.Path, child.Path},
			})
		}
	}
	return chains
}

func detectBrowserExploit(procs []*types.ProcessRecord, childMap map[uint32][]*types.ProcessRecord) []*types.BehaviorChain {
	var chains []*types.BehaviorChain

	browsers := map[string]bool{
		"chrome.exe": true, "msedge.exe": true, "firefox.exe": true,
		"iexplore.exe": true, "brave.exe": true,
	}
	sysTools := map[string]bool{
		"cmd.exe": true, "powershell.exe": true, "pwsh.exe": true,
		"rundll32.exe": true, "regsvr32.exe": true, "mshta.exe": true,
	}

	for _, p := range procs {
		if !browsers[strings.ToLower(p.Name)] {
			continue
		}
		children := childMap[p.PID]
		for _, child := range children {
			if !sysTools[strings.ToLower(child.Name)] {
				continue
			}
			// Skip Native Messaging
			cmdLower := strings.ToLower(child.CommandLine)
			if strings.Contains(cmdLower, "chrome-extension://") || strings.Contains(cmdLower, "nativemessaging") {
				continue
			}

			evidence := []string{
				fmt.Sprintf("浏览器: %s (PID:%d)", p.Name, p.PID),
				fmt.Sprintf("派生系统工具: %s (PID:%d)", child.Name, child.PID),
			}
			if child.CommandLine != "" {
				evidence = append(evidence, "命令行: "+truncate(child.CommandLine, 150))
			}

			chains = append(chains, &types.BehaviorChain{
				PatternName:  "浏览器利用链 (Browser→系统工具)",
				PatternScore: 20,
				Evidence:     evidence,
				ObjectPaths:  []string{p.Path, child.Path},
			})
		}
	}
	return chains
}

func detectPersistenceExec(triggers []*types.TriggerEntry, forensics []*types.ForensicEntry) []*types.BehaviorChain {
	var chains []*types.BehaviorChain

	// Build set of prefetch-seen executables
	prefetchSeen := make(map[string]bool)
	for _, f := range forensics {
		if f.Source == types.ForensicPrefetch {
			prefetchSeen[strings.ToLower(f.ExeName)] = true
		}
	}

	// Build set of recent files
	recentFiles := make(map[string]bool)
	for _, f := range forensics {
		if f.Source == types.ForensicRecentFile {
			recentFiles[strings.ToLower(f.Path)] = true
		}
	}

	for _, t := range triggers {
		if t.Type != types.TriggerRunKey && t.Type != types.TriggerTask && t.Type != types.TriggerService {
			continue
		}

		pathLower := strings.ToLower(t.Path)
		exeName := strings.ToLower(baseName(t.Path))

		hasRecentFile := recentFiles[pathLower]
		hasPrefetch := prefetchSeen[exeName]

		if hasRecentFile && hasPrefetch {
			chains = append(chains, &types.BehaviorChain{
				PatternName:  "持久化执行链 (文件落地→注册→执行)",
				PatternScore: 20,
				Evidence: []string{
					fmt.Sprintf("触发器: [%s] %s", t.Type, t.Name),
					fmt.Sprintf("目标路径: %s", t.Path),
					"最近文件修改: 是",
					"Prefetch执行记录: 是",
				},
				ObjectPaths: []string{t.Path},
			})
		} else if hasRecentFile || hasPrefetch {
			reason := "最近文件修改"
			if hasPrefetch {
				reason = "Prefetch执行记录"
			}
			chains = append(chains, &types.BehaviorChain{
				PatternName:  "持久化关联 (触发器+历史痕迹)",
				PatternScore: 15,
				Evidence: []string{
					fmt.Sprintf("触发器: [%s] %s", t.Type, t.Name),
					fmt.Sprintf("关联证据: %s", reason),
				},
				ObjectPaths: []string{t.Path},
			})
		}
	}

	return chains
}

func detectWMIBackdoor(triggers []*types.TriggerEntry) []*types.BehaviorChain {
	var chains []*types.BehaviorChain

	for _, t := range triggers {
		if t.Type != types.TriggerWMI {
			continue
		}

		cmdLower := strings.ToLower(t.CommandLine)
		hasScript := strings.Contains(cmdLower, "powershell") || strings.Contains(cmdLower, "cmd") ||
			strings.Contains(cmdLower, "mshta") || strings.Contains(cmdLower, "wscript")
		hasURL := strings.Contains(cmdLower, "http://") || strings.Contains(cmdLower, "https://")
		hasEnc := strings.Contains(cmdLower, "-enc") || strings.Contains(cmdLower, "base64")

		if hasScript && (hasURL || hasEnc) {
			chains = append(chains, &types.BehaviorChain{
				PatternName:  "WMI后门链 (WMI→脚本引擎→远程)",
				PatternScore: 30,
				Evidence: []string{
					fmt.Sprintf("WMI Consumer: %s", t.Name),
					fmt.Sprintf("命令: %s", truncate(t.CommandLine, 150)),
					fmt.Sprintf("脚本引擎: %v, URL: %v, 编码: %v", hasScript, hasURL, hasEnc),
				},
				ObjectPaths: []string{t.Path},
			})
		}
	}

	return chains
}

func detectDLLSideload(forensics []*types.ForensicEntry) []*types.BehaviorChain {
	var chains []*types.BehaviorChain

	for _, f := range forensics {
		if f.Source != types.ForensicModule {
			continue
		}

		pathLower := strings.ToLower(f.ModulePath)
		if strings.Contains(pathLower, `\users\`) || strings.Contains(pathLower, `\temp\`) ||
			strings.Contains(pathLower, `\appdata\`) {
			if !f.ModuleSigned {
				chains = append(chains, &types.BehaviorChain{
					PatternName:  "DLL侧加载链 (进程→用户目录DLL)",
					PatternScore: 25,
					Evidence: []string{
						fmt.Sprintf("宿主进程: %s (PID:%d)", f.ProcessName, f.ProcessPID),
						fmt.Sprintf("可疑DLL: %s", f.ModulePath),
						"签名: 否",
					},
					ObjectPaths: []string{f.ModulePath},
				})
			}
		}
	}
	return chains
}

func detectDownloadExec(procs []*types.ProcessRecord) []*types.BehaviorChain {
	var chains []*types.BehaviorChain

	for _, p := range procs {
		cmdLower := strings.ToLower(p.CommandLine)
		nameLower := strings.ToLower(p.Name)

		// cmd /c ... curl/certutil/bitsadmin ... && ... start/powershell
		if nameLower == "cmd.exe" && strings.Contains(cmdLower, "/c") {
			hasDownload := strings.Contains(cmdLower, "curl") || strings.Contains(cmdLower, "certutil") ||
				strings.Contains(cmdLower, "bitsadmin") || strings.Contains(cmdLower, "wget") ||
				strings.Contains(cmdLower, "invoke-webrequest")
			hasExec := strings.Contains(cmdLower, "start ") || strings.Contains(cmdLower, "powershell") ||
				strings.Contains(cmdLower, "&&") || strings.Contains(cmdLower, "|")

			if hasDownload && hasExec {
				chains = append(chains, &types.BehaviorChain{
					PatternName:  "下载执行链 (cmd /c 下载+执行)",
					PatternScore: 25,
					Evidence: []string{
						fmt.Sprintf("进程: %s (PID:%d)", p.Name, p.PID),
						fmt.Sprintf("命令行: %s", truncate(p.CommandLine, 200)),
					},
					ObjectPaths: []string{p.Path},
				})
			}
		}

		// PowerShell download + IEX in one line
		if (nameLower == "powershell.exe" || nameLower == "pwsh.exe") &&
			(strings.Contains(cmdLower, "downloadstring") || strings.Contains(cmdLower, "invoke-webrequest")) &&
			(strings.Contains(cmdLower, "iex") || strings.Contains(cmdLower, "invoke-expression")) {
			chains = append(chains, &types.BehaviorChain{
				PatternName:  "PowerShell下载执行链 (Download+IEX)",
				PatternScore: 30,
				Evidence: []string{
					fmt.Sprintf("进程: %s (PID:%d)", p.Name, p.PID),
					fmt.Sprintf("命令行: %s", truncate(p.CommandLine, 200)),
				},
				ObjectPaths: []string{p.Path},
			})
		}
	}

	return chains
}

func baseName(path string) string {
	if idx := strings.LastIndex(path, `\`); idx >= 0 {
		return path[idx+1:]
	}
	return path
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
