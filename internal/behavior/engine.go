package behavior

import (
	"fmt"
	"strings"

	"procir/internal/i18n"
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

	// Chain 7: Credential access
	detectCredentialChain(processes, &chains)

	// Chain 8: AMSI/Defender bypass
	detectAMSIBypassChain(processes, &chains)

	// Chain 9: Lateral movement
	detectLateralMovementChain(processes, triggers, &chains)

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
				fmt.Sprintf(i18n.T("beh_office_proc"), p.Name, p.PID),
				fmt.Sprintf(i18n.T("beh_spawn_script"), child.Name, child.PID),
			}
			if child.CommandLine != "" {
				evidence = append(evidence, i18n.T("beh_cmdline")+truncate(child.CommandLine, 150))
			}
			if child.HasPublicIP {
				evidence = append(evidence, i18n.T("beh_public_conn"))
			}

			score := 25
			// Escalate if command line is suspicious
			cmdLower := strings.ToLower(child.CommandLine)
			if strings.Contains(cmdLower, "-enc") || strings.Contains(cmdLower, "downloadstring") ||
				strings.Contains(cmdLower, "iex") {
				score = 40
			}

			chains = append(chains, &types.BehaviorChain{
				PatternName:  i18n.T("beh_macro_chain"),
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
				fmt.Sprintf(i18n.T("beh_browser"), p.Name, p.PID),
				fmt.Sprintf(i18n.T("beh_spawn_tool"), child.Name, child.PID),
			}
			if child.CommandLine != "" {
				evidence = append(evidence, i18n.T("beh_cmdline")+truncate(child.CommandLine, 150))
			}

			chains = append(chains, &types.BehaviorChain{
				PatternName:  i18n.T("beh_browser_chain"),
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
				PatternName:  i18n.T("beh_persist_chain"),
				PatternScore: 20,
				Evidence: []string{
					fmt.Sprintf(i18n.T("beh_trigger_fmt"), t.Type, t.Name),
					fmt.Sprintf(i18n.T("beh_target_path"), t.Path),
					i18n.T("beh_recent_file_mod"),
					i18n.T("beh_prefetch_record"),
				},
				ObjectPaths: []string{t.Path},
			})
		} else if hasRecentFile || hasPrefetch {
			reason := i18n.T("beh_recent_file")
			if hasPrefetch {
				reason = i18n.T("beh_prefetch")
			}
			chains = append(chains, &types.BehaviorChain{
				PatternName:  i18n.T("beh_persist_assoc"),
				PatternScore: 15,
				Evidence: []string{
					fmt.Sprintf(i18n.T("beh_trigger_fmt"), t.Type, t.Name),
					fmt.Sprintf(i18n.T("beh_assoc_evidence"), reason),
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
				PatternName:  i18n.T("beh_wmi_chain"),
				PatternScore: 30,
				Evidence: []string{
					fmt.Sprintf("WMI Consumer: %s", t.Name),
					fmt.Sprintf(i18n.T("beh_command"), truncate(t.CommandLine, 150)),
					fmt.Sprintf(i18n.T("beh_wmi_flags"), hasScript, hasURL, hasEnc),
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
					PatternName:  i18n.T("beh_dll_sideload_chain"),
					PatternScore: 25,
					Evidence: []string{
						fmt.Sprintf(i18n.T("beh_host_proc"), f.ProcessName, f.ProcessPID),
						fmt.Sprintf(i18n.T("beh_susp_dll"), f.ModulePath),
						i18n.T("beh_unsigned"),
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
					PatternName:  i18n.T("beh_download_chain"),
					PatternScore: 25,
					Evidence: []string{
						fmt.Sprintf(i18n.T("beh_process_fmt"), p.Name, p.PID),
						fmt.Sprintf(i18n.T("beh_cmdline_fmt"), truncate(p.CommandLine, 200)),
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
				PatternName:  i18n.T("beh_ps_download_chain"),
				PatternScore: 30,
				Evidence: []string{
					fmt.Sprintf(i18n.T("beh_process_fmt"), p.Name, p.PID),
					fmt.Sprintf(i18n.T("beh_cmdline_fmt"), truncate(p.CommandLine, 200)),
				},
				ObjectPaths: []string{p.Path},
			})
		}
	}

	return chains
}

// Chain 7: Credential access (privilege + LSASS access indicators)
func detectCredentialChain(records []*types.ProcessRecord, chains *[]*types.BehaviorChain) {
	for _, r := range records {
		cmdLower := strings.ToLower(r.CommandLine)
		nameLower := strings.ToLower(r.Name)

		// Detect credential dump tools
		isDumpTool := strings.Contains(cmdLower, "sekurlsa") ||
			strings.Contains(cmdLower, "minidump") ||
			(strings.Contains(cmdLower, "comsvcs") && strings.Contains(cmdLower, "minidump")) ||
			strings.Contains(cmdLower, "procdump") && strings.Contains(cmdLower, "lsass") ||
			strings.Contains(cmdLower, "nanodump") || strings.Contains(cmdLower, "dumpert") ||
			strings.Contains(cmdLower, "pypykatz") || strings.Contains(cmdLower, "handlekatz") ||
			nameLower == "mimikatz.exe"

		if !isDumpTool {
			continue
		}

		evidence := []string{
			fmt.Sprintf(i18n.T("beh_process_fmt"), r.Name, r.PID),
			fmt.Sprintf(i18n.T("beh_cmdline_fmt"), truncate(r.CommandLine, 120)),
		}

		score := 35
		if r.HasPublicIP || r.HasNetwork {
			evidence = append(evidence, i18n.T("beh_public_conn"))
			score = 40
		}

		*chains = append(*chains, &types.BehaviorChain{
			PatternName:  i18n.T("beh_cred_chain"),
			PatternScore: score,
			Evidence:     evidence,
			ObjectPaths:  []string{r.Path},
		})
	}
}

// Chain 8: AMSI/Defender bypass
func detectAMSIBypassChain(records []*types.ProcessRecord, chains *[]*types.BehaviorChain) {
	for _, r := range records {
		cmdLower := strings.ToLower(r.CommandLine)
		nameLower := strings.ToLower(r.Name)
		isPowerShell := nameLower == "powershell.exe" || nameLower == "pwsh.exe"
		if !isPowerShell {
			continue
		}

		hasAMSI := strings.Contains(cmdLower, "amsiinitfailed") || strings.Contains(cmdLower, "amsiutils")
		hasDefender := (strings.Contains(cmdLower, "set-mppreference") || strings.Contains(cmdLower, "add-mppreference")) &&
			(strings.Contains(cmdLower, "exclusion") || strings.Contains(cmdLower, "disablerealtimemonitoring"))

		if !hasAMSI && !hasDefender {
			continue
		}

		hasDownload := strings.Contains(cmdLower, "downloadstring") || strings.Contains(cmdLower, "invoke-webrequest") ||
			strings.Contains(cmdLower, "net.webclient")
		hasIEX := strings.Contains(cmdLower, "invoke-expression") || strings.Contains(cmdLower, "iex ")

		evidence := []string{
			fmt.Sprintf(i18n.T("beh_process_fmt"), r.Name, r.PID),
		}
		if hasAMSI {
			evidence = append(evidence, i18n.T("beh_amsi_bypass"))
		}
		if hasDefender {
			evidence = append(evidence, i18n.T("beh_defender_tamper"))
		}
		if hasDownload || hasIEX {
			evidence = append(evidence, fmt.Sprintf(i18n.T("beh_cmdline_fmt"), truncate(r.CommandLine, 120)))
		}

		score := 25
		if (hasAMSI || hasDefender) && (hasDownload || hasIEX) {
			score = 35
		}

		*chains = append(*chains, &types.BehaviorChain{
			PatternName:  i18n.T("beh_amsi_chain"),
			PatternScore: score,
			Evidence:     evidence,
			ObjectPaths:  []string{r.Path},
		})
	}
}

// Chain 9: Lateral movement
func detectLateralMovementChain(records []*types.ProcessRecord, triggers []*types.TriggerEntry, chains *[]*types.BehaviorChain) {
	for _, r := range records {
		cmdLower := strings.ToLower(r.CommandLine)
		nameLower := strings.ToLower(r.Name)

		isLateral := false
		var evidence []string

		// wmic remote exec
		if nameLower == "wmic.exe" && strings.Contains(cmdLower, "process call create") {
			isLateral = true
			evidence = append(evidence, fmt.Sprintf(i18n.T("beh_process_fmt"), r.Name, r.PID))
			evidence = append(evidence, i18n.T("beh_wmic_remote"))
		}

		// schtasks remote
		if nameLower == "schtasks.exe" && strings.Contains(cmdLower, "/create") && strings.Contains(cmdLower, "/s ") {
			isLateral = true
			evidence = append(evidence, fmt.Sprintf(i18n.T("beh_process_fmt"), r.Name, r.PID))
			evidence = append(evidence, i18n.T("beh_remote_task"))
		}

		// sc remote
		if nameLower == "sc.exe" && strings.Contains(cmdLower, `\\`) && strings.Contains(cmdLower, "create") {
			isLateral = true
			evidence = append(evidence, fmt.Sprintf(i18n.T("beh_process_fmt"), r.Name, r.PID))
			evidence = append(evidence, i18n.T("beh_remote_svc"))
		}

		// psexec / winrs
		if nameLower == "psexec.exe" || nameLower == "psexec64.exe" ||
			(nameLower == "winrs.exe") ||
			(strings.Contains(cmdLower, "enter-pssession") || strings.Contains(cmdLower, "invoke-command") && strings.Contains(cmdLower, "-computername")) {
			isLateral = true
			evidence = append(evidence, fmt.Sprintf(i18n.T("beh_process_fmt"), r.Name, r.PID))
			evidence = append(evidence, i18n.T("beh_remote_exec"))
		}

		if !isLateral {
			continue
		}

		*chains = append(*chains, &types.BehaviorChain{
			PatternName:  i18n.T("beh_lateral_chain"),
			PatternScore: 30,
			Evidence:     evidence,
			ObjectPaths:  []string{r.Path},
		})
	}
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
