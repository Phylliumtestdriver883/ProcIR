package event

import (
	"fmt"
	"os"
	"strings"
	"sync"

	"procir/internal/types"
)

// CollectResult holds all collected event evidence.
type CollectResult struct {
	Events []*types.EventEvidence
	Errors []string
}

// CollectAll runs all event collectors and returns unified results.
func CollectAll(cfg *types.EventCollectConfig) *CollectResult {
	if cfg == nil {
		cfg = &types.EventCollectConfig{MaxAgeDays: 3, MaxEvents: 2000}
	}
	if cfg.MaxAgeDays == 0 {
		cfg.MaxAgeDays = 3
	}
	if cfg.MaxEvents == 0 {
		cfg.MaxEvents = 2000
	}

	var mu sync.Mutex
	result := &CollectResult{}

	add := func(evts []*types.EventEvidence, err error) {
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			result.Errors = append(result.Errors, err.Error())
			return
		}
		result.Events = append(result.Events, evts...)
	}

	var wg sync.WaitGroup

	// Determine if we're using offline EVTX or live logs
	isFile := cfg.OfflinePath != ""

	type job struct {
		name string
		fn   func(*types.EventCollectConfig) ([]*types.EventEvidence, error)
	}

	jobs := []job{
		{"Security-ProcessCreation", collectSecurityProcessCreation},
		{"Security-TaskCreation", collectSecurityTaskEvents},
		{"Security-ServiceInstall", collectSecurityServiceInstall},
		{"Security-Logon", collectSecurityLogon},
		{"System-ServiceInstall", collectSystemServiceInstall},
		{"PowerShell-ScriptBlock", collectPowerShellScriptBlock},
		{"TaskScheduler", collectTaskScheduler},
		{"WMI-Activity", collectWMIActivity},
	}

	// Add Sysmon if requested and present
	if cfg.IncludeSysmon || sysmonExists() {
		jobs = append(jobs, job{"Sysmon", collectSysmon})
	}

	// If offline mode, only process the single evtx file
	if isFile {
		wg.Add(1)
		go func() {
			defer wg.Done()
			evts, err := collectOfflineEvtx(cfg)
			add(evts, err)
		}()
	} else {
		for _, j := range jobs {
			wg.Add(1)
			go func(fn func(*types.EventCollectConfig) ([]*types.EventEvidence, error)) {
				defer wg.Done()
				evts, err := fn(cfg)
				add(evts, err)
			}(j.fn)
		}
	}

	wg.Wait()
	return result
}

func sysmonExists() bool {
	_, err := os.Stat(`C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx`)
	return err == nil
}

// --- Security: Process Creation (4688) ---

func collectSecurityProcessCreation(cfg *types.EventCollectConfig) ([]*types.EventEvidence, error) {
	query := fmt.Sprintf("*[System[EventID=4688 and TimeCreated[%s]]]", timeFilter(cfg.MaxAgeDays))
	evts, err := queryEvents("Security", query, cfg.MaxEvents, false)
	if err != nil {
		return nil, err
	}

	var results []*types.EventEvidence
	for _, e := range evts {
		proc := e.EventData.get("NewProcessName")
		cmd := e.EventData.get("CommandLine")
		parent := e.EventData.get("ParentProcessName")
		user := e.EventData.get("SubjectUserName")
		domain := e.EventData.get("SubjectDomainName")

		if proc == "" {
			continue
		}

		fullUser := user
		if domain != "" {
			fullUser = domain + `\` + user
		}

		results = append(results, &types.EventEvidence{
			Source:      "Security",
			EventID:     4688,
			Time:        parseTime(e.System.TimeCreated.SystemTime),
			Computer:    e.System.Computer,
			User:        fullUser,
			Description: fmt.Sprintf("进程创建: %s → %s", baseName(parent), baseName(proc)),
			ProcessPath: proc,
			CommandLine: cmd,
			ParentPath:  parent,
			ProcessID:   e.EventData.get("NewProcessId"),
		})
	}
	return results, nil
}

// --- Security: Task Creation/Modification (4698, 4702) ---

func collectSecurityTaskEvents(cfg *types.EventCollectConfig) ([]*types.EventEvidence, error) {
	query := fmt.Sprintf("*[System[(EventID=4698 or EventID=4702) and TimeCreated[%s]]]", timeFilter(cfg.MaxAgeDays))
	evts, err := queryEvents("Security", query, cfg.MaxEvents/2, false)
	if err != nil {
		return nil, err
	}

	var results []*types.EventEvidence
	for _, e := range evts {
		taskName := e.EventData.get("TaskName")
		taskContent := e.EventData.get("TaskContent")
		user := e.EventData.get("SubjectUserName")

		desc := "创建计划任务"
		if e.System.EventID == 4702 {
			desc = "修改计划任务"
		}

		results = append(results, &types.EventEvidence{
			Source:      "Security",
			EventID:     e.System.EventID,
			Time:        parseTime(e.System.TimeCreated.SystemTime),
			Computer:    e.System.Computer,
			User:        user,
			Description: fmt.Sprintf("%s: %s", desc, taskName),
			TaskName:    taskName,
			CommandLine: truncStr(taskContent, 500),
		})
	}
	return results, nil
}

// --- Security: Service Install (4697) ---

func collectSecurityServiceInstall(cfg *types.EventCollectConfig) ([]*types.EventEvidence, error) {
	query := fmt.Sprintf("*[System[EventID=4697 and TimeCreated[%s]]]", timeFilter(cfg.MaxAgeDays))
	evts, err := queryEvents("Security", query, cfg.MaxEvents/2, false)
	if err != nil {
		return nil, err
	}

	var results []*types.EventEvidence
	for _, e := range evts {
		svcName := e.EventData.get("ServiceName")
		svcFile := e.EventData.get("ServiceFileName")
		user := e.EventData.get("SubjectUserName")

		results = append(results, &types.EventEvidence{
			Source:      "Security",
			EventID:     4697,
			Time:        parseTime(e.System.TimeCreated.SystemTime),
			Computer:    e.System.Computer,
			User:        user,
			Description: fmt.Sprintf("服务安装(Security): %s → %s", svcName, truncStr(svcFile, 100)),
			ServiceName: svcName,
			TargetPath:  svcFile,
		})
	}
	return results, nil
}

// --- Security: Logon Events (4624, 4625, 4648, 4672) ---

func collectSecurityLogon(cfg *types.EventCollectConfig) ([]*types.EventEvidence, error) {
	query := fmt.Sprintf("*[System[(EventID=4624 or EventID=4625 or EventID=4648 or EventID=4672) and TimeCreated[%s]]]", timeFilter(cfg.MaxAgeDays))
	evts, err := queryEvents("Security", query, cfg.MaxEvents, false)
	if err != nil {
		return nil, err
	}

	var results []*types.EventEvidence
	for _, e := range evts {
		user := e.EventData.get("TargetUserName")
		if user == "" {
			user = e.EventData.get("SubjectUserName")
		}
		domain := e.EventData.get("TargetDomainName")
		logonType := e.EventData.get("LogonType")
		ipAddr := e.EventData.get("IpAddress")
		if ipAddr == "-" {
			ipAddr = ""
		}

		// Filter: only keep interesting logon events
		interesting := false
		desc := ""

		switch e.System.EventID {
		case 4624:
			// Only flag network/remote logons (type 3,10) and service logons (type 5)
			if logonType == "3" || logonType == "10" || logonType == "5" {
				interesting = true
				desc = fmt.Sprintf("登录成功(类型%s): %s\\%s", logonType, domain, user)
			}
		case 4625:
			interesting = true
			desc = fmt.Sprintf("登录失败(类型%s): %s\\%s", logonType, domain, user)
		case 4648:
			interesting = true
			targetUser := e.EventData.get("TargetUserName")
			targetServer := e.EventData.get("TargetServerName")
			desc = fmt.Sprintf("显式凭证登录: %s → %s@%s", user, targetUser, targetServer)
		case 4672:
			// Special privilege logon - only if non-SYSTEM
			if !strings.EqualFold(user, "SYSTEM") && !strings.EqualFold(user, "LOCAL SERVICE") && !strings.EqualFold(user, "NETWORK SERVICE") {
				interesting = true
				desc = fmt.Sprintf("特权登录: %s\\%s", domain, user)
			}
		}

		if !interesting {
			continue
		}

		results = append(results, &types.EventEvidence{
			Source:      "Security",
			EventID:     e.System.EventID,
			Time:        parseTime(e.System.TimeCreated.SystemTime),
			Computer:    e.System.Computer,
			User:        fmt.Sprintf("%s\\%s", domain, user),
			Description: desc,
			LogonType:   logonType,
			IPAddress:   ipAddr,
		})
	}
	return results, nil
}

// --- System: Service Install (7045) ---

func collectSystemServiceInstall(cfg *types.EventCollectConfig) ([]*types.EventEvidence, error) {
	query := fmt.Sprintf("*[System[EventID=7045 and TimeCreated[%s]]]", timeFilter(cfg.MaxAgeDays*2)) // wider window for services
	evts, err := queryEvents("System", query, cfg.MaxEvents/2, false)
	if err != nil {
		return nil, err
	}

	var results []*types.EventEvidence
	for _, e := range evts {
		svcName := e.EventData.get("ServiceName")
		imagePath := e.EventData.get("ImagePath")
		svcType := e.EventData.get("ServiceType")
		startType := e.EventData.get("StartType")

		results = append(results, &types.EventEvidence{
			Source:      "System",
			EventID:     7045,
			Time:        parseTime(e.System.TimeCreated.SystemTime),
			Computer:    e.System.Computer,
			Description: fmt.Sprintf("服务安装: %s [类型:%s 启动:%s]", svcName, svcType, startType),
			ServiceName: svcName,
			TargetPath:  imagePath,
		})
	}
	return results, nil
}

// --- PowerShell: Script Block Logging (4104) ---

func collectPowerShellScriptBlock(cfg *types.EventCollectConfig) ([]*types.EventEvidence, error) {
	query := fmt.Sprintf("*[System[EventID=4104 and TimeCreated[%s]]]", timeFilter(cfg.MaxAgeDays))
	evts, err := queryEvents("Microsoft-Windows-PowerShell/Operational", query, cfg.MaxEvents, false)
	if err != nil {
		return nil, err
	}

	var results []*types.EventEvidence
	for _, e := range evts {
		scriptBlock := e.EventData.get("ScriptBlockText")
		if scriptBlock == "" {
			continue
		}

		results = append(results, &types.EventEvidence{
			Source:      "PowerShell",
			EventID:     4104,
			Time:        parseTime(e.System.TimeCreated.SystemTime),
			Computer:    e.System.Computer,
			Description: "PowerShell脚本块: " + truncStr(scriptBlock, 120),
			ProcessPath: "powershell.exe",
			CommandLine: truncStr(scriptBlock, 2000),
		})
	}
	return results, nil
}

// --- TaskScheduler: Task Execution ---

func collectTaskScheduler(cfg *types.EventCollectConfig) ([]*types.EventEvidence, error) {
	// 106=task registered, 200=action started, 201=action completed
	query := fmt.Sprintf("*[System[(EventID=106 or EventID=200) and TimeCreated[%s]]]", timeFilter(cfg.MaxAgeDays))
	evts, err := queryEvents("Microsoft-Windows-TaskScheduler/Operational", query, cfg.MaxEvents/2, false)
	if err != nil {
		return nil, err
	}

	var results []*types.EventEvidence
	for _, e := range evts {
		taskName := e.EventData.get("TaskName")
		if taskName == "" {
			taskName = e.EventData.get("Name")
		}
		actionName := e.EventData.get("ActionName")

		desc := "计划任务注册"
		if e.System.EventID == 200 {
			desc = "计划任务执行"
		}

		results = append(results, &types.EventEvidence{
			Source:      "TaskScheduler",
			EventID:     e.System.EventID,
			Time:        parseTime(e.System.TimeCreated.SystemTime),
			Computer:    e.System.Computer,
			Description: fmt.Sprintf("%s: %s", desc, taskName),
			TaskName:    taskName,
			TargetPath:  actionName,
		})
	}
	return results, nil
}

// --- WMI Activity ---

func collectWMIActivity(cfg *types.EventCollectConfig) ([]*types.EventEvidence, error) {
	query := fmt.Sprintf("*[System[TimeCreated[%s]]]", timeFilter(cfg.MaxAgeDays))
	evts, err := queryEvents("Microsoft-Windows-WMI-Activity/Operational", query, cfg.MaxEvents/4, false)
	if err != nil {
		return nil, err
	}

	var results []*types.EventEvidence
	for _, e := range evts {
		operation := e.EventData.get("Operation")
		if operation == "" {
			continue
		}

		results = append(results, &types.EventEvidence{
			Source:      "WMI",
			EventID:     e.System.EventID,
			Time:        parseTime(e.System.TimeCreated.SystemTime),
			Computer:    e.System.Computer,
			Description: "WMI操作: " + truncStr(operation, 150),
			CommandLine: operation,
		})
	}
	return results, nil
}

// --- Sysmon ---

func collectSysmon(cfg *types.EventCollectConfig) ([]*types.EventEvidence, error) {
	// Event IDs: 1(process), 3(network), 7(imageload), 11(filecreate), 13(regmod), 22(dns)
	query := fmt.Sprintf("*[System[(EventID=1 or EventID=3 or EventID=7 or EventID=11 or EventID=13 or EventID=22) and TimeCreated[%s]]]", timeFilter(cfg.MaxAgeDays))
	evts, err := queryEvents("Microsoft-Windows-Sysmon/Operational", query, cfg.MaxEvents, false)
	if err != nil {
		return nil, err
	}

	var results []*types.EventEvidence
	for _, e := range evts {
		ev := &types.EventEvidence{
			Source:   "Sysmon",
			EventID:  e.System.EventID,
			Time:     parseTime(e.System.TimeCreated.SystemTime),
			Computer: e.System.Computer,
			User:     e.EventData.get("User"),
		}

		switch e.System.EventID {
		case 1: // Process creation
			ev.ProcessPath = e.EventData.get("Image")
			ev.CommandLine = e.EventData.get("CommandLine")
			ev.ParentPath = e.EventData.get("ParentImage")
			ev.ProcessID = e.EventData.get("ProcessId")
			ev.Description = fmt.Sprintf("Sysmon进程创建: %s → %s", baseName(ev.ParentPath), baseName(ev.ProcessPath))
		case 3: // Network connection
			ev.ProcessPath = e.EventData.get("Image")
			ev.IPAddress = e.EventData.get("DestinationIp")
			ev.Port = e.EventData.get("DestinationPort")
			ev.Description = fmt.Sprintf("Sysmon网络连接: %s → %s:%s", baseName(ev.ProcessPath), ev.IPAddress, ev.Port)
		case 7: // Image loaded
			ev.ProcessPath = e.EventData.get("Image")
			ev.TargetPath = e.EventData.get("ImageLoaded")
			ev.Description = fmt.Sprintf("Sysmon模块加载: %s 加载 %s", baseName(ev.ProcessPath), baseName(ev.TargetPath))
		case 11: // File created
			ev.ProcessPath = e.EventData.get("Image")
			ev.TargetPath = e.EventData.get("TargetFilename")
			ev.Description = fmt.Sprintf("Sysmon文件创建: %s → %s", baseName(ev.ProcessPath), baseName(ev.TargetPath))
		case 13: // Registry modified
			ev.ProcessPath = e.EventData.get("Image")
			ev.TargetPath = e.EventData.get("TargetObject")
			ev.Description = fmt.Sprintf("Sysmon注册表修改: %s → %s", baseName(ev.ProcessPath), truncStr(ev.TargetPath, 80))
		case 22: // DNS query
			ev.ProcessPath = e.EventData.get("Image")
			ev.Domain = e.EventData.get("QueryName")
			ev.Description = fmt.Sprintf("Sysmon DNS查询: %s → %s", baseName(ev.ProcessPath), ev.Domain)
		default:
			continue
		}

		results = append(results, ev)
	}
	return results, nil
}

// --- Offline EVTX ---

func collectOfflineEvtx(cfg *types.EventCollectConfig) ([]*types.EventEvidence, error) {
	if _, err := os.Stat(cfg.OfflinePath); err != nil {
		return nil, fmt.Errorf("EVTX文件不存在: %s", cfg.OfflinePath)
	}

	// Query all events from the offline file (limited by maxEvents)
	evts, err := queryEvents(cfg.OfflinePath, "*", cfg.MaxEvents, true)
	if err != nil {
		return nil, err
	}

	var results []*types.EventEvidence
	for _, e := range evts {
		ev := &types.EventEvidence{
			Source:   "Offline:" + baseName(cfg.OfflinePath),
			EventID:  e.System.EventID,
			Time:     parseTime(e.System.TimeCreated.SystemTime),
			Computer: e.System.Computer,
		}

		// Extract common fields
		ev.ProcessPath = firstNonEmpty(e.EventData.get("NewProcessName"), e.EventData.get("Image"))
		ev.CommandLine = firstNonEmpty(e.EventData.get("CommandLine"), e.EventData.get("ScriptBlockText"))
		ev.ParentPath = firstNonEmpty(e.EventData.get("ParentProcessName"), e.EventData.get("ParentImage"))
		ev.User = firstNonEmpty(e.EventData.get("SubjectUserName"), e.EventData.get("TargetUserName"), e.EventData.get("User"))
		ev.ServiceName = e.EventData.get("ServiceName")
		ev.TaskName = e.EventData.get("TaskName")
		ev.TargetPath = firstNonEmpty(e.EventData.get("ServiceFileName"), e.EventData.get("ImagePath"), e.EventData.get("TargetFilename"))
		ev.IPAddress = e.EventData.get("IpAddress")

		ev.Description = fmt.Sprintf("EventID:%d %s", ev.EventID, describeEventID(ev.EventID))

		results = append(results, ev)
	}
	return results, nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" && v != "-" {
			return v
		}
	}
	return ""
}

func describeEventID(id int) string {
	m := map[int]string{
		4688: "进程创建", 4698: "任务创建", 4702: "任务修改", 4697: "服务安装",
		4624: "登录成功", 4625: "登录失败", 4648: "显式凭证", 4672: "特权登录",
		7045: "服务安装", 7036: "服务状态变化",
		4104: "PS脚本块", 4103: "PS模块日志",
		1: "进程创建(Sysmon)", 3: "网络连接(Sysmon)", 7: "模块加载(Sysmon)",
		11: "文件创建(Sysmon)", 13: "注册表修改(Sysmon)", 22: "DNS查询(Sysmon)",
	}
	if desc, ok := m[id]; ok {
		return desc
	}
	return ""
}
