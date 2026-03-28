package persistence

import (
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// Result holds persistence mechanisms associated with a process path.
type Result struct {
	Mechanisms []string
}

// Analyzer collects all persistence mechanisms and maps them to executable paths.
type Analyzer struct {
	byPath map[string][]string // normalized lowercase path -> mechanisms
}

func NewAnalyzer() *Analyzer {
	a := &Analyzer{
		byPath: make(map[string][]string),
	}
	a.collectRegistry()
	a.collectStartup()
	a.collectScheduledTasks()
	a.collectServices()
	return a
}

// GetByPath returns persistence mechanisms for a given executable path.
func (a *Analyzer) GetByPath(path string) *Result {
	if path == "" {
		return &Result{}
	}
	pathLower := strings.ToLower(path)

	var mechanisms []string
	for key, mechs := range a.byPath {
		if strings.Contains(key, pathLower) || strings.Contains(pathLower, key) {
			mechanisms = append(mechanisms, mechs...)
		}
	}

	return &Result{Mechanisms: mechanisms}
}

func (a *Analyzer) addEntry(path, mechanism string) {
	if path == "" {
		return
	}
	// Normalize: strip quotes, extract exe path
	path = strings.Trim(path, `"`)
	path = strings.TrimSpace(path)

	// Try to extract just the exe path from command lines
	if idx := strings.Index(strings.ToLower(path), ".exe"); idx >= 0 {
		path = path[:idx+4]
	}
	path = strings.Trim(path, `"`)
	pathLower := strings.ToLower(path)

	a.byPath[pathLower] = append(a.byPath[pathLower], mechanism)
}

func (a *Analyzer) collectRegistry() {
	regKeys := []struct {
		root registry.Key
		path string
		name string
	}{
		{registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, "HKLM\\Run"},
		{registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`, "HKLM\\RunOnce"},
		{registry.LOCAL_MACHINE, `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run`, "HKLM\\Run(WOW64)"},
		{registry.CURRENT_USER, `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, "HKCU\\Run"},
		{registry.CURRENT_USER, `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`, "HKCU\\RunOnce"},
	}

	for _, rk := range regKeys {
		key, err := registry.OpenKey(rk.root, rk.path, registry.READ)
		if err != nil {
			continue
		}

		names, err := key.ReadValueNames(-1)
		if err != nil {
			key.Close()
			continue
		}

		for _, name := range names {
			val, _, err := key.GetStringValue(name)
			if err != nil {
				continue
			}
			a.addEntry(val, rk.name+": "+name)
		}
		key.Close()
	}
}

func (a *Analyzer) collectStartup() {
	startupDirs := []string{
		filepath.Join(os.Getenv("APPDATA"), `Microsoft\Windows\Start Menu\Programs\Startup`),
		`C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp`,
	}

	for _, dir := range startupDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			ext := strings.ToLower(filepath.Ext(entry.Name()))
			if ext == ".lnk" || ext == ".exe" || ext == ".bat" || ext == ".cmd" || ext == ".vbs" {
				fullPath := filepath.Join(dir, entry.Name())
				a.addEntry(fullPath, "Startup: "+entry.Name())
			}
		}
	}
}

func (a *Analyzer) collectScheduledTasks() {
	// Use COM-free approach: read scheduled tasks via schtasks output
	// For reliability, use the Task Scheduler folder directly
	taskFolders := []string{
		`C:\Windows\System32\Tasks`,
	}

	for _, folder := range taskFolders {
		filepath.Walk(folder, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return nil
			}

			content := string(data)
			// Simple XML parsing - find <Command> tags
			for {
				idx := strings.Index(content, "<Command>")
				if idx < 0 {
					break
				}
				content = content[idx+9:]
				end := strings.Index(content, "</Command>")
				if end < 0 {
					break
				}
				cmd := strings.TrimSpace(content[:end])
				taskName := strings.TrimPrefix(path, folder)
				taskName = strings.ReplaceAll(taskName, `\`, "/")
				a.addEntry(cmd, "ScheduledTask: "+taskName)
				content = content[end:]
			}
			return nil
		})
	}
}

func (a *Analyzer) collectServices() {
	scmHandle, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_ENUMERATE_SERVICE)
	if err != nil {
		return
	}
	defer windows.CloseServiceHandle(scmHandle)

	var bytesNeeded, servicesReturned, resumeHandle uint32
	// First call to get required buffer size
	windows.EnumServicesStatusEx(
		scmHandle,
		windows.SC_ENUM_PROCESS_INFO,
		windows.SERVICE_WIN32,
		windows.SERVICE_STATE_ALL,
		nil,
		0,
		&bytesNeeded,
		&servicesReturned,
		&resumeHandle,
		nil,
	)

	if bytesNeeded == 0 {
		return
	}

	buf := make([]byte, bytesNeeded)
	err = windows.EnumServicesStatusEx(
		scmHandle,
		windows.SC_ENUM_PROCESS_INFO,
		windows.SERVICE_WIN32,
		windows.SERVICE_STATE_ALL,
		&buf[0],
		bytesNeeded,
		&bytesNeeded,
		&servicesReturned,
		&resumeHandle,
		nil,
	)
	if err != nil {
		return
	}

	type enumServiceStatusProcess struct {
		ServiceName          *uint16
		DisplayName          *uint16
		ServiceStatusProcess windows.SERVICE_STATUS_PROCESS
	}

	entrySize := unsafe.Sizeof(enumServiceStatusProcess{})
	for i := uint32(0); i < servicesReturned; i++ {
		entry := (*enumServiceStatusProcess)(unsafe.Pointer(&buf[uintptr(i)*entrySize]))
		serviceName := windows.UTF16PtrToString(entry.ServiceName)

		// Open service to get binary path
		svcHandle, err := windows.OpenService(scmHandle, entry.ServiceName, windows.SERVICE_QUERY_CONFIG)
		if err != nil {
			continue
		}

		var needed uint32
		windows.QueryServiceConfig(svcHandle, nil, 0, &needed)
		if needed == 0 {
			windows.CloseServiceHandle(svcHandle)
			continue
		}

		cfgBuf := make([]byte, needed)
		cfg := (*windows.QUERY_SERVICE_CONFIG)(unsafe.Pointer(&cfgBuf[0]))
		err = windows.QueryServiceConfig(svcHandle, cfg, needed, &needed)
		windows.CloseServiceHandle(svcHandle)
		if err != nil {
			continue
		}

		binaryPath := windows.UTF16PtrToString(cfg.BinaryPathName)
		if binaryPath != "" {
			a.addEntry(binaryPath, "Service: "+serviceName)
		}
	}
}
