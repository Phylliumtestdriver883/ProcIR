package trigger

import (
	"fmt"
	"strings"

	"procir/internal/types"

	"golang.org/x/sys/windows/registry"
)

// collectRunKeys scans all Run/RunOnce registry keys.
func collectRunKeys() []*types.TriggerEntry {
	var results []*types.TriggerEntry

	keys := []struct {
		root     registry.Key
		path     string
		label    string
		userCtx  string
	}{
		{registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, "HKLM\\Run", "SYSTEM"},
		{registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`, "HKLM\\RunOnce", "SYSTEM"},
		{registry.LOCAL_MACHINE, `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run`, "HKLM\\Run(WOW64)", "SYSTEM"},
		{registry.LOCAL_MACHINE, `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce`, "HKLM\\RunOnce(WOW64)", "SYSTEM"},
		{registry.CURRENT_USER, `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, "HKCU\\Run", "CurrentUser"},
		{registry.CURRENT_USER, `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`, "HKCU\\RunOnce", "CurrentUser"},
	}

	for _, rk := range keys {
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

			entry := &types.TriggerEntry{
				Type:        types.TriggerRunKey,
				Name:        name,
				CommandLine: val,
				Path:        extractExePath(val),
				Detail:      fmt.Sprintf("%s → %s = %s", rk.label, name, truncate(val, 120)),
			}

			results = append(results, entry)
		}
		key.Close()
	}

	return results
}

// extractExePath tries to extract the executable path from a command line.
func extractExePath(cmdline string) string {
	cmd := strings.TrimSpace(cmdline)
	if cmd == "" {
		return ""
	}

	// Handle quoted path
	if cmd[0] == '"' {
		end := strings.Index(cmd[1:], `"`)
		if end >= 0 {
			return cmd[1 : end+1]
		}
	}

	// Try to find .exe boundary
	lower := strings.ToLower(cmd)
	if idx := strings.Index(lower, ".exe"); idx >= 0 {
		path := cmd[:idx+4]
		path = strings.Trim(path, `"`)
		return path
	}

	// Return first token
	parts := strings.Fields(cmd)
	if len(parts) > 0 {
		return strings.Trim(parts[0], `"`)
	}
	return cmd
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
