package trigger

import (
	"fmt"
	"os/exec"
	"strings"

	"procir/internal/types"
)

// collectWMI detects WMI event subscriptions (high-value persistence).
// Uses wmic/PowerShell to query WMI subscriptions since direct COM is complex.
func collectWMI() []*types.TriggerEntry {
	var results []*types.TriggerEntry

	// Collect EventFilters
	filters := wmiQuery("__EventFilter", []string{"Name", "Query"})

	// Collect CommandLineEventConsumers
	cmdConsumers := wmiQuery("CommandLineEventConsumer", []string{"Name", "CommandLineTemplate", "ExecutablePath"})

	// Collect ActiveScriptEventConsumers
	scriptConsumers := wmiQuery("ActiveScriptEventConsumer", []string{"Name", "ScriptText", "ScriptFileName"})

	// Collect FilterToConsumerBindings
	bindings := wmiQuery("__FilterToConsumerBinding", []string{"Filter", "Consumer"})

	// Process CommandLineEventConsumers
	for _, c := range cmdConsumers {
		name := c["Name"]
		cmdLine := c["CommandLineTemplate"]
		exePath := c["ExecutablePath"]

		if cmdLine == "" && exePath == "" {
			continue
		}

		cmd := cmdLine
		if cmd == "" {
			cmd = exePath
		}

		// Find matching filter
		filterQuery := ""
		for _, b := range bindings {
			if strings.Contains(b["Consumer"], name) {
				filterName := extractWMIRef(b["Filter"])
				for _, f := range filters {
					if f["Name"] == filterName {
						filterQuery = f["Query"]
						break
					}
				}
				break
			}
		}

		entry := &types.TriggerEntry{
			Type:            types.TriggerWMI,
			Name:            name,
			Path:            extractExePath(cmd),
			CommandLine:     cmd,
			Detail:          fmt.Sprintf("WMI CommandLineConsumer: %s → %s", name, truncate(cmd, 100)),
			WMIFilterName:   findFilterForConsumer(name, bindings, filters),
			WMIFilterQuery:  filterQuery,
			WMIConsumerName: name,
			WMIConsumerCmd:  cmd,
		}

		results = append(results, entry)
	}

	// Process ActiveScriptEventConsumers
	for _, c := range scriptConsumers {
		name := c["Name"]
		scriptText := c["ScriptText"]
		scriptFile := c["ScriptFileName"]

		detail := scriptText
		if detail == "" {
			detail = scriptFile
		}
		if detail == "" {
			continue
		}

		entry := &types.TriggerEntry{
			Type:            types.TriggerWMI,
			Name:            name,
			Path:            scriptFile,
			CommandLine:     detail,
			Detail:          fmt.Sprintf("WMI ScriptConsumer: %s → %s", name, truncate(detail, 100)),
			WMIConsumerName: name,
			WMIConsumerCmd:  detail,
		}

		results = append(results, entry)
	}

	return results
}

// wmiQuery runs a WMI query via PowerShell and returns results as maps.
func wmiQuery(className string, fields []string) []map[string]string {
	fieldList := strings.Join(fields, ",")
	query := fmt.Sprintf(`Get-WmiObject -Namespace root\subscription -Class %s -ErrorAction SilentlyContinue | Select-Object %s | ForEach-Object { $fields = @(); foreach($f in '%s'.Split(',')) { $fields += "$f=$($_.$f)" }; $fields -join '|||' }`,
		className, fieldList, fieldList)

	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", query)
	out, err := cmd.Output()
	if err != nil {
		return nil
	}

	var results []map[string]string
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		m := make(map[string]string)
		parts := strings.Split(line, "|||")
		for _, part := range parts {
			kv := strings.SplitN(part, "=", 2)
			if len(kv) == 2 {
				m[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
			}
		}
		if len(m) > 0 {
			results = append(results, m)
		}
	}

	return results
}

func extractWMIRef(ref string) string {
	// WMI refs look like: \\.\root\subscription:__EventFilter.Name="name"
	if idx := strings.Index(ref, `Name="`); idx >= 0 {
		s := ref[idx+6:]
		if end := strings.Index(s, `"`); end >= 0 {
			return s[:end]
		}
	}
	return ref
}

func findFilterForConsumer(consumerName string, bindings []map[string]string, filters []map[string]string) string {
	for _, b := range bindings {
		if strings.Contains(b["Consumer"], consumerName) {
			filterName := extractWMIRef(b["Filter"])
			return filterName
		}
	}
	return ""
}
