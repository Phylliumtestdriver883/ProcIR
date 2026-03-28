package module

import (
	"path/filepath"
	"strings"
	"unsafe"

	"procir/internal/signature"
	"procir/internal/types"

	"golang.org/x/sys/windows"
)

// systemDLLNames are DLL names that should only exist in System32/SysWOW64.
// These are the most commonly abused for sideloading.
var systemDLLNames = map[string]bool{
	"kernel32.dll": true, "kernelbase.dll": true, "ntdll.dll": true,
	"user32.dll": true, "advapi32.dll": true, "gdi32.dll": true,
	"shell32.dll": true, "ole32.dll": true, "oleaut32.dll": true,
	"msvcrt.dll": true, "ws2_32.dll": true, "wininet.dll": true,
	"crypt32.dll": true, "secur32.dll": true, "rpcrt4.dll": true,
	"combase.dll": true, "shlwapi.dll": true, "urlmon.dll": true,
	"winhttp.dll": true, "winspool.drv": true, "uxtheme.dll": true,
	"dwmapi.dll": true, "userenv.dll": true, "netapi32.dll": true,
	"mswsock.dll": true, "iphlpapi.dll": true, "psapi.dll": true,
	"wintrust.dll": true, "setupapi.dll": true, "cfgmgr32.dll": true,
	"bcrypt.dll": true, "ncrypt.dll": true, "dpapi.dll": true,
	"cryptsp.dll": true, "cryptbase.dll": true, "sspicli.dll": true,
	// Commonly sideloaded names (high value)
	"version.dll": true, "dbghelp.dll": true, "dbgcore.dll": true,
	"msvcp140.dll": true, "vcruntime140.dll": true,
	"msasn1.dll": true, "profapi.dll": true, "propsys.dll": true,
	"dwrite.dll": true, "d3d11.dll": true, "dxgi.dll": true,
	"wtsapi32.dll": true, "amsi.dll": true, "clbcatq.dll": true,
	"edputil.dll": true, "fltlib.dll": true, "linkinfo.dll": true,
	"ntshrui.dll": true, "srvcli.dll": true, "cscapi.dll": true,
	"wer.dll": true, "devobj.dll": true, "msimg32.dll": true,
	"windowscodecs.dll": true, "textshaping.dll": true,
}

// systemProcesses are processes that should NEVER load DLLs from user dirs.
var systemProcesses = map[string]bool{
	"svchost.exe": true, "lsass.exe": true, "services.exe": true,
	"csrss.exe": true, "smss.exe": true, "wininit.exe": true,
	"winlogon.exe": true, "spoolsv.exe": true, "dwm.exe": true,
	"taskhostw.exe": true, "conhost.exe": true, "explorer.exe": true,
}

// AnalyzeProcess enumerates and analyzes all modules loaded by a process.
func AnalyzeProcess(pid uint32, exeName, exePath string, exeSigned bool, exeSigner string) *types.ModuleAnalysis {
	if pid == 0 || pid == 4 {
		return nil
	}

	result := &types.ModuleAnalysis{
		PID:       pid,
		ExeName:   exeName,
		ExePath:   exePath,
		ExeSigned: exeSigned,
		ExeSigner: exeSigner,
	}

	modules := enumerateModules(pid)
	if len(modules) == 0 {
		return result
	}

	result.TotalModules = len(modules)
	exeDir := strings.ToLower(filepath.Dir(exePath))

	// Signature cache to avoid re-checking the same DLL
	sigCache := make(map[string]*signature.SignatureInfo)

	for _, modPath := range modules {
		modLower := strings.ToLower(modPath)
		modName := strings.ToLower(filepath.Base(modPath))
		modDir := strings.ToLower(filepath.Dir(modPath))

		// Quick filter: skip known-good system paths
		if isSystemPath(modLower) {
			continue
		}
		// Skip the exe itself
		if strings.EqualFold(modPath, exePath) {
			continue
		}
		// Skip known runtime DLLs in their expected locations
		if isKnownGoodModule(modLower) {
			continue
		}

		// This module is outside system paths — analyze it
		mi := &types.ModuleInfo{
			Path:            modPath,
			Name:            filepath.Base(modPath),
			IsSystemDLLName: systemDLLNames[modName],
			IsSystemPath:    false,
			IsUserPath:      isUserPath(modLower),
			IsTempPath:      isTempPath(modLower),
			IsSameDirAsExe:  modDir == exeDir && exeDir != "",
		}

		// Check signature (with cache)
		if sig, ok := sigCache[modLower]; ok {
			mi.Signed = sig.Signed
			mi.Signer = sig.Signer
		} else {
			sig := signature.Analyze(modPath)
			mi.Signed = sig.Signed
			mi.Signer = sig.Signer
			sigCache[modLower] = sig
		}

		// Apply scoring rules
		scoreModule(mi, result)

		if mi.Score > 0 {
			result.SuspiciousModules = append(result.SuspiciousModules, mi)
			result.SuspiciousCount++
		}
	}

	// Aggregate scoring
	aggregateScore(result)

	return result
}

func enumerateModules(pid uint32) []string {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPMODULE|windows.TH32CS_SNAPMODULE32, pid)
	if err != nil {
		return nil
	}
	defer windows.CloseHandle(snap)

	var me windows.ModuleEntry32
	me.Size = uint32(unsafe.Sizeof(me))

	if err := windows.Module32First(snap, &me); err != nil {
		return nil
	}

	var modules []string
	first := true
	for {
		if !first { // skip first entry (the exe itself)
			modPath := windows.UTF16ToString(me.ExePath[:])
			if modPath != "" {
				modules = append(modules, modPath)
			}
		}
		first = false

		if err := windows.Module32Next(snap, &me); err != nil {
			break
		}
	}

	return modules
}

func isSystemPath(p string) bool {
	return strings.HasPrefix(p, `c:\windows\system32`) ||
		strings.HasPrefix(p, `c:\windows\syswow64`) ||
		strings.HasPrefix(p, `c:\windows\winsxs`) ||
		strings.HasPrefix(p, `c:\windows\microsoft.net`)
}

func isUserPath(p string) bool {
	if strings.HasPrefix(p, `c:\users\`) {
		// Exclude known-good sub-paths
		if strings.Contains(p, `\appdata\local\microsoft\`) {
			return false
		}
		return true
	}
	return false
}

func isTempPath(p string) bool {
	return strings.Contains(p, `\temp\`) || strings.Contains(p, `\tmp\`)
}

func isKnownGoodModule(p string) bool {
	// Program Files installed DLLs
	if strings.HasPrefix(p, `c:\program files\`) || strings.HasPrefix(p, `c:\program files (x86)\`) {
		return true
	}
	// Windows directory (but not winsxs which we already handled)
	if strings.HasPrefix(p, `c:\windows\`) {
		return true
	}
	return false
}
