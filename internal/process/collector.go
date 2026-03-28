package process

import (
	"fmt"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ProcessInfo holds raw process data from the OS.
type ProcessInfo struct {
	PID         uint32
	PPID        uint32
	Name        string
	Path        string
	CommandLine string
	User        string
	StartTime   string
}

var (
	modntdll                       = windows.NewLazySystemDLL("ntdll.dll")
	procNtQueryInformationProcess  = modntdll.NewProc("NtQueryInformationProcess")
	modkernel32                    = windows.NewLazySystemDLL("kernel32.dll")
	procQueryFullProcessImageNameW = modkernel32.NewProc("QueryFullProcessImageNameW")
)

// Collect enumerates all active processes and returns their info.
func Collect() []ProcessInfo {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil
	}
	defer windows.CloseHandle(snapshot)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	err = windows.Process32First(snapshot, &entry)
	if err != nil {
		return nil
	}

	var results []ProcessInfo
	for {
		info := ProcessInfo{
			PID:  entry.ProcessID,
			PPID: entry.ParentProcessID,
			Name: windows.UTF16ToString(entry.ExeFile[:]),
		}

		info.Path = getProcessPath(entry.ProcessID)
		info.CommandLine = getCommandLine(entry.ProcessID)
		info.User = getProcessUser(entry.ProcessID)
		info.StartTime = getProcessStartTime(entry.ProcessID)

		results = append(results, info)

		err = windows.Process32Next(snapshot, &entry)
		if err != nil {
			break
		}
	}

	return results
}

func getProcessPath(pid uint32) string {
	if pid == 0 || pid == 4 {
		return ""
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(h)

	buf := make([]uint16, 1024)
	size := uint32(len(buf))
	r, _, _ := procQueryFullProcessImageNameW.Call(
		uintptr(h),
		0,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
	)
	if r == 0 {
		return ""
	}
	return windows.UTF16ToString(buf[:size])
}

func getCommandLine(pid uint32) string {
	if pid == 0 || pid == 4 {
		return ""
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.PROCESS_VM_READ, false, pid)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(h)

	// Get PEB address via NtQueryInformationProcess
	type processBasicInformation struct {
		ExitStatus                   uintptr
		PebBaseAddress               uintptr
		AffinityMask                 uintptr
		BasePriority                 int32
		_                            [4]byte
		UniqueProcessId              uintptr
		InheritedFromUniqueProcessId uintptr
	}
	var pbi processBasicInformation
	var retLen uint32
	r, _, _ := procNtQueryInformationProcess.Call(
		uintptr(h),
		0, // ProcessBasicInformation
		uintptr(unsafe.Pointer(&pbi)),
		unsafe.Sizeof(pbi),
		uintptr(unsafe.Pointer(&retLen)),
	)
	if r != 0 {
		return ""
	}

	// Read RTL_USER_PROCESS_PARAMETERS pointer from PEB
	// Offset 0x20 on 64-bit for ProcessParameters
	var paramsAddr uintptr
	err = windows.ReadProcessMemory(h, pbi.PebBaseAddress+0x20, (*byte)(unsafe.Pointer(&paramsAddr)), unsafe.Sizeof(paramsAddr), nil)
	if err != nil {
		return ""
	}

	// UNICODE_STRING for CommandLine is at offset 0x70 in RTL_USER_PROCESS_PARAMETERS (64-bit)
	type unicodeString struct {
		Length        uint16
		MaximumLength uint16
		_             [4]byte
		Buffer        uintptr
	}
	var cmdLine unicodeString
	err = windows.ReadProcessMemory(h, paramsAddr+0x70, (*byte)(unsafe.Pointer(&cmdLine)), unsafe.Sizeof(cmdLine), nil)
	if err != nil {
		return ""
	}

	if cmdLine.Length == 0 || cmdLine.Buffer == 0 {
		return ""
	}

	cmdBuf := make([]byte, cmdLine.Length)
	err = windows.ReadProcessMemory(h, cmdLine.Buffer, &cmdBuf[0], uintptr(cmdLine.Length), nil)
	if err != nil {
		return ""
	}

	// Convert UTF-16LE bytes to string
	u16 := make([]uint16, cmdLine.Length/2)
	for i := range u16 {
		u16[i] = uint16(cmdBuf[i*2]) | uint16(cmdBuf[i*2+1])<<8
	}
	return strings.TrimSpace(windows.UTF16ToString(u16))
}

func getProcessUser(pid uint32) string {
	if pid == 0 || pid == 4 {
		return "SYSTEM"
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(h)

	var token syscall.Token
	err = syscall.OpenProcessToken(syscall.Handle(h), syscall.TOKEN_QUERY, &token)
	if err != nil {
		return ""
	}
	defer token.Close()

	user, err := token.GetTokenUser()
	if err != nil {
		return ""
	}

	account, domain, _, lookupErr := user.User.Sid.LookupAccount("")
	if lookupErr != nil {
		sidStr, _ := user.User.Sid.String()
		return sidStr
	}
	return fmt.Sprintf("%s\\%s", domain, account)
}

func getProcessStartTime(pid uint32) string {
	if pid == 0 || pid == 4 {
		return ""
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(h)

	var creation, exit, kernel, userTime windows.Filetime
	err = windows.GetProcessTimes(h, &creation, &exit, &kernel, &userTime)
	if err != nil {
		return ""
	}

	nsec := creation.Nanoseconds()
	t := time.Unix(0, nsec).UTC()
	// Windows FILETIME epoch is 1601-01-01, Go handles this via Nanoseconds()
	return t.Local().Format("2006-01-02 15:04:05")
}
