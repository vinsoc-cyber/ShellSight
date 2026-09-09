//go:build windows

package main

import (
	"fmt"
	"strings"
	"unsafe"

	"shellsight/internal/finding"
	"golang.org/x/sys/windows"
)

// Auto-discovery targets when the spec names no explicit PID. Kestrel/console apps run as dotnet.exe.
var autoDiscoverNames = map[string]bool{"w3wp.exe": true, "dotnet.exe": true, "iisexpress.exe": true}

// resolveTargets returns the PIDs to scan. Explicit PIDs from the spec win (explicit=true so
// "none found" is a failure); otherwise auto-discover by process name (explicit=false so "none
// found" is n/a, not a failure).
func resolveTargets(spec finding.TargetSpec) (pids []uint32, explicit bool) {
	if len(spec.PIDs) > 0 {
		for _, p := range spec.PIDs {
			if p > 0 {
				pids = append(pids, uint32(p))
			}
		}
		return pids, true
	}
	return discoverByName(autoDiscoverNames), false
}

func snapshotProcesses() ([]windows.ProcessEntry32, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snap)
	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	if err := windows.Process32First(snap, &pe); err != nil {
		return nil, err
	}
	var out []windows.ProcessEntry32
	for {
		out = append(out, pe)
		if err := windows.Process32Next(snap, &pe); err != nil {
			break
		}
	}
	return out, nil
}

func discoverByName(names map[string]bool) []uint32 {
	procs, err := snapshotProcesses()
	if err != nil {
		return nil
	}
	var pids []uint32
	for _, pe := range procs {
		if names[strings.ToLower(windows.UTF16ToString(pe.ExeFile[:]))] {
			pids = append(pids, pe.ProcessID)
		}
	}
	return pids
}

func procName(pid uint32) string {
	if procs, err := snapshotProcesses(); err == nil {
		for _, pe := range procs {
			if pe.ProcessID == pid {
				return windows.UTF16ToString(pe.ExeFile[:])
			}
		}
	}
	return fmt.Sprintf("pid%d", pid)
}

// openProcess opens a target READ-ONLY (query + read; never write/operation).
func openProcess(pid uint32) (windows.Handle, error) {
	return windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, pid)
}

// enableSeDebug best-effort enables SeDebugPrivilege (needed only for cross-session targets like a
// SYSTEM-owned w3wp; same-user fixtures don't need it). Silent no-op if not held.
func enableSeDebug() {
	var tok windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(),
		windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &tok); err != nil {
		return
	}
	defer tok.Close()
	name, err := windows.UTF16PtrFromString("SeDebugPrivilege")
	if err != nil {
		return
	}
	var luid windows.LUID
	if err := windows.LookupPrivilegeValue(nil, name, &luid); err != nil {
		return
	}
	tp := windows.Tokenprivileges{PrivilegeCount: 1}
	tp.Privileges[0] = windows.LUIDAndAttributes{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED}
	_ = windows.AdjustTokenPrivileges(tok, false, &tp, 0, nil, nil)
}
