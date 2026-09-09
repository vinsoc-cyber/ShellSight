//go:build windows

package orchestrator

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// peakWorkingSetSupported: Windows reports a live process's working set via psapi.
const peakWorkingSetSupported = true

var (
	psapiDLL                 = windows.NewLazySystemDLL("psapi.dll")
	procGetProcessMemoryInfo = psapiDLL.NewProc("GetProcessMemoryInfo")
)

// processMemoryCountersEx mirrors PROCESS_MEMORY_COUNTERS_EX (psapi.h). SIZE_T is pointer-sized,
// so uintptr keeps the layout correct on 386 as well as amd64/arm64.
type processMemoryCountersEx struct {
	cb                         uint32
	pageFaultCount             uint32
	peakWorkingSetSize         uintptr
	workingSetSize             uintptr
	quotaPeakPagedPoolUsage    uintptr
	quotaPagedPoolUsage        uintptr
	quotaPeakNonPagedPoolUsage uintptr
	quotaNonPagedPoolUsage     uintptr
	pagefileUsage              uintptr
	peakPagefileUsage          uintptr
	privateUsage               uintptr
}

// processMem holds a handle to the sampled process. Holding one handle for the whole run (rather
// than reopening by PID) means a PID reused after the probe exits can never be sampled by mistake.
type processMem struct{ handle windows.Handle }

// openProcessMem asks for the LEAST privilege that answers the question:
// PROCESS_QUERY_LIMITED_INFORMATION alone satisfies GetProcessMemoryInfo. A defensive tool must not
// request PROCESS_VM_READ it does not need — that combination is itself an EDR heuristic.
func openProcessMem(pid int) (*processMem, error) {
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return nil, err
	}
	return &processMem{handle: handle}, nil
}

// sample reads PeakWorkingSetSize — the peak Windows itself maintains for the process — rather than
// the instantaneous working set, so no sampling interval can miss a spike between polls.
func (p *processMem) sample() (int64, error) {
	var counters processMemoryCountersEx
	counters.cb = uint32(unsafe.Sizeof(counters))
	ret, _, err := procGetProcessMemoryInfo.Call(
		uintptr(p.handle), uintptr(unsafe.Pointer(&counters)), uintptr(counters.cb))
	if ret == 0 {
		return 0, err
	}
	return int64(counters.peakWorkingSetSize), nil
}

func (p *processMem) close() { _ = windows.CloseHandle(p.handle) }
