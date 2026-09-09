//go:build windows

package main

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	ntdll                        = windows.NewLazySystemDLL("ntdll.dll")
	procNtQueryInformationThread = ntdll.NewProc("NtQueryInformationThread")
)

const (
	threadQueryLimited              = 0x0800 // THREAD_QUERY_LIMITED_INFORMATION
	threadQuerySetWin32StartAddress = 9      // THREADINFOCLASS
)

// threadStarts returns the Win32 start address of every thread owned by pid. Threads we cannot
// open or query are skipped (best-effort). Uses the toolhelp snapshot (no elevation needed for
// same-user) + NtQueryInformationThread(ThreadQuerySetWin32StartAddress).
func threadStarts(pid uint32) ([]uintptr, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snap)

	var te windows.ThreadEntry32
	te.Size = uint32(unsafe.Sizeof(te))
	if err := windows.Thread32First(snap, &te); err != nil {
		return nil, err
	}
	var starts []uintptr
	for {
		if te.OwnerProcessID == pid {
			if h, err := windows.OpenThread(threadQueryLimited, false, te.ThreadID); err == nil {
				var start uintptr
				var retLen uint32
				r1, _, _ := procNtQueryInformationThread.Call(uintptr(h), threadQuerySetWin32StartAddress,
					uintptr(unsafe.Pointer(&start)), unsafe.Sizeof(start), uintptr(unsafe.Pointer(&retLen)))
				if r1 == 0 && start != 0 { // STATUS_SUCCESS
					starts = append(starts, start)
				}
				windows.CloseHandle(h)
			}
		}
		if err := windows.Thread32Next(snap, &te); err != nil {
			break // ERROR_NO_MORE_FILES
		}
	}
	return starts, nil
}
