//go:build windows

package main

import (
	"fmt"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	psapi                    = windows.NewLazySystemDLL("psapi.dll")
	procEnumProcessModulesEx = psapi.NewProc("EnumProcessModulesEx")
	procGetModuleFileNameExW = psapi.NewProc("GetModuleFileNameExW")
	procGetModuleInformation = psapi.NewProc("GetModuleInformation")
)

const listModulesAll = 0x03 // LIST_MODULES_ALL

// MODULEINFO (psapi.h)
type moduleInfo struct {
	lpBaseOfDll uintptr
	sizeOfImage uint32
	entryPoint  uintptr
}

// enumModules lists every loaded module in the target with its in-memory range. Two-call pattern:
// first call discovers the needed buffer size, second fills it.
func enumModules(h windows.Handle) ([]Module, error) {
	var needed uint32
	r1, _, e := procEnumProcessModulesEx.Call(uintptr(h), 0, 0, uintptr(unsafe.Pointer(&needed)), listModulesAll)
	if r1 == 0 {
		return nil, fmt.Errorf("EnumProcessModulesEx(size): %w", e)
	}
	hsize := unsafe.Sizeof(windows.Handle(0))
	count := int(uintptr(needed) / hsize)
	if count == 0 {
		return nil, nil
	}
	handles := make([]windows.Handle, count)
	r1, _, e = procEnumProcessModulesEx.Call(uintptr(h), uintptr(unsafe.Pointer(&handles[0])),
		uintptr(needed), uintptr(unsafe.Pointer(&needed)), listModulesAll)
	if r1 == 0 {
		return nil, fmt.Errorf("EnumProcessModulesEx: %w", e)
	}
	if got := int(uintptr(needed) / hsize); got < count {
		count = got
	}
	mods := make([]Module, 0, count)
	buf := make([]uint16, windows.MAX_PATH)
	for i := 0; i < count; i++ {
		hm := handles[i]
		var path string
		if n, _, _ := procGetModuleFileNameExW.Call(uintptr(h), uintptr(hm),
			uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf))); n > 0 {
			path = windows.UTF16ToString(buf[:n])
		}
		var mi moduleInfo
		procGetModuleInformation.Call(uintptr(h), uintptr(hm), uintptr(unsafe.Pointer(&mi)), unsafe.Sizeof(mi))
		mods = append(mods, Module{
			Name: strings.ToLower(filepath.Base(path)),
			Path: path,
			Base: mi.lpBaseOfDll,
			Size: uintptr(mi.sizeOfImage),
		})
	}
	return mods, nil
}
