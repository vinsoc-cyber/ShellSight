//go:build windows

package main

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	kernel32           = windows.NewLazySystemDLL("kernel32.dll")
	procVirtualQueryEx = kernel32.NewProc("VirtualQueryEx")
)

const (
	memCommit  = 0x1000
	memImage   = 0x1000000
	memMapped  = 0x40000
	memPrivate = 0x20000
)

// scanRegions walks the target's address space and returns every committed, EXECUTABLE region,
// classified. Non-executable and non-committed regions are skipped. Read failures on a single
// region are non-fatal (best-effort). Stops at the end of the address space (VirtualQueryEx == 0).
func scanRegions(h windows.Handle, mods []Module) ([]Region, error) {
	var regions []Region
	var addr uintptr
	var mbi windows.MemoryBasicInformation
	mbiSize := unsafe.Sizeof(mbi)
	for {
		r1, _, _ := procVirtualQueryEx.Call(uintptr(h), addr, uintptr(unsafe.Pointer(&mbi)), mbiSize)
		if r1 == 0 {
			break // past the last region / query failed
		}
		next := mbi.BaseAddress + mbi.RegionSize
		if next <= addr {
			break // no forward progress — defensive
		}
		if mbi.State == memCommit && isExecutable(mbi.Protect) {
			regions = append(regions, classifyRegion(h, mbi, mods))
		}
		addr = next
	}
	return regions, nil
}

// classifyRegion turns a raw MBI into a Region: type, backed-ness, and a best-effort "MZ" probe.
func classifyRegion(h windows.Handle, mbi windows.MemoryBasicInformation, mods []Module) Region {
	typ := "private"
	switch mbi.Type {
	case memImage:
		typ = "image"
	case memMapped:
		typ = "mapped"
	}
	r := Region{Base: mbi.BaseAddress, Size: mbi.RegionSize, Type: typ, Protect: mbi.Protect}

	// Backed = an image-typed region inside a known module's range. Private/mapped executable
	// regions, and image regions not matching any module, are unbacked.
	if typ == "image" && backedBy(mbi.BaseAddress, mods) {
		r.Backed = true
	}
	// PE-header probe (only meaningful for unbacked regions): "MZ" at base => a mapped PE image.
	if !r.Backed {
		var hdr [2]byte
		var n uintptr
		if err := windows.ReadProcessMemory(h, mbi.BaseAddress, &hdr[0], 2, &n); err == nil && n == 2 {
			if hdr[0] == 'M' && hdr[1] == 'Z' {
				r.HasPEHeader = true
			}
		}
	}
	return r
}
