//go:build windows

package main

import (
	"debug/pe"

	"golang.org/x/sys/windows"
)

const dirEntryBaseReloc = 5 // IMAGE_DIRECTORY_ENTRY_BASERELOC

// checkRegionStomp diffs a backed executable region's in-memory bytes against its on-disk module
// image (ASLR-rebased) and sets r.Stomped/Patched/ModifiedFrac/PatchRVAs. Best-effort: any failure
// (unreadable file, parse error, no overlap, read failure) leaves r unchanged (region stays clean).
func checkRegionStomp(h windows.Handle, m Module, r *Region) {
	pf, err := pe.Open(m.Path)
	if err != nil {
		return
	}
	defer pf.Close()

	imageBase, ok := peImageBase(pf)
	if !ok {
		return
	}
	delta := int64(m.Base) - int64(imageBase)
	rva := uint32(r.Base - m.Base)
	length := int(r.Size)

	secs := make([]sectionInfo, 0, len(pf.Sections))
	for _, s := range pf.Sections {
		raw, derr := s.Data()
		if derr != nil {
			raw = nil
		}
		secs = append(secs, sectionInfo{VA: s.VirtualAddress, VSize: s.VirtualSize, Raw: raw})
	}
	disk := diskBytesForRange(secs, rva, length)
	if disk == nil {
		return
	}
	if delta != 0 {
		applyRelocs(disk, rva, parseRelocs(relocDir(pf)), delta)
	}

	mem := make([]byte, length)
	var n uintptr
	if err := windows.ReadProcessMemory(h, r.Base, &mem[0], uintptr(length), &n); err != nil || n == 0 {
		return
	}
	if int(n) < length {
		mem = mem[:n]
		disk = disk[:n]
	}
	v := classifyStomp(diffBytes(mem, disk, rva), stompFrac, stompRun)
	r.Stomped, r.Patched, r.ModifiedFrac, r.PatchRVAs = v.Stomped, v.Patched, v.ModifiedFrac, v.PatchRVAs
}

// peImageBase returns the preferred ImageBase from the optional header (PE32 or PE32+).
func peImageBase(pf *pe.File) (uint64, bool) {
	switch oh := pf.OptionalHeader.(type) {
	case *pe.OptionalHeader64:
		return oh.ImageBase, true
	case *pe.OptionalHeader32:
		return uint64(oh.ImageBase), true
	default:
		return 0, false
	}
}

// relocDir returns the raw bytes of the base-relocation directory, or nil if the module has none.
func relocDir(pf *pe.File) []byte {
	var dd pe.DataDirectory
	switch oh := pf.OptionalHeader.(type) {
	case *pe.OptionalHeader64:
		dd = oh.DataDirectory[dirEntryBaseReloc]
	case *pe.OptionalHeader32:
		dd = oh.DataDirectory[dirEntryBaseReloc]
	default:
		return nil
	}
	if dd.VirtualAddress == 0 || dd.Size == 0 {
		return nil
	}
	for _, s := range pf.Sections {
		if dd.VirtualAddress >= s.VirtualAddress && dd.VirtualAddress < s.VirtualAddress+s.VirtualSize {
			raw, err := s.Data()
			if err != nil {
				return nil
			}
			start := dd.VirtualAddress - s.VirtualAddress
			if int(start) >= len(raw) {
				return nil
			}
			endo := start + dd.Size
			if int(endo) > len(raw) {
				endo = uint32(len(raw))
			}
			return raw[start:endo]
		}
	}
	return nil
}
