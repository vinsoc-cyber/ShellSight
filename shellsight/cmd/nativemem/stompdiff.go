package main

import "encoding/binary"

// Reloc is one base-relocation entry: the RVA it patches and its type.
type Reloc struct {
	RVA  uint32
	Type uint8
}

// PE base-relocation types.
const (
	relAbsolute = 0  // IMAGE_REL_BASED_ABSOLUTE (block padding; skipped)
	relHighLow  = 3  // IMAGE_REL_BASED_HIGHLOW  (32-bit absolute)
	relDir64    = 10 // IMAGE_REL_BASED_DIR64    (64-bit absolute)
)

// parseRelocs decodes the base-relocation directory (a sequence of IMAGE_BASE_RELOCATION blocks)
// into a flat (RVA, type) list. Each block: PageRVA uint32, BlockSize uint32, then
// (BlockSize-8)/2 uint16 entries (high 4 bits = type, low 12 = offset). ABSOLUTE padding skipped.
func parseRelocs(dir []byte) []Reloc {
	var out []Reloc
	for off := 0; off+8 <= len(dir); {
		pageRVA := binary.LittleEndian.Uint32(dir[off:])
		blockSize := binary.LittleEndian.Uint32(dir[off+4:])
		if blockSize < 8 || off+int(blockSize) > len(dir) {
			break
		}
		entries := (int(blockSize) - 8) / 2
		p := off + 8
		for i := 0; i < entries; i++ {
			e := binary.LittleEndian.Uint16(dir[p:])
			p += 2
			if typ := uint8(e >> 12); typ != relAbsolute {
				out = append(out, Reloc{RVA: pageRVA + uint32(e&0x0fff), Type: typ})
			}
		}
		off += int(blockSize)
	}
	return out
}

// applyRelocs rebases img in place. img holds bytes starting at RVA bufBase (img[k] is the byte at
// RVA bufBase+k). For each reloc that lands fully inside img, it adds delta to the absolute pointer
// stored there (HIGHLOW = 32-bit, DIR64 = 64-bit). Relocs outside img are ignored. Result: a disk
// image that matches what the loader produced at the actual (ASLR) load address.
func applyRelocs(img []byte, bufBase uint32, relocs []Reloc, delta int64) {
	for _, r := range relocs {
		if r.RVA < bufBase {
			continue
		}
		o := int(r.RVA - bufBase)
		switch r.Type {
		case relHighLow:
			if o >= 0 && o+4 <= len(img) {
				v := binary.LittleEndian.Uint32(img[o:])
				binary.LittleEndian.PutUint32(img[o:], uint32(int64(v)+delta))
			}
		case relDir64:
			if o >= 0 && o+8 <= len(img) {
				v := binary.LittleEndian.Uint64(img[o:])
				binary.LittleEndian.PutUint64(img[o:], uint64(int64(v)+delta))
			}
		}
	}
}

// sectionInfo is the on-disk layout of one PE section: its virtual address/size and raw bytes.
type sectionInfo struct {
	VA    uint32
	VSize uint32
	Raw   []byte
}

// diskBytesForRange assembles the expected pre-relocation bytes for the virtual range
// [rva, rva+length) from the on-disk sections: each overlapping section's raw data is copied to its
// virtual offset, zero-padded where Raw is shorter than VSize. Returns nil if no section overlaps
// (the region is not represented on disk → caller skips the diff).
func diskBytesForRange(secs []sectionInfo, rva uint32, length int) []byte {
	if length <= 0 {
		return nil
	}
	out := make([]byte, length)
	end := rva + uint32(length)
	covered := false
	for _, s := range secs {
		if s.VA >= end || s.VA+s.VSize <= rva {
			continue // no overlap
		}
		covered = true
		for k := 0; k < int(s.VSize); k++ {
			abs := s.VA + uint32(k)
			if abs < rva || abs >= end {
				continue
			}
			if k < len(s.Raw) {
				out[abs-rva] = s.Raw[k]
			} // else leave zero (zero-pad)
		}
	}
	if !covered {
		return nil
	}
	return out
}

// DiffResult summarizes a byte-compare of in-memory vs rebased-disk bytes.
type DiffResult struct {
	Modified   int
	Total      int
	MaxRun     int
	SampleRVAs []uint32
}

// diffBytes compares mem vs (rebased) disk and reports differing-byte count, longest contiguous
// differing run, and a small sample of differing RVAs (baseRVA + offset). Shorter length governs.
func diffBytes(mem, disk []byte, baseRVA uint32) DiffResult {
	n := len(mem)
	if len(disk) < n {
		n = len(disk)
	}
	const maxSamples = 16
	d := DiffResult{Total: n}
	run := 0
	for i := 0; i < n; i++ {
		if mem[i] != disk[i] {
			d.Modified++
			run++
			if run > d.MaxRun {
				d.MaxRun = run
			}
			if len(d.SampleRVAs) < maxSamples {
				d.SampleRVAs = append(d.SampleRVAs, baseRVA+uint32(i))
			}
		} else {
			run = 0
		}
	}
	return d
}

// StompVerdict is the tiered conclusion for one region's diff.
type StompVerdict struct {
	Stomped      bool
	Patched      bool
	ModifiedFrac float64
	PatchRVAs    []uint32
}

// Default thresholds (tunable; validated in the pilot).
const (
	stompFrac = 0.05 // >= 5% of bytes differ → wholesale (hollowing)
	stompRun  = 256  // OR a contiguous differing run >= 256 bytes → wholesale
)

// classifyStomp tiers a diff: wholesale modification (by fraction OR a long contiguous run) is a
// stomp/hollow; any smaller modification is an inline patch; zero modification is clean.
func classifyStomp(d DiffResult, fracThreshold float64, runThreshold int) StompVerdict {
	if d.Total == 0 || d.Modified == 0 {
		return StompVerdict{}
	}
	v := StompVerdict{ModifiedFrac: float64(d.Modified) / float64(d.Total), PatchRVAs: d.SampleRVAs}
	if v.ModifiedFrac >= fracThreshold || d.MaxRun >= runThreshold {
		v.Stomped = true
	} else {
		v.Patched = true
	}
	return v
}
