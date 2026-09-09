package main

import (
	"encoding/binary"
	"testing"
)

// buildRelocBlock encodes one IMAGE_BASE_RELOCATION block: pageRVA + entries (type<<12 | offset).
func buildRelocBlock(pageRVA uint32, entries []uint16) []byte {
	b := make([]byte, 8+2*len(entries))
	binary.LittleEndian.PutUint32(b[0:], pageRVA)
	binary.LittleEndian.PutUint32(b[4:], uint32(len(b)))
	for i, e := range entries {
		binary.LittleEndian.PutUint16(b[8+2*i:], e)
	}
	return b
}

func TestParseRelocs(t *testing.T) {
	// page 0x1000: DIR64@0x10, DIR64@0x20, ABSOLUTE(skip), HIGHLOW@0x30
	dir := buildRelocBlock(0x1000, []uint16{10<<12 | 0x10, 10<<12 | 0x20, 0, 3<<12 | 0x30})
	got := parseRelocs(dir)
	want := []Reloc{{0x1010, 10}, {0x1020, 10}, {0x1030, 3}}
	if len(got) != len(want) {
		t.Fatalf("got %d relocs, want %d (%v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("reloc[%d]=%+v want %+v", i, got[i], want[i])
		}
	}
}

func TestParseRelocsTruncatedBlockStops(t *testing.T) {
	dir := buildRelocBlock(0x2000, []uint16{3<<12 | 0x4})
	if r := parseRelocs(dir[:6]); len(r) != 0 { // header itself truncated → no entries
		t.Errorf("truncated dir must yield 0 relocs, got %v", r)
	}
}

func TestApplyRelocsDir64(t *testing.T) {
	img := make([]byte, 0x40) // represents RVA range starting at bufBase 0x1000
	binary.LittleEndian.PutUint64(img[0x10:], 0x140001000)
	applyRelocs(img, 0x1000, []Reloc{{0x1010, relDir64}}, 0x2000) // delta +0x2000
	if got := binary.LittleEndian.Uint64(img[0x10:]); got != 0x140003000 {
		t.Errorf("DIR64 rebase = 0x%x, want 0x140003000", got)
	}
}

func TestApplyRelocsHighLowAndNegativeDelta(t *testing.T) {
	img := make([]byte, 0x20)
	binary.LittleEndian.PutUint32(img[0x4:], 0x00405000)
	applyRelocs(img, 0x2000, []Reloc{{0x2004, relHighLow}}, -0x1000) // negative delta
	if got := binary.LittleEndian.Uint32(img[0x4:]); got != 0x00404000 {
		t.Errorf("HIGHLOW rebase = 0x%x, want 0x00404000", got)
	}
}

func TestApplyRelocsIgnoresOutOfRange(t *testing.T) {
	img := make([]byte, 0x10)
	orig := make([]byte, 0x10)
	copy(orig, img)
	applyRelocs(img, 0x1000, []Reloc{{0x0fff, relDir64}, {0x9000, relDir64}}, 0x1000) // both outside
	for i := range img {
		if img[i] != orig[i] {
			t.Fatalf("out-of-range relocs must not modify img (byte %d changed)", i)
		}
	}
}

func TestDiskBytesForRange(t *testing.T) {
	secs := []sectionInfo{
		{VA: 0x1000, VSize: 0x100, Raw: bytesSeq(0x100, 0xAA)}, // .text
		{VA: 0x2000, VSize: 0x100, Raw: bytesSeq(0x100, 0xBB)},
	}
	got := diskBytesForRange(secs, 0x1000, 0x10) // fully inside .text
	for i, b := range got {
		if b != 0xAA {
			t.Fatalf("byte %d = 0x%x, want 0xAA", i, b)
		}
	}
	if diskBytesForRange(secs, 0x9000, 0x10) != nil { // not covered by any section
		t.Error("uncovered range must return nil")
	}
}

func TestDiskBytesForRangeZeroPadsBeyondRaw(t *testing.T) {
	// VSize 0x20 but only 0x10 raw bytes → bytes 0x10..0x20 must be zero.
	secs := []sectionInfo{{VA: 0x1000, VSize: 0x20, Raw: bytesSeq(0x10, 0xCC)}}
	got := diskBytesForRange(secs, 0x1000, 0x20)
	for i := 0x10; i < 0x20; i++ {
		if got[i] != 0x00 {
			t.Fatalf("byte %d = 0x%x, want zero-pad 0x00", i, got[i])
		}
	}
}

func bytesSeq(n int, fill byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = fill
	}
	return b
}

func TestDiffBytesCountsAndRuns(t *testing.T) {
	mem := bytesSeq(100, 0x11)
	disk := bytesSeq(100, 0x11)
	for i := 10; i < 14; i++ { // a 4-byte run differs
		mem[i] = 0x22
	}
	mem[50] = 0x33 // and one isolated byte
	d := diffBytes(mem, disk, 0x1000)
	if d.Modified != 5 || d.Total != 100 {
		t.Fatalf("Modified=%d Total=%d, want 5/100", d.Modified, d.Total)
	}
	if d.MaxRun != 4 {
		t.Fatalf("MaxRun=%d, want 4", d.MaxRun)
	}
	if len(d.SampleRVAs) == 0 || d.SampleRVAs[0] != 0x100A {
		t.Fatalf("first sample RVA = %v, want 0x100A", d.SampleRVAs)
	}
}

func TestClassifyStompTiers(t *testing.T) {
	if v := classifyStomp(DiffResult{Total: 1000, Modified: 0}, stompFrac, stompRun); v.Stomped || v.Patched {
		t.Errorf("0 modified must be clean, got %+v", v)
	}
	if v := classifyStomp(DiffResult{Total: 10000, Modified: 8, MaxRun: 8}, stompFrac, stompRun); !v.Patched || v.Stomped {
		t.Errorf("small isolated change must be patched, got %+v", v)
	}
	if v := classifyStomp(DiffResult{Total: 100000, Modified: 300, MaxRun: 300}, stompFrac, stompRun); !v.Stomped {
		t.Errorf("a >=256 run must be stomped, got %+v", v)
	}
	if v := classifyStomp(DiffResult{Total: 1000, Modified: 60, MaxRun: 4}, stompFrac, stompRun); !v.Stomped {
		t.Errorf(">=5%% modified must be stomped, got %+v", v)
	}
}
