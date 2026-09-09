package deobfuscate

import (
	"bytes"
	"testing"
)

// AntSword's chr encoder emits @eVAl(cHr(97).ChR(115)....) — a run of chr(N) calls that folds
// to cleartext PHP. Run must emit a "chr" layer whose bytes are that cleartext, so the mirror
// scan sees the sink underneath.
func TestRunFoldsChrConcatToCleartext(t *testing.T) {
	src := []byte(`<?php @eVAl(cHr(97).ChR(115).ChR(115).ChR(101).ChR(114).ChR(116).ChR(40).ChR(36).ChR(95).ChR(80).ChR(79).ChR(83).ChR(84).ChR(91).ChR(39).ChR(99).ChR(39).ChR(93).ChR(41).ChR(59));`)
	var got []byte
	for _, l := range Run(src).Layers {
		if l.Method == "chr" {
			got = l.Data
		}
	}
	if got == nil {
		t.Fatalf("no chr layer produced")
	}
	if !bytes.Contains(got, []byte(`assert($_POST['c']);`)) {
		t.Fatalf("chr layer did not fold to cleartext; got %q", got)
	}
}

// AntSword's chr16 encoder emits hex args: cHr(0x40).ChR(0x69)... The same fold must handle
// hexadecimal chr(0xNN) runs.
func TestRunFoldsHexChrConcat(t *testing.T) {
	// 0x73='s' 0x79='y' 0x73='s' 0x74='t' 0x65='e' 0x6d='m' 0x28='(' 0x24='$'
	src := []byte(`<?php @eVAl(cHr(0x73).ChR(0x79).ChR(0x73).ChR(0x74).ChR(0x65).ChR(0x6d).ChR(0x28).ChR(0x24).ChR(0x78).ChR(0x29).ChR(0x3b));`)
	var got []byte
	for _, l := range Run(src).Layers {
		if l.Method == "chr" {
			got = l.Data
		}
	}
	if got == nil {
		t.Fatalf("no chr layer produced for hex chr")
	}
	if !bytes.Contains(got, []byte(`system($x);`)) {
		t.Fatalf("hex chr layer did not fold; got %q", got)
	}
}

// A single chr() call is not obfuscation — no layer, no noise (the run gate is >=4).
func TestRunIgnoresShortChr(t *testing.T) {
	for _, l := range Run([]byte(`<?php echo chr(65);`)).Layers {
		if l.Method == "chr" {
			t.Fatalf("unexpected chr layer for one chr() call: %q", l.Data)
		}
	}
}
