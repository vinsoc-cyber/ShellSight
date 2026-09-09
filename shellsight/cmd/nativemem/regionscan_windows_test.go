//go:build windows

package main

import (
	"testing"

	"shellsight/internal/finding"
	"golang.org/x/sys/windows"
)

// A clean, AOT-compiled Go process (no JIT, no injected code) must yield zero likely-malicious
// regions: every executable region is image-backed. This exercises the full native pipeline.
func TestScanSelfHasNoLikelyMalicious(t *testing.T) {
	h := windows.CurrentProcess()
	mods, err := enumModules(h)
	if err != nil {
		t.Fatalf("enumModules(self): %v", err)
	}
	regions, err := scanRegions(h, mods)
	if err != nil {
		t.Fatalf("scanRegions(self): %v", err)
	}
	if len(regions) == 0 {
		t.Fatal("expected at least the image .text region in self")
	}
	for _, r := range regions {
		if a := assess(r); a.Tier == finding.TierLikely {
			t.Errorf("clean self process flagged likely-malicious: region 0x%x (%s %s) signals=%v",
				r.Base, r.Type, protString(r.Protect), a.Signals)
		}
	}
}
