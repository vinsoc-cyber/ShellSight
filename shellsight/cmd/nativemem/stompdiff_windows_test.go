//go:build windows

package main

import (
	"testing"

	"golang.org/x/sys/windows"
)

// A clean process: every backed executable region, after rebasing, must match its on-disk module —
// so the stomp-diff must NOT report a stomp on any of them. This validates the rebasing against real
// ASLR-loaded modules on the lab (the alert-threshold FP guard).
func TestStompSelfNoFalsePositive(t *testing.T) {
	h := windows.CurrentProcess()
	mods, err := enumModules(h)
	if err != nil {
		t.Fatalf("enumModules(self): %v", err)
	}
	regions, err := scanRegions(h, mods)
	if err != nil {
		t.Fatalf("scanRegions(self): %v", err)
	}
	checked := 0
	for i := range regions {
		if !regions[i].Backed {
			continue
		}
		m := backingModule(regions[i].Base, mods)
		if m == nil {
			continue
		}
		checkRegionStomp(h, *m, &regions[i])
		checked++
		if regions[i].Stomped {
			t.Errorf("clean self process flagged module-stomp on %s region 0x%x (%.1f%% modified)",
				m.Name, regions[i].Base, regions[i].ModifiedFrac*100)
		}
	}
	if checked == 0 {
		t.Fatal("expected at least one backed executable region to diff in self")
	}
}
