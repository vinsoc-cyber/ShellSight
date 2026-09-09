package main

import (
	"testing"

	"shellsight/internal/finding"
)

func TestAssess(t *testing.T) {
	cases := []struct {
		name      string
		r         Region
		wantTier  finding.Tier
		wantScore int
	}{
		{"image-backed RX is clean", Region{Type: "image", Protect: 0x20, Backed: true}, finding.TierClean, 0},
		{"jit-owned RX is clean", Region{Type: "private", Protect: 0x20, JITOwned: true}, finding.TierClean, 0},
		{"unbacked RX alone is suspicious", Region{Type: "private", Protect: 0x20}, finding.TierSuspicious, 50},
		{"unbacked RWX is likely", Region{Type: "private", Protect: 0x40}, finding.TierLikely, 80},
		{"unbacked RX + thread-start is likely", Region{Type: "private", Protect: 0x20, ThreadStart: true}, finding.TierLikely, 85},
		{"unbacked + PE header is likely", Region{Type: "private", Protect: 0x20, HasPEHeader: true}, finding.TierLikely, 90},
		{"unbacked RWX + PE + thread takes max", Region{Type: "private", Protect: 0x40, HasPEHeader: true, ThreadStart: true}, finding.TierLikely, 90},
	}
	for _, c := range cases {
		got := assess(c.r)
		if got.Tier != c.wantTier || got.Score != c.wantScore {
			t.Errorf("%s: assess()=%s/%d want %s/%d (signals=%v)", c.name, got.Tier, got.Score, c.wantTier, c.wantScore, got.Signals)
		}
	}
}

func TestAssessAllowlistsBackedAndJIT(t *testing.T) {
	for _, r := range []Region{{Backed: true, Protect: 0x20}, {JITOwned: true, Protect: 0x20}} {
		if a := assess(r); !a.Allowlisted || a.Tier != finding.TierClean {
			t.Errorf("expected clean+allowlisted, got %s allowlisted=%v", a.Tier, a.Allowlisted)
		}
	}
}

func TestAssessRWXEvidenceMentionsRWX(t *testing.T) {
	a := assess(Region{Type: "private", Protect: 0x40})
	found := false
	for _, s := range a.Signals {
		if s == "rwx" {
			found = true
		}
	}
	if !found {
		t.Errorf("RWX region signals must include \"rwx\"; got %v", a.Signals)
	}
}

func TestAssessStompedBackedIsLikely(t *testing.T) {
	r := Region{Type: "image", Protect: 0x20, Backed: true, Stomped: true, ModifiedFrac: 0.42}
	a := assess(r)
	if a.Tier != finding.TierLikely || a.Allowlisted {
		t.Fatalf("stomped backed region must be likely + not allowlisted, got %s allowlisted=%v", a.Tier, a.Allowlisted)
	}
	found := false
	for _, s := range a.Signals {
		if s == "module-stomped" {
			found = true
		}
	}
	if !found {
		t.Errorf("stomped region signals must include module-stomped, got %v", a.Signals)
	}
}

func TestAssessPatchedBackedIsSuspicious(t *testing.T) {
	r := Region{Type: "image", Protect: 0x20, Backed: true, Patched: true, ModifiedFrac: 0.001}
	a := assess(r)
	if a.Tier != finding.TierSuspicious || a.Allowlisted {
		t.Fatalf("patched backed region must be suspicious + not allowlisted, got %s allowlisted=%v", a.Tier, a.Allowlisted)
	}
}

func TestAssessCleanBackedStillClean(t *testing.T) {
	r := Region{Type: "image", Protect: 0x20, Backed: true}
	if a := assess(r); a.Tier != finding.TierClean || !a.Allowlisted {
		t.Fatalf("an unstomped backed region must stay clean+allowlisted, got %s allowlisted=%v", a.Tier, a.Allowlisted)
	}
}
