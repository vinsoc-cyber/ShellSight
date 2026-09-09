package main

import (
	"fmt"
	"strings"

	"shellsight/internal/finding"
)

// Assessment is the discriminator's verdict for one region.
type Assessment struct {
	Tier        finding.Tier
	Score       int
	Allowlisted bool
	Signals     []string
	Evidence    string
}

// assess tiers a single executable region. Corroboration-gated, mirroring the managed probes:
// unbacked-executable is the base signal (suspicious); a W^X violation, a thread starting inside,
// or a mapped PE header escalates to likely-malicious. Image-backed and CLR-JIT-owned regions are
// normal and allowlisted. This is the project's "lone->suspicious / corroborated->likely" philosophy.
func assess(r Region) Assessment {
	if r.Backed {
		if r.Stomped {
			return Assessment{Tier: finding.TierLikely, Score: 90, Allowlisted: false,
				Signals: []string{"module-stomped"},
				Evidence: fmt.Sprintf("image-backed region 0x%x-0x%x: in-memory code does NOT match the on-disk module (%.1f%% of compared bytes differ after rebasing) — DLL hollowing / module-stomp",
					r.Base, r.Base+r.Size, r.ModifiedFrac*100)}
		}
		if r.Patched {
			return Assessment{Tier: finding.TierSuspicious, Score: 55, Allowlisted: false,
				Signals: []string{"inline-patched-code"},
				Evidence: fmt.Sprintf("image-backed region 0x%x-0x%x: %.2f%% of compared bytes differ from the on-disk module (inline patch/hook) — benign EDR hooks look similar; warrants analyst review",
					r.Base, r.Base+r.Size, r.ModifiedFrac*100)}
		}
		return Assessment{Tier: finding.TierClean, Score: 0, Allowlisted: true,
			Signals: []string{"image-backed"}, Evidence: "executable region backed by an on-disk image module (in-memory code matches disk)"}
	}
	if r.JITOwned {
		return Assessment{Tier: finding.TierClean, Score: 0, Allowlisted: true,
			Signals: []string{"jit-owned"}, Evidence: "CLR-owned RX JIT code heap (managed process)"}
	}

	signals := []string{"unbacked-executable-region"}
	tier := finding.TierSuspicious
	score := 50

	escalate := func(sig string, s int) {
		signals = append(signals, sig)
		tier = finding.TierLikely
		if s > score {
			score = s
		}
	}
	if isWritableExecute(r.Protect) {
		escalate("rwx", 80)
	}
	if r.ThreadStart {
		escalate("thread-start", 85)
	}
	if r.HasPEHeader {
		escalate("pe-image", 90)
	}

	ev := fmt.Sprintf("unbacked executable region 0x%x-0x%x (%s, %s); not backed by any on-disk image",
		r.Base, r.Base+r.Size, r.Type, protString(r.Protect))
	if tier == finding.TierLikely {
		ev += "; corroborated by [" + strings.Join(signals[1:], ", ") + "]"
	} else {
		ev += "; warrants analyst review"
	}
	return Assessment{Tier: tier, Score: score, Allowlisted: false, Signals: signals, Evidence: ev}
}
