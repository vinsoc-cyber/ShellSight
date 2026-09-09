package main

import (
	"fmt"

	"shellsight/internal/finding"
	"shellsight/internal/jvmtriage"
)

// procTarget is the probe's view of one JVM: only the fields findings need, kept separate from
// jvmtarget.Target so the non-Linux build does not drag in a /proc walker.
type procTarget struct {
	PID    int
	Server string
	Argv   []string
}

// externalFindings turns external observations about one JVM into findings.
//
// TIER POLICY — the most important decision in this file.
//
// Stage 1 evidence is EXTERNAL. It proves something about a process's file and memory
// bookkeeping; it does not prove a webshell is resident. An unlinked jar is what a well-behaved
// deployment pipeline looks like on plenty of estates. So the ceiling here is `suspicious`, and
// `likely-malicious` is reserved for the in-JVM stages where an actual wired component is
// identified.
//
// Info-severity signals produce no finding. They are carried on the coverage record as context so
// an analyst reading "attach failed" can see "attach-disabled" beside it — the difference between
// an explained failure and an unexplained one.
func externalFindings(t procTarget, sigs []jvmtriage.Signal) []finding.Finding {
	var out []finding.Finding
	for _, s := range sigs {
		if s.Severity == jvmtriage.SevInfo {
			continue
		}
		score := 25
		if s.Severity == jvmtriage.SevStrong {
			score = 40
		}
		out = append(out, finding.Finding{
			SchemaVersion: finding.SchemaVersion,
			ID:            fmt.Sprintf("jvm-%d-%s", t.PID, s.ID()),
			View:          "java-mem",
			Target: finding.Target{
				Kind:    "process",
				Process: &finding.Process{PID: t.PID, Name: "java"},
			},
			Artifact: finding.Artifact{
				Kind:     "process",
				Identity: fmt.Sprintf("pid:%d", t.PID),
				Location: fmt.Sprintf("/proc/%d", t.PID),
			},
			Detection: finding.Detection{
				// Verified field names — Detection has no Method and no Rule; the stable pivot
				// key is KnowledgeRef.
				Basis:        "structural-heuristic",
				KnowledgeRef: "kb:java-mem/" + s.Code,
				Evidence:     s.Detail,
			},
			Score:   score,
			Tier:    finding.TierSuspicious,
			Context: map[string]string{"server": t.Server, "vantage": "external"},
		})
	}
	return out
}

// infoContext collects the info-severity signals into a coverage-friendly string. These explain a
// result rather than being one.
func infoContext(sigs []jvmtriage.Signal) string {
	var parts []string
	for _, s := range sigs {
		if s.Severity == jvmtriage.SevInfo {
			parts = append(parts, s.Code)
		}
	}
	if len(parts) == 0 {
		return ""
	}
	out := parts[0]
	for _, p := range parts[1:] {
		out += "," + p
	}
	return out
}
