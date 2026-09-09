//go:build !linux

package main

import "shellsight/internal/finding"

// run on a non-Linux host. This view is a Linux capability; the registry should never invoke it
// here, but a probe invoked anyway must say why rather than emit an empty clean result.
func run(_ finding.TargetSpec) finding.ProbeOutput {
	return finding.ProbeOutput{
		Findings: []finding.Finding{},
		Coverage: &finding.ProbeCoverage{
			Status: "n/a",
			Reason: "jvmprobe external triage requires Linux /proc",
		},
	}
}
