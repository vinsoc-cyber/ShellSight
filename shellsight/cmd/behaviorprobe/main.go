// behaviorprobe — the behavioral/log webshell view. Reads a TargetSpec on stdin,
// queries Windows event logs (live or an offline .evtx via --evtx), runs the
// detectors, and emits []Finding on stdout.
//
// Coverage honesty (project invariant): never report a silent clean. If the event
// source cannot be read (no wevtutil, access denied, missing .evtx) the probe exits
// non-zero so the core marks the view failed rather than clean.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"shellsight/internal/finding"
)

const (
	exitOK       = 0
	exitInternal = 1
	exitCoverage = 2
)

func main() {
	evtx := flag.String("evtx", "", "analyze an exported .evtx file instead of the live log (offline mode)")
	flag.Parse()

	specBytes, _ := io.ReadAll(os.Stdin)
	var spec finding.TargetSpec
	if len(specBytes) > 0 {
		if err := json.Unmarshal(specBytes, &spec); err != nil {
			fmt.Fprintln(os.Stderr, "behaviorprobe: bad TargetSpec on stdin:", err)
			os.Exit(exitCoverage)
		}
	}

	findings, cov, err := run(spec, *evtx)
	if err != nil {
		fmt.Fprintln(os.Stderr, "behaviorprobe:", err)
		os.Exit(exitCoverage)
	}
	if findings == nil {
		findings = []finding.Finding{}
	}
	out, err := json.Marshal(finding.ProbeOutput{Findings: findings, Coverage: cov})
	if err != nil {
		fmt.Fprintln(os.Stderr, "behaviorprobe: marshal:", err)
		os.Exit(exitInternal)
	}
	os.Stdout.Write(out)
	os.Exit(exitOK)
}

// run gathers events (live or from an .evtx) and applies every detector. It returns honest
// coverage: the live path degrades when process-creation telemetry is unavailable (so a stock
// host is never reported as a clean-and-complete behavioral scan).
func run(spec finding.TargetSpec, evtxPath string) ([]finding.Finding, *finding.ProbeCoverage, error) {
	host := spec.Host
	var events []Event
	var err error
	var cov *finding.ProbeCoverage
	if evtxPath != "" {
		events, err = gatherEvtx(evtxPath)
		if err != nil {
			return nil, nil, err
		}
	} else {
		events, _, err = gatherLive()
		if err != nil {
			return nil, nil, err
		}
		cov = liveCoverage(events) // nil = ran; non-nil = degraded with cause-specific reason
	}
	var findings []finding.Finding
	findings = append(findings, detectViewState(events, host)...)
	findings = append(findings, detectIISConfig(events, host)...)
	findings = append(findings, detectW3wpChild(events, host)...)
	if cov == nil {
		cov = &finding.ProbeCoverage{Status: finding.CovRan}
	}
	cov.TargetsScanned = len(events)
	return findings, cov, nil
}
