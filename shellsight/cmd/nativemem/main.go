//go:build windows

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"shellsight/internal/finding"
	"golang.org/x/sys/windows"
)

const (
	exitOK       = 0
	exitInternal = 1
	exitCoverage = 2
)

func main() {
	specBytes, _ := io.ReadAll(os.Stdin)
	var spec finding.TargetSpec
	if len(specBytes) > 0 {
		if err := json.Unmarshal(specBytes, &spec); err != nil {
			fmt.Fprintln(os.Stderr, "nativemem: bad TargetSpec on stdin:", err)
			os.Exit(exitCoverage)
		}
	}
	enableSeDebug() // best-effort; only matters for cross-session targets

	pids, explicit := resolveTargets(spec)
	if len(pids) == 0 {
		status, reason := finding.CovNA, "no w3wp/dotnet/iisexpress process found"
		if explicit {
			status, reason = finding.CovFailed, "requested PID(s) not found"
		}
		emit([]finding.Finding{}, &finding.ProbeCoverage{Status: status, Reason: reason})
		return
	}

	var findings []finding.Finding
	var failures []string
	scanned := 0
	for _, pid := range pids {
		h, err := openProcess(pid)
		if err != nil {
			failures = append(failures, fmt.Sprintf("pid %d: open: %v", pid, err))
			continue
		}
		mods, err := enumModules(h)
		if err != nil {
			failures = append(failures, fmt.Sprintf("pid %d: modules: %v", pid, err))
			windows.CloseHandle(h)
			continue
		}
		regions, _ := scanRegions(h, mods)  // sets Type/Protect/Backed/HasPEHeader
		starts, _ := threadStarts(pid)      // best-effort
		markThreadStarts(regions, starts)   // sets ThreadStart
		filterJIT(regions, isManaged(mods)) // sets JITOwned (managed only)
		// Module-stomp / hollowing: a backed executable region whose in-memory code no longer
		// matches its on-disk module is tampered. Best-effort; failures leave the region clean.
		for i := range regions {
			if regions[i].Backed {
				if bm := backingModule(regions[i].Base, mods); bm != nil {
					checkRegionStomp(h, *bm, &regions[i])
				}
			}
		}
		name := procName(pid)
		for _, r := range regions {
			a := assess(r)
			if a.Tier == finding.TierClean {
				continue
			}
			findings = append(findings, mapFinding(spec.Host, pid, name, r, a))
		}
		scanned++
		windows.CloseHandle(h)
	}

	cov := &finding.ProbeCoverage{TargetsScanned: scanned}
	switch {
	case scanned == 0:
		cov.Status, cov.Reason = finding.CovFailed, strings.Join(failures, "; ")
	case len(failures) > 0:
		cov.Status, cov.Reason = finding.CovDegraded, strings.Join(failures, "; ")
	default:
		cov.Status = finding.CovRan
	}
	if findings == nil {
		findings = []finding.Finding{}
	}
	emit(findings, cov)
}

func emit(findings []finding.Finding, cov *finding.ProbeCoverage) {
	out, err := json.Marshal(finding.ProbeOutput{Findings: findings, Coverage: cov})
	if err != nil {
		fmt.Fprintln(os.Stderr, "nativemem: marshal:", err)
		os.Exit(exitInternal)
	}
	os.Stdout.Write(out)
	os.Exit(exitOK)
}

func mapFinding(host string, pid uint32, name string, r Region, a Assessment) finding.Finding {
	return finding.Finding{
		SchemaVersion: finding.SchemaVersion,
		ID:            fmt.Sprintf("nativemem-%d-%x", pid, r.Base),
		Host:          host,
		View:          "native-mem",
		Target:        finding.Target{Kind: "process", Process: &finding.Process{PID: int(pid), Name: name}},
		Artifact: finding.Artifact{
			Kind:     "native-memory-region",
			Identity: fmt.Sprintf("0x%x-0x%x %s %s", r.Base, r.Base+r.Size, r.Type, protString(r.Protect)),
			Location: fmt.Sprintf("in-memory (pid %d)", pid),
		},
		Detection: finding.Detection{
			Basis:        "memory-region-anomaly",
			KnowledgeRef: "heuristic:native/unbacked-executable",
			Evidence:     a.Evidence,
			Allowlisted:  false,
		},
		Score: a.Score,
		Tier:  a.Tier,
		Context: map[string]string{
			"signals":     strings.Join(a.Signals, ","),
			"region_type": r.Type,
			"protection":  protString(r.Protect),
			"source":      "live-scan",
		},
	}
}
