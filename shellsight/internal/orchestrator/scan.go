package orchestrator

import (
	"context"
	"os"
	"sort"
	"sync"
	"time"

	"shellsight/internal/finding"
	"shellsight/internal/fusion"
)

// Scan runs every probe (in parallel), collects findings + coverage, and assembles a Report.
func Scan(ctx context.Context, probes []Probe, spec finding.TargetSpec, toolVersion, runID string, timeout time.Duration) finding.Report {
	started := time.Now().UTC().Format(time.RFC3339)
	host := spec.Host
	if host == "" {
		if h, err := os.Hostname(); err == nil {
			host = h
		}
	}

	// Initialize as non-nil so the Report always serializes arrays ([]), never null —
	// a stable schema for downstream consumers (fusion, SIEM export, the classifier).
	var (
		mu       sync.Mutex
		findings = []finding.Finding{}
		coverage = []finding.Coverage{}
		wg       sync.WaitGroup
	)
	for _, p := range probes {
		wg.Add(1)
		go func(p Probe) {
			defer wg.Done()
			fs, cov := RunProbe(ctx, p, spec, timeout)
			mu.Lock()
			findings = append(findings, fs...)
			coverage = append(coverage, cov)
			mu.Unlock()
		}(p)
	}
	wg.Wait()

	// Coverage is appended by whichever probe finishes first, so the same host scanned twice used to
	// emit the same records in a different order. That was invisible while a Linux report carried one
	// record; it carries six now that capabilities the platform cannot support are stated rather than
	// omitted, and 720 orderings of an identical result is diff noise in every report comparison.
	// Sort by view: one deterministic order, and the verdict cannot depend on it either way.
	sort.Slice(coverage, func(i, j int) bool { return coverage[i].View < coverage[j].View })

	// Stamp the resolved host onto any finding a probe left blank, so correlation IDs and
	// corroboration key off the real host (matching Scan.Host) rather than "unknown".
	for i := range findings {
		if findings[i].Host == "" {
			findings[i].Host = host
		}
	}

	verdict, fused := fusion.Assess(findings, coverage)
	return finding.Report{
		SchemaVersion: finding.SchemaVersion,
		Scan: finding.Scan{
			Host: host, Started: started,
			Finished:    time.Now().UTC().Format(time.RFC3339),
			ToolVersion: toolVersion, RunID: runID,
		},
		Verdict:  verdict,
		Coverage: coverage,
		Findings: fused,
	}
}
