package main

import (
	"os"
	"path/filepath"

	"shellsight/internal/orchestrator"
	"shellsight/internal/output"
)

// The run folder is created BEFORE the probes run (spec 007 US3, research R4).
//
// The disk probe writes two temporary artifacts -- the engine's scan list and the decoded-layer
// mirror. In a container with a read-only root filesystem and no writable /tmp the default temporary
// location fails, and until this the whole disk view failed with it (measured 2026-08-26: exit 5,
// "scan list: open /proc/nonexistent/ss-scanlist-…: no such file or directory"). The one directory a
// scan can always write is the run folder -- --out has to be writable for the report -- so it is
// created up front, its scratch subdirectory is handed to the disk probe as --scratch, and it is
// removed when the scan ends. output.Write finds the folder already present and uses it unchanged.

// prepareRunDir creates the run folder and its scratch subdirectory, failing loudly when --out cannot
// hold them: a scan whose report could never be written must not run at all.
func prepareRunDir(outDir, host, runID string) (runDir, scratch string, err error) {
	runDir = output.RunDirFor(outDir, host, runID)
	scratch = filepath.Join(runDir, "scratch")
	if err := os.MkdirAll(scratch, 0o755); err != nil {
		return "", "", err
	}
	return runDir, scratch, nil
}

// withScratch hands the scratch directory to every disk probe that will actually run. Memory probes
// walk no filesystem, and a probe marked not-applicable is never executed, so neither is touched.
func withScratch(probes []orchestrator.Probe, runDir string) []orchestrator.Probe {
	for i := range probes {
		if probes[i].View == "disk" && probes[i].NotApplicable == "" {
			probes[i].Args = append(probes[i].Args, "--scratch", filepath.Join(runDir, "scratch"))
		}
	}
	return probes
}

// cleanupScratch removes the scratch directory after the scan. The probe removes its own files; this
// removes the directory itself so a completed run folder holds only the report.
func cleanupScratch(scratch string) {
	if scratch != "" {
		_ = os.RemoveAll(scratch)
	}
}
