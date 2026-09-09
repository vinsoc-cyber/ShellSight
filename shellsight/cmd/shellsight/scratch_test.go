package main

// Spec 007 US3: the core creates the run directory BEFORE the probes run and hands the disk probe a
// scratch directory inside it, so a read-only root filesystem with no writable /tmp no longer fails the
// disk view; when the run ends the scratch directory is gone and the run folder holds only the report.

import (
	"os"
	"path/filepath"
	"testing"

	"shellsight/internal/orchestrator"
)

func TestOnlyApplicableDiskProbesReceiveTheScratchArgument(t *testing.T) {
	probes := []orchestrator.Probe{
		{View: "disk", Path: "diskprobe", Args: []string{"--yr", "yr"}},
		{View: "dotnet-mem", Path: "dotnetmem", Args: []string{"--pid", "1"}},
		{View: "disk", Path: "diskprobe", NotApplicable: "deferred on this platform"},
	}
	runDir := filepath.Join("out", "run_h_1")
	got := withScratch(probes, runDir)
	want := filepath.Join(runDir, "scratch")
	if !containsArg(got[0].Args, "--scratch") || !containsArg(got[0].Args, want) {
		t.Fatalf("the disk probe must receive --scratch %s, got %v", want, got[0].Args)
	}
	if containsArg(got[1].Args, "--scratch") {
		t.Fatalf("a memory probe walks no filesystem and must not receive --scratch, got %v", got[1].Args)
	}
	if containsArg(got[2].Args, "--scratch") {
		t.Fatalf("a probe that is not applicable is never run and must not be touched, got %v", got[2].Args)
	}
}

func TestPrepareRunDirCreatesTheRunFolderAndScratchEarly(t *testing.T) {
	out := t.TempDir()
	runDir, scratch, err := prepareRunDir(out, "web-01", "20260826_120000")
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{runDir, scratch} {
		if fi, err := os.Stat(d); err != nil || !fi.IsDir() {
			t.Fatalf("%s must exist before any probe runs: %v", d, err)
		}
	}
	if filepath.Dir(scratch) != runDir || filepath.Base(scratch) != "scratch" {
		t.Fatalf("scratch must be <runDir>/scratch, got %s under %s", scratch, runDir)
	}
}

func TestCleanupScratchRemovesOnlyTheScratchDirectory(t *testing.T) {
	out := t.TempDir()
	runDir, scratch, err := prepareRunDir(out, "web-01", "20260826_120000")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(scratch, "ss-scanlist-1.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(runDir, "report.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	cleanupScratch(scratch)
	if _, err := os.Stat(scratch); !os.IsNotExist(err) {
		t.Fatalf("the scratch directory must be gone after the run, stat err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(runDir, "report.json")); err != nil {
		t.Fatalf("cleanup must not touch the run folder's own files: %v", err)
	}
}

func TestPrepareRunDirFailsLoudlyWhenOutIsUnwritable(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := prepareRunDir(blocker, "web-01", "20260826_120000"); err == nil {
		t.Fatalf("an --out that cannot hold a run folder must be an error, not a silent run without output")
	}
}
