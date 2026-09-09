package output

// Spec 007 US3: the run directory is created before the probes run (so the disk probe can fall back to
// it for its temporary workspace), and the report says when that fallback happened.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"shellsight/internal/finding"
)

func TestRunDirForMatchesWhatWriteCreates(t *testing.T) {
	out := t.TempDir()
	rep := finding.Report{
		Scan:    finding.Scan{Host: "web-01", ToolVersion: "v1", RunID: "20260826_120000"},
		Verdict: finding.Verdict{Tier: finding.TierClean},
	}
	want := RunDirFor(out, rep.Scan.Host, rep.Scan.RunID)
	got, err := Write(rep, out)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Clean(got) != filepath.Clean(want) {
		t.Fatalf("RunDirFor must name the directory Write creates: want %s, got %s", want, got)
	}
	if _, err := os.Stat(filepath.Join(got, "report.json")); err != nil {
		t.Fatalf("Write must still produce the run folder: %v", err)
	}
}

func TestWriteReusesARunDirectoryCreatedEarly(t *testing.T) {
	// The core creates the directory before the probes run; Write must not fail or rename.
	out := t.TempDir()
	rep := finding.Report{
		Scan:    finding.Scan{Host: "web-01", ToolVersion: "v1", RunID: "20260826_120000"},
		Verdict: finding.Verdict{Tier: finding.TierClean},
	}
	early := RunDirFor(out, rep.Scan.Host, rep.Scan.RunID)
	if err := os.MkdirAll(filepath.Join(early, "scratch"), 0o755); err != nil {
		t.Fatal(err)
	}
	got, err := Write(rep, out)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Clean(got) != filepath.Clean(early) {
		t.Fatalf("Write must reuse the early directory %s, got %s", early, got)
	}
}

func TestSummaryShowsTheScratchWorkspaceLine(t *testing.T) {
	rep := finding.Report{
		Scan:    finding.Scan{Host: "web01", ToolVersion: "v1.0.0", RunID: "20260826_120000"},
		Verdict: finding.Verdict{Tier: finding.TierClean},
		Coverage: []finding.Coverage{{
			View: "disk", Status: finding.CovRan, TargetsScanned: 1,
			Scratch: "/tmp/ss/run_web01_20260826_120000/scratch",
		}},
	}
	text := summary(rep)
	if !strings.Contains(text, "scratch workspace: /tmp/ss/run_web01_20260826_120000/scratch (default temporary location not writable)") {
		t.Fatalf("the report must say where the workspace went, got:\n%s", text)
	}
	rep.Coverage[0].Scratch = ""
	if strings.Contains(summary(rep), "scratch workspace") {
		t.Fatalf("no line when the fallback was not used")
	}
}
