package output

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"shellsight/internal/finding"
)

func TestWriteRunFolder(t *testing.T) {
	rep := finding.Report{
		SchemaVersion: finding.SchemaVersion,
		Scan:          finding.Scan{Host: "WEB01", RunID: "run-1", ToolVersion: "test"},
		Verdict:       finding.Verdict{Tier: finding.TierSuspicious, Score: 40},
		Coverage:      []finding.Coverage{{View: "mock", Status: finding.CovRan, TargetsScanned: 1}},
		Findings:      []finding.Finding{{View: "mock", Tier: finding.TierSuspicious, Artifact: finding.Artifact{Identity: "EvilMarker"}}},
	}
	dir := t.TempDir()
	runDir, err := Write(rep, dir)
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	for _, name := range []string{"report.json", "summary.txt", "manifest.json"} {
		if _, err := os.Stat(filepath.Join(runDir, name)); err != nil {
			t.Fatalf("missing %s: %v", name, err)
		}
	}
	// report.json round-trips.
	rj, _ := os.ReadFile(filepath.Join(runDir, "report.json"))
	var got finding.Report
	if err := json.Unmarshal(rj, &got); err != nil {
		t.Fatalf("report.json invalid: %v", err)
	}
	if got.Verdict.Tier != finding.TierSuspicious {
		t.Fatalf("verdict not preserved: %s", got.Verdict.Tier)
	}
	// manifest contains report.json's hash (chain-of-custody).
	mj, _ := os.ReadFile(filepath.Join(runDir, "manifest.json"))
	var manifest map[string]string
	if err := json.Unmarshal(mj, &manifest); err != nil {
		t.Fatalf("manifest invalid: %v", err)
	}
	if manifest["report.json"] == "" {
		t.Fatal("manifest missing report.json hash")
	}
}
