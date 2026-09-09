package report

import (
	"os"
	"path/filepath"
	"testing"
)

func loadFixture(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "report.json"))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return b
}

func TestParseReadsTheEnvelope(t *testing.T) {
	r, err := Parse(loadFixture(t))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if r.Scan.RunID == "" {
		t.Error("run_id is empty")
	}
	if r.Scan.Host == "" {
		t.Error("host is empty")
	}
	if r.Verdict.Tier == "" {
		t.Error("verdict tier is empty")
	}
	if len(r.Findings) == 0 {
		t.Fatal("expected findings in the fixture")
	}
	if len(r.Coverage) == 0 {
		t.Fatal("expected coverage in the fixture")
	}
}

func TestCoverageCarriesSkipCountsAndStatus(t *testing.T) {
	// Coverage is half the verdict. A report whose skip counts were dropped on ingest cannot
	// answer "clean, but how much was actually read".
	r, _ := Parse(loadFixture(t))
	var disk *Coverage
	for i := range r.Coverage {
		if r.Coverage[i].View == "disk" {
			disk = &r.Coverage[i]
		}
	}
	if disk == nil {
		t.Fatal("no disk coverage in the fixture")
	}
	if disk.Status != "ran" {
		t.Fatalf("disk status is %q, want ran", disk.Status)
	}
	if disk.Skipped == nil {
		t.Fatal("skip counts were dropped")
	}
}

func TestEveryFileFindingHasAContentHash(t *testing.T) {
	// Triage groups on Target.File.SHA256. A finding that reached the store without one could
	// never be grouped or carry a decision.
	r, _ := Parse(loadFixture(t))
	for _, f := range r.Findings {
		if f.Target.File == nil {
			continue // memory findings legitimately have none
		}
		if len(f.Target.File.SHA256) != 64 {
			t.Errorf("%s: sha256 is %q, want 64 hex chars", f.ID, f.Target.File.SHA256)
		}
	}
}

func TestContentKeyGroupsByFileNotByRule(t *testing.T) {
	// The correction this design needed: several rules firing on ONE file must produce ONE key.
	r, _ := Parse(loadFixture(t))
	keys := map[string]int{}
	for _, f := range r.Findings {
		keys[ContentKey(f)]++
	}
	if len(keys) >= len(r.Findings) {
		t.Fatalf("ContentKey produced %d keys for %d findings; it is not grouping",
			len(keys), len(r.Findings))
	}
	for k, n := range keys {
		if k == "" {
			t.Fatalf("%d findings produced an empty content key", n)
		}
	}
}

func TestContentKeyFallsBackToArtifactWhenThereIsNoFile(t *testing.T) {
	f := Finding{ID: "x", Artifact: Artifact{Kind: "java-filter", Identity: "com.evil.Shell"}}
	if got := ContentKey(f); got != "artifact:com.evil.Shell" {
		t.Fatalf("ContentKey = %q, want artifact:com.evil.Shell", got)
	}
}

func TestParseRejectsMalformedJSON(t *testing.T) {
	if _, err := Parse([]byte("{not json")); err == nil {
		t.Fatal("expected malformed JSON to be rejected")
	}
}

func TestParseRejectsAReportWithNoRunID(t *testing.T) {
	// RunID is the idempotency key for ingest. Without one a re-import would duplicate the scan.
	if _, err := Parse([]byte(`{"schema_version":"1.0","scan":{"host":"h"}}`)); err == nil {
		t.Fatal("expected a report with no run_id to be rejected")
	}
}
