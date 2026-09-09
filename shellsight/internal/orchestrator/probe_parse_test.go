package orchestrator

import (
	"testing"

	"shellsight/internal/finding"
)

func TestParseProbeOutputLegacyArray(t *testing.T) {
	out := []byte(`[{"view":"disk","detection":{"basis":"signature"}}]`)
	f, cov := parseProbeOutput("disk", out)
	if len(f) != 1 || cov.Status != finding.CovRan || cov.TargetsScanned != 1 {
		t.Fatalf("legacy array: got %d findings, status=%s scanned=%d", len(f), cov.Status, cov.TargetsScanned)
	}
}

func TestParseProbeOutputObjectWithDegradedCoverage(t *testing.T) {
	out := []byte(`{"findings":[],"coverage":{"status":"degraded","reason":"4688 auditing off","targets_scanned":0}}`)
	f, cov := parseProbeOutput("behavioral", out)
	if len(f) != 0 || cov.Status != finding.CovDegraded || cov.Reason != "4688 auditing off" {
		t.Fatalf("object form: status=%s reason=%q", cov.Status, cov.Reason)
	}
}

func TestParseProbeOutputObjectRealTargetsScanned(t *testing.T) {
	// targets_scanned is the probe's real count, NOT len(findings).
	out := []byte(`{"findings":[{"view":"disk"}],"coverage":{"status":"ran","targets_scanned":7}}`)
	_, cov := parseProbeOutput("disk", out)
	if cov.TargetsScanned != 7 {
		t.Fatalf("want targets_scanned=7 (real count), got %d", cov.TargetsScanned)
	}
}

// TestProbeOutputArtifactCoverageIsCarriedButNeverAggregated: the per-artifact channel reaches the
// detailed caller and changes NOTHING about the aggregate coverage record fusion consumes.
func TestProbeOutputArtifactCoverageIsCarriedButNeverAggregated(t *testing.T) {
	withChannel := []byte(`{"findings":[{"view":"disk"}],"coverage":{"status":"ran","targets_scanned":2},` +
		`"artifact_coverage":[` +
		`{"path":"inert/one.jar","sha256":"aa","status":"complete","bytes":10},` +
		`{"path":"inert/two.class","sha256":"bb","status":"degraded","bytes":5,"diagnostic_codes":["java-class-malformed"]},` +
		`{"path":"inert/three.class","sha256":"","status":"failed","bytes":0,"diagnostic_codes":["java-artifact-read-failed"]}]}`)
	withoutChannel := []byte(`{"findings":[{"view":"disk"}],"coverage":{"status":"ran","targets_scanned":2}}`)

	po, cov := parseProbeOutputDetailed("disk", withChannel)
	_, plainCov := parseProbeOutputDetailed("disk", withoutChannel)
	if cov != plainCov {
		t.Fatalf("artifact coverage perturbed the aggregate record: %+v vs %+v", cov, plainCov)
	}
	if len(po.ArtifactCoverage) != 3 {
		t.Fatalf("want 3 artifact coverage entries, got %+v", po.ArtifactCoverage)
	}
	// The legacy accessor must still hand back only findings + aggregate coverage.
	f, legacyCov := parseProbeOutput("disk", withChannel)
	if len(f) != 1 || legacyCov != cov {
		t.Fatalf("parseProbeOutput changed shape: %d findings, cov=%+v", len(f), legacyCov)
	}
}

func TestProbeOutputArtifactCoverageInconsistenciesFail(t *testing.T) {
	cases := []struct {
		name string
		out  string
	}{
		{"unknown-status", `{"findings":[],"artifact_coverage":[{"path":"a.jar","sha256":"aa","status":"partial","bytes":1}]}`},
		{"duplicate-path", `{"findings":[],"artifact_coverage":[` +
			`{"path":"a.jar","sha256":"aa","status":"complete","bytes":1},` +
			`{"path":"a.jar","sha256":"aa","status":"degraded","bytes":1}]}`},
		{"empty-path", `{"findings":[],"artifact_coverage":[{"path":"","sha256":"aa","status":"complete","bytes":1}]}`},
		{"sha-mismatch", `{"findings":[{"view":"disk","target":{"kind":"file","file":{"path":"a.jar","sha256":"aa"}}}],` +
			`"artifact_coverage":[{"path":"a.jar","sha256":"bb","status":"complete","bytes":1}]}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			po, cov := parseProbeOutputDetailed("disk", []byte(tc.out))
			if cov.Status != finding.CovFailed {
				t.Fatalf("want failed coverage, got %s (%s)", cov.Status, cov.Reason)
			}
			if len(po.Findings) != 0 || len(po.ArtifactCoverage) != 0 {
				t.Fatalf("failed run must surface nothing: %+v", po)
			}
			if cov.Reason == "" {
				t.Fatal("failed coverage must carry a reason")
			}
		})
	}
}

// A finding whose path has no artifact-coverage entry (or no SHA on either side) is normal — the
// channel only covers Java artifacts, while findings also come from PHP/YARA paths.
func TestProbeOutputArtifactCoverageAllowsUncoveredFindings(t *testing.T) {
	out := []byte(`{"findings":[` +
		`{"view":"disk","target":{"kind":"file","file":{"path":"web/shell.php","sha256":"cc"}}},` +
		`{"view":"disk","target":{"kind":"file","file":{"path":"a.jar"}}}],` +
		`"artifact_coverage":[{"path":"a.jar","sha256":"aa","status":"complete","bytes":1}]}`)
	po, cov := parseProbeOutputDetailed("disk", out)
	if cov.Status != finding.CovRan || len(po.Findings) != 2 || len(po.ArtifactCoverage) != 1 {
		t.Fatalf("uncovered findings must not fail the run: cov=%+v out=%+v", cov, po)
	}
}
