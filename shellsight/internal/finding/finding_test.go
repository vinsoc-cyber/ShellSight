package finding

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestFindingJSONRoundTrip(t *testing.T) {
	in := Finding{
		SchemaVersion: SchemaVersion, ID: "abc", Host: "WEB01", View: "mock",
		Target:    Target{Kind: "process", Process: &Process{PID: 4924, Name: "w3wp.exe"}},
		Artifact:  Artifact{Kind: "dynamic-assembly", Identity: "EvilMarker"},
		Detection: Detection{Basis: "structural-heuristic", Allowlisted: false},
		Score:     40, Tier: TierSuspicious,
	}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// Classification must serialize present-but-null (the hook).
	if !strings.Contains(string(b), `"classification":{"family":null,"capability":null,"source":null,"confidence":0}`) {
		t.Fatalf("classification not present-but-null: %s", b)
	}
	var out Finding
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.View != "mock" || out.Tier != TierSuspicious || out.Target.Process.PID != 4924 {
		t.Fatalf("round-trip mismatch: %+v", out)
	}
}

// TestArtifactCoverageAbsentIsByteIdenticalToLegacyOutput pins the production contract: the
// per-artifact coverage channel is opt-in telemetry, so a ProbeOutput without it must marshal to
// EXACTLY the bytes the pre-channel struct produced. legacyProbeOutput is a verbatim copy of the
// shipped shape; renaming or reordering a field, or adding one that always marshals, fails here. The
// load-bearing assertion for the opt-in field itself is the artifact_coverage check below — an added
// `omitempty` field left empty would pass the byte comparison.
func TestArtifactCoverageAbsentIsByteIdenticalToLegacyOutput(t *testing.T) {
	type legacyProbeOutput struct {
		Findings []Finding      `json:"findings"`
		Coverage *ProbeCoverage `json:"coverage,omitempty"`
	}
	cases := []struct {
		name     string
		findings []Finding
		coverage *ProbeCoverage
	}{
		{"nil-findings-no-coverage", nil, nil}, // must still emit "findings":null, as it always did
		{"empty-findings-no-coverage", []Finding{}, nil},
		{"empty-findings-ran-coverage", []Finding{}, &ProbeCoverage{Status: CovRan, TargetsScanned: 3}},
		{"findings-degraded-coverage",
			[]Finding{{SchemaVersion: SchemaVersion, ID: "abc", View: "disk", Score: 70, Tier: TierLikely}},
			&ProbeCoverage{Status: CovDegraded, Reason: "java-class-malformed=2", TargetsScanned: 1}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			legacy, err := json.Marshal(legacyProbeOutput{Findings: tc.findings, Coverage: tc.coverage})
			if err != nil {
				t.Fatalf("marshal legacy: %v", err)
			}
			current, err := json.Marshal(ProbeOutput{Findings: tc.findings, Coverage: tc.coverage})
			if err != nil {
				t.Fatalf("marshal current: %v", err)
			}
			if !bytes.Equal(legacy, current) {
				t.Fatalf("production output changed\nlegacy : %s\ncurrent: %s", legacy, current)
			}
			if bytes.Contains(current, []byte("artifact_coverage")) {
				t.Fatalf("artifact coverage leaked into un-requested output: %s", current)
			}
			if tc.findings == nil && !bytes.Contains(current, []byte(`"findings":null`)) {
				t.Fatalf("nil findings must still marshal as null: %s", current)
			}
		})
	}
}

func TestArtifactCoverageRoundTripsWhenRequested(t *testing.T) {
	in := ProbeOutput{
		Findings: []Finding{},
		Coverage: &ProbeCoverage{Status: CovDegraded, Reason: "java-class-malformed=1", TargetsScanned: 1},
		ArtifactCoverage: []ArtifactCoverage{
			{Path: "inert/one.jar", SHA256: "aa11", Status: ArtifactCovComplete, Bytes: 1024},
			{Path: "inert/two.class", SHA256: "bb22", Status: ArtifactCovDegraded, Bytes: 512,
				DiagnosticCodes: []string{"java-class-malformed"}},
			{Path: "inert/three.class", Status: ArtifactCovFailed,
				DiagnosticCodes: []string{"java-artifact-read-failed"}},
		},
	}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(b), `"artifact_coverage":[{"path":"inert/one.jar","sha256":"aa11","status":"complete","bytes":1024}`) {
		t.Fatalf("unexpected artifact coverage encoding: %s", b)
	}
	var out ProbeOutput
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(out.ArtifactCoverage) != 3 {
		t.Fatalf("want 3 artifact coverage entries, got %d", len(out.ArtifactCoverage))
	}
	if out.ArtifactCoverage[1].Status != ArtifactCovDegraded || out.ArtifactCoverage[1].Bytes != 512 ||
		len(out.ArtifactCoverage[1].DiagnosticCodes) != 1 {
		t.Fatalf("degraded entry did not round-trip: %+v", out.ArtifactCoverage[1])
	}
	if out.ArtifactCoverage[2].Status != ArtifactCovFailed {
		t.Fatalf("failed entry did not round-trip: %+v", out.ArtifactCoverage[2])
	}
}

// TestArtifactCoverageUnknownStatusFailsParsing: an unrecognized status must fail loudly rather
// than be read as "this artifact was covered".
func TestArtifactCoverageUnknownStatusFailsParsing(t *testing.T) {
	for _, in := range []string{
		`{"findings":[],"artifact_coverage":[{"path":"a.jar","sha256":"aa","status":"partial","bytes":1}]}`,
		`{"findings":[],"artifact_coverage":[{"path":"a.jar","sha256":"aa","status":"","bytes":1}]}`,
		`{"findings":[],"artifact_coverage":[{"path":"a.jar","sha256":"aa","status":"ran","bytes":1}]}`,
	} {
		var out ProbeOutput
		if err := json.Unmarshal([]byte(in), &out); err == nil {
			t.Fatalf("unknown artifact status parsed successfully: %s", in)
		}
	}
	if !ValidArtifactCovStatus(ArtifactCovComplete) || !ValidArtifactCovStatus(ArtifactCovDegraded) ||
		!ValidArtifactCovStatus(ArtifactCovFailed) || ValidArtifactCovStatus("complete ") {
		t.Fatal("ValidArtifactCovStatus does not describe exactly the three defined statuses")
	}
}
