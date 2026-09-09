package orchestrator

import (
	"testing"

	"shellsight/internal/finding"
	"shellsight/internal/fusion"
)

// The Windows jar path's wire form, captured VERBATIM from javamem.jar running against a live
// Tomcat 9 holding a resident memshell with the agent budget forced to 1 ms
// (lab/javamem-docker/docker/repro-truncated-jar.sh).
//
// A hand-written fixture would have proved only that the parser agrees with my idea of the jar's
// output. The jar used to emit a bare findings array with no coverage block at all, so its budget
// exhaustion was unreportable however much it knew; the point of using its real bytes is to show
// the core reads what the probe actually sends.
const jarTruncatedOutput = `{"findings":[],"coverage":{"status":"degraded",` +
	`"reason":"in-JVM sweep truncated — pid 1: time budget exhausted after 0 class(es) captured",` +
	`"targets_scanned":1,"truncated":true}}`

// And the same probe on a completed sweep, also captured verbatim.
const jarCompleteOutput = `{"findings":[],"coverage":{"status":"ran","reason":"",` +
	`"targets_scanned":1,"truncated":false}}`

func TestJarTruncatedOutputReachesTheVerdict(t *testing.T) {
	_, cov := parseProbeOutput("java-mem", []byte(jarTruncatedOutput))
	if !cov.Truncated {
		t.Fatalf("the jar's truncation must survive parsing, got %+v", cov)
	}
	if cov.Status != finding.CovDegraded {
		t.Errorf("status = %q, want degraded", cov.Status)
	}

	// The fusion layer is shared between the two delivery paths, so this is what closes the hole on
	// the jar path: the same flag, the same consequence.
	v, _ := fusion.Assess(nil, []finding.Coverage{cov})
	if !v.Incomplete {
		t.Error("a truncated jar sweep must make the scan incomplete")
	}
	if v.Tier != finding.TierUnknown {
		t.Errorf("a truncated sweep that found nothing must not report clean, got %s", v.Tier)
	}
}

func TestJarCompletedOutputIsNotTruncated(t *testing.T) {
	_, cov := parseProbeOutput("java-mem", []byte(jarCompleteOutput))
	if cov.Truncated {
		t.Error("a completed jar sweep must not be truncated")
	}
	v, _ := fusion.Assess(nil, []finding.Coverage{cov})
	if v.Incomplete || v.Tier != finding.TierClean {
		t.Errorf("a completed clean sweep must stay clean and complete, got %s incomplete=%v",
			v.Tier, v.Incomplete)
	}
}

// The legacy bare array must keep working. Older javamem.jar builds emit it, the core has always
// accepted it, and a version-skewed bundle pairing an old probe with a new core must not break --
// it simply cannot report truncation, which is the state the Windows path was in before this change.
func TestLegacyBareArrayStillParses(t *testing.T) {
	_, cov := parseProbeOutput("java-mem", []byte(`[]`))
	if cov.Status != finding.CovRan {
		t.Errorf("a legacy bare array must still parse as ran, got %q", cov.Status)
	}
	if cov.Truncated {
		t.Error("a legacy probe cannot report truncation, so it must read as not truncated")
	}
}
