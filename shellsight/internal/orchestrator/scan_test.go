package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"shellsight/internal/finding"
)

// buildMockProbe compiles cmd/mockprobe into a temp exe and returns its path.
// It runs `go build` from the module root (derived from this test file's path)
// so the import path resolves regardless of the test's working directory.
func buildMockProbe(t *testing.T) string {
	t.Helper()
	// Skip rather than fail when there is no toolchain. Every Linux-only property in this feature is
	// checked by cross-building this test binary on Windows and running it under WSL, which has no Go
	// installed -- so without this the whole package reads as broken on the platform it exists to
	// verify, and a permanently-red suite is one people stop reading.
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("no Go toolchain here: this test builds cmd/mockprobe (cross-built runs hit this)")
	}
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate test file path")
	}
	// thisFile = <module>/internal/orchestrator/scan_test.go → module root is three dirs up.
	moduleRoot := filepath.Join(filepath.Dir(thisFile), "..", "..")

	out := filepath.Join(t.TempDir(), "mockprobe.exe")
	cmd := exec.Command("go", "build", "-o", out, "shellsight/cmd/mockprobe")
	cmd.Dir = moduleRoot
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build mockprobe: %v\n%s", err, b)
	}
	return out
}

func TestRunProbeEmitsFindings(t *testing.T) {
	exe := buildMockProbe(t)
	p := Probe{View: "mock", Path: exe, Args: []string{"emit"}}
	fs, cov := RunProbe(context.Background(), p, finding.TargetSpec{Host: "WEB01"}, 10*time.Second)
	if cov.Status != finding.CovRan {
		t.Fatalf("want ran, got %s (%s)", cov.Status, cov.Reason)
	}
	if len(fs) != 1 || fs[0].Tier != finding.TierSuspicious {
		t.Fatalf("want 1 suspicious finding, got %+v", fs)
	}
}

func TestRunProbeFailureIsCoveredNotClean(t *testing.T) {
	exe := buildMockProbe(t)
	p := Probe{View: "mock", Path: exe, Args: []string{"fail"}}
	fs, cov := RunProbe(context.Background(), p, finding.TargetSpec{Host: "WEB01"}, 10*time.Second)
	if len(fs) != 0 {
		t.Fatalf("failed probe must yield 0 findings, got %d", len(fs))
	}
	if cov.Status != finding.CovFailed {
		t.Fatalf("want failed coverage, got %s", cov.Status)
	}
}

func TestRunProbeTimeout(t *testing.T) {
	exe := buildMockProbe(t)
	p := Probe{View: "mock", Path: exe, Args: []string{"hang"}}
	_, cov := RunProbe(context.Background(), p, finding.TargetSpec{Host: "WEB01"}, 500*time.Millisecond)
	if cov.Status != finding.CovFailed {
		t.Fatalf("hang must time out to failed, got %s", cov.Status)
	}
}

func TestScanCollectsFindingsAndStaysHonest(t *testing.T) {
	exe := buildMockProbe(t)
	probes := []Probe{
		{View: "mock-a", Path: exe, Args: []string{"emit"}},
		{View: "mock-b", Path: exe, Args: []string{"fail"}},
	}
	rep := Scan(context.Background(), probes, finding.TargetSpec{Host: "WEB01"}, "test", "run-1", 10*time.Second)

	if len(rep.Findings) != 1 {
		t.Fatalf("want 1 finding from the emit probe, got %d", len(rep.Findings))
	}
	if len(rep.Coverage) != 2 {
		t.Fatalf("want 2 coverage entries, got %d", len(rep.Coverage))
	}
	// The failed view must be visible AND make the verdict incomplete — never folded into clean.
	if !rep.Verdict.Incomplete {
		t.Fatal("a failed view must set verdict.incomplete")
	}
	if rep.Verdict.Tier != finding.TierSuspicious {
		t.Fatalf("want suspicious (from emit), got %s", rep.Verdict.Tier)
	}
}

func TestScanEmptyFindingsSerializeAsArrayNotNull(t *testing.T) {
	exe := buildMockProbe(t)
	probes := []Probe{{View: "mock-fail", Path: exe, Args: []string{"fail"}}}
	rep := Scan(context.Background(), probes, finding.TargetSpec{Host: "WEB01"}, "test", "run-1", 10*time.Second)
	b, err := json.Marshal(rep)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(b), `"findings":null`) {
		t.Fatalf("findings must serialize as [] not null: %s", b)
	}
	if !strings.Contains(string(b), `"findings":[]`) {
		t.Fatalf("expected empty findings array: %s", b)
	}
}

// --- not-applicable capabilities (US4) ---

// A capability the host cannot support is decided by the capability table, not by trying to run it:
// Path deliberately names a binary that does not exist, so an execution attempt would come back
// `failed` and fail this test. What must come back is one n/a record carrying its reason.
func TestANotApplicableCapabilityIsCoveredWithoutBeingRun(t *testing.T) {
	p := Probe{
		View:          "dotnet-mem",
		Path:          filepath.Join(t.TempDir(), "there-is-no-such-binary"),
		NotApplicable: "dotnet-mem is supported on windows only; this host is linux",
	}
	fs, cov := RunProbe(context.Background(), p, finding.TargetSpec{Host: "web01"}, 10*time.Second)
	if len(fs) != 0 {
		t.Fatalf("a capability that cannot exist must produce no findings, got %d", len(fs))
	}
	if cov.Status != finding.CovNA {
		t.Fatalf("want %s, got %s (%s)", finding.CovNA, cov.Status, cov.Reason)
	}
	if cov.View != "dotnet-mem" || cov.Reason != p.NotApplicable {
		t.Fatalf("the record must name the view and keep its reason, got %+v", cov)
	}
}

// The invariant the report depends on: the requested set and the coverage list are one to one. A
// capability that is silently absent from coverage is indistinguishable from one nobody asked for,
// and that is the difference between "we did not look there" and "there was nothing to look at".
func TestEveryRequestedCapabilityProducesExactlyOneCoverageRecord(t *testing.T) {
	exe := buildMockProbe(t)
	probes := []Probe{
		{View: "disk", Path: exe, Args: []string{"emit"}},
		{View: "java-mem", Path: exe, Args: []string{"fail"}},
		{View: "dotnet-mem", NotApplicable: "dotnet-mem is supported on windows only; this host is linux"},
		{View: "behavioral", NotApplicable: "behavioral is supported on windows only; this host is linux"},
	}
	rep := Scan(context.Background(), probes, finding.TargetSpec{Host: "web01"}, "test", "run-1", 10*time.Second)

	if len(rep.Coverage) != len(probes) {
		t.Fatalf("want one coverage record per requested capability (%d), got %d: %+v",
			len(probes), len(rep.Coverage), rep.Coverage)
	}
	want := map[string]string{
		"disk": finding.CovRan, "java-mem": finding.CovFailed,
		"dotnet-mem": finding.CovNA, "behavioral": finding.CovNA,
	}
	seen := map[string]int{}
	for _, c := range rep.Coverage {
		seen[c.View]++
		if got := want[c.View]; c.Status != got {
			t.Errorf("%s: want status %q, got %q (%s)", c.View, got, c.Status, c.Reason)
		}
	}
	for view := range want {
		if seen[view] != 1 {
			t.Errorf("%s appears %d times in coverage, want exactly 1", view, seen[view])
		}
	}
	// The failed view still dominates: n/a records must not soften a real gap.
	if !rep.Verdict.Incomplete {
		t.Error("a failed view must still set verdict.incomplete alongside n/a records")
	}
}

// The same scan twice must produce the same coverage list. Probes finish in whatever order they
// finish, and a report that reorders its own coverage between identical runs makes every comparison
// -- release to release, host to host, platform to platform -- report differences that are not there.
func TestCoverageOrderIsDeterministic(t *testing.T) {
	exe := buildMockProbe(t)
	probes := []Probe{
		{View: "native-mem", NotApplicable: "native-mem is supported on windows only; this host is linux"},
		{View: "disk", Path: exe, Args: []string{"emit"}},
		{View: "behavioral", NotApplicable: "behavioral is supported on windows only; this host is linux"},
		{View: "java-mem", Path: exe, Args: []string{"fail"}},
	}
	want := []string{"behavioral", "disk", "java-mem", "native-mem"}
	for run := 0; run < 3; run++ {
		rep := Scan(context.Background(), probes, finding.TargetSpec{Host: "web01"}, "test", "run-1", 10*time.Second)
		var got []string
		for _, c := range rep.Coverage {
			got = append(got, c.View)
		}
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Fatalf("run %d: coverage order = %v, want %v", run, got, want)
		}
	}
}

// FR-012: any status other than `ran` carries a reason. A probe that declares `degraded` and says
// nothing leaves the operator with a report that admits a gap it will not describe, so the
// orchestrator states what it knows — which probe, and that the probe gave no reason — rather than
// passing an empty string through to the report.
func TestANonRanStatusWithoutAReasonGetsOne(t *testing.T) {
	for _, status := range []string{finding.CovDegraded, finding.CovFailed, finding.CovNA} {
		out := fmt.Sprintf(`{"findings":[],"coverage":{"status":%q}}`, status)
		_, cov := parseProbeOutputDetailed("disk", []byte(out))
		if cov.Status != status {
			t.Fatalf("%s: status was rewritten to %q", status, cov.Status)
		}
		if strings.TrimSpace(cov.Reason) == "" {
			t.Errorf("%s: a non-ran status must carry a reason, got none", status)
		}
	}
	// ...and `ran` needs none: inventing one would put prose in every clean report.
	_, cov := parseProbeOutputDetailed("disk", []byte(`{"findings":[],"coverage":{"status":"ran"}}`))
	if cov.Reason != "" {
		t.Errorf("a clean run must not be given a reason, got %q", cov.Reason)
	}
}
