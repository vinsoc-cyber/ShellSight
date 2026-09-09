package lowprio

import (
	"runtime"
	"strings"
	"testing"
)

// FR-042. The property that matters is not "the call returned" but "the process is actually running
// at lower priority, and if it is not, we said so". Reporting a throttle that did not happen is worse
// than having no flag: an operator would sweep a live production web server at full speed believing
// it was being gentle.

func TestReduceReportsWhatItActuallyAchieved(t *testing.T) {
	r := Reduce()
	if r.CPU == "" || r.IO == "" {
		t.Fatalf("both halves must be accounted for, got %+v", r)
	}
	// The two are independent: lowering your own CPU priority needs no privilege, while the I/O class
	// can be refused by a kernel or a container. A single boolean would hide which one the operator
	// actually got.
	if r.CPUApplied && strings.Contains(r.CPU, "could not") {
		t.Errorf("CPU claims applied but reads as a failure: %q", r.CPU)
	}
	if r.IOApplied && strings.Contains(r.IO, "could not") {
		t.Errorf("IO claims applied but reads as a failure: %q", r.IO)
	}
	if !r.Applied() && r.String() == "unchanged" {
		t.Errorf("nothing applied AND nothing explained: %+v", r)
	}
	t.Logf("on %s/%s: %s", runtime.GOOS, runtime.GOARCH, r)
}

func TestTheNicenessIsNotSoLowThatAScanNeverFinishes(t *testing.T) {
	// 19 is "run only when the machine is otherwise completely idle", which on a busy web server can
	// stretch a sweep from minutes into hours and invites the operator to kill it. A scan that does
	// not finish detects nothing, so the throttle must yield without stalling.
	if niceness <= 0 {
		t.Fatalf("niceness %d does not lower anything", niceness)
	}
	if niceness >= 19 {
		t.Fatalf("niceness %d starves the scan on a busy host", niceness)
	}
}

func TestAFailureIsNeverReportedAsSuccess(t *testing.T) {
	// The one thing this package must never do.
	r := Report{CPU: "could not renice: operation not permitted", IO: "could not set the I/O class: x"}
	if r.Applied() {
		t.Fatal("a report with neither half applied must not claim success")
	}
	if !strings.Contains(r.String(), "could not") {
		t.Fatalf("the failure must survive into the operator-facing line, got %q", r.String())
	}
}

func TestTheReportLineNamesBothHalvesSeparately(t *testing.T) {
	// An operator on a live host needs to know whether the disk was throttled, the CPU, or both --
	// the I/O half is the one that protects request latency.
	line := Report{CPU: "nice 10", IO: "idle class", CPUApplied: true, IOApplied: true}.String()
	if !strings.Contains(line, "cpu:") || !strings.Contains(line, "io:") {
		t.Fatalf("both halves must be visible, got %q", line)
	}
}
