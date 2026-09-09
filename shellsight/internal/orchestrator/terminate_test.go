package orchestrator

import (
	"context"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"

	"shellsight/internal/finding"
)

// T027a. A probe killed for exceeding --timeout must get the chance to clean up first.
//
// Measured against the real binaries, the probe half is settled: the pre-fix probe left its decoded
// mirror behind on SIGTERM as well as SIGKILL; the fixed one removes it on SIGTERM and still leaks on
// SIGKILL, which is unavoidable — SIGKILL cannot be handled, and that is precisely why the core must
// send SIGTERM FIRST.
//
// This tests the core's half of that contract, and it does so with a helper process rather than the
// disk probe because the disk probe's mirror only exists inside a narrow window: measured at
// 10.95s–12.63s of one 600-file synthetic scan, and on real obfuscated content the rule-compilation
// phase alone outlasted a 20s timeout. Racing that window makes a flaky test out of a deterministic
// property.

const helperEnv = "SHELLSIGHT_TERMINATE_HELPER_SENTINEL"

// TestHelperProbe is not a test: it is the child process the tests below spawn. It writes a sentinel,
// removes it on SIGTERM, and otherwise runs until killed — exactly the shape of a probe with deferred
// cleanup.
func TestHelperProbe(t *testing.T) {
	sentinel := os.Getenv(helperEnv)
	if sentinel == "" {
		t.Skip("not the helper invocation")
	}
	if err := os.WriteFile(sentinel, []byte("cleanup pending\n"), 0o600); err != nil {
		os.Exit(3)
	}
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM, os.Interrupt)
	select {
	case <-sigs:
		os.Remove(sentinel) // what `defer os.RemoveAll(mirror)` does in the real probe
		os.Exit(0)
	case <-time.After(30 * time.Second):
		os.Exit(4)
	}
}

func helperProbe(t *testing.T, sentinel string) Probe {
	t.Helper()
	return Probe{
		View: "disk",
		Path: os.Args[0],
		Args: []string{"-test.run=TestHelperProbe", "-test.v=false"},
	}
}

func TestATimedOutProbeIsAskedToCleanUpBeforeItIsKilled(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("SIGTERM is not deliverable on Windows; see the companion test for what Windows gets")
	}
	sentinel := filepath.Join(t.TempDir(), "mirror-marker")
	p := helperProbe(t, sentinel)
	t.Setenv(helperEnv, sentinel)

	// A timeout shorter than the helper's lifetime, so the deadline is what ends it.
	run := runProbe(context.Background(), p, finding.TargetSpec{Host: "h"}, 700*time.Millisecond, probeRunOptions{})

	if run.Coverage.Status != finding.CovFailed {
		t.Fatalf("a timed-out probe must report failed, got %+v", run.Coverage)
	}
	// The property under test: the child got a signal it could act on, and acted on it.
	if _, err := os.Stat(sentinel); !os.IsNotExist(err) {
		t.Fatalf("the probe was not given the chance to clean up: %q still exists (err=%v)", sentinel, err)
	}
}

func TestTheGracePeriodIsBoundedSoAnIgnoredSignalStillTerminates(t *testing.T) {
	// WaitDelay is what makes the polite signal safe. Without it, a probe that IGNORED SIGTERM would
	// hang the scan forever, and the previous SIGKILL behaviour at least always terminated. This is
	// asserted on the value because reproducing it needs a deliberately unkillable child.
	if terminateGrace <= 0 {
		t.Fatal("an unbounded grace period would let an unresponsive probe hang the scan")
	}
	if terminateGrace > 30*time.Second {
		t.Fatalf("a %v grace period is long enough that an operator would think the scan hung", terminateGrace)
	}
}

func TestPoliteTerminationIsInstalledOnEveryProbeInvocation(t *testing.T) {
	// Guards against the fix being applied to one call site. Cancel and WaitDelay must both be set:
	// Cancel alone would make an ignored signal hang, and WaitDelay alone would keep SIGKILL.
	cmd := exec.Command(os.Args[0], "-test.run=TestHelperProbe")
	politeTermination(cmd)
	if cmd.Cancel == nil {
		t.Error("Cancel must be set, or cancellation goes straight to SIGKILL")
	}
	if cmd.WaitDelay == 0 {
		t.Error("WaitDelay must be set, or a probe that ignores SIGTERM hangs the scan")
	}
}

func TestWindowsKeepsItsExistingKillBehaviour(t *testing.T) {
	// The Cancel func sends SIGTERM and falls back to Kill when Signal reports it unsupported, which
	// is what Windows does. So Windows behaviour is unchanged rather than newly dependent on a signal
	// it cannot deliver — asserted here so a future "simplification" to Signal-only is caught.
	if runtime.GOOS != "windows" {
		t.Skip("this asserts the Windows fallback")
	}
	sentinel := filepath.Join(t.TempDir(), "marker")
	p := helperProbe(t, sentinel)
	t.Setenv(helperEnv, sentinel)
	run := runProbe(context.Background(), p, finding.TargetSpec{Host: "h"}, 700*time.Millisecond, probeRunOptions{})
	if run.Coverage.Status != finding.CovFailed {
		t.Fatalf("a timed-out probe must still report failed on Windows, got %+v", run.Coverage)
	}
}
