package orchestrator

import (
	"os/exec"
	"syscall"
	"time"
)

// Killing a probe the polite way first, so it can clean up after itself (T027a, FR-004).
//
// THE DEFECT THIS CLOSES, measured rather than reasoned. exec.CommandContext kills a probe that
// exceeds --timeout with SIGKILL, which is unhandleable: deferred cleanup does not run. The disk
// probe writes a decoded mirror of obfuscated files under /tmp and removes it with `defer
// os.RemoveAll`, so a killed scan left it behind. `kill -9` during a scan of php/obfuscated-large
// left /tmp/ss-deobf-1646598990 holding 45 DECODED webshells, mode 0700.
//
// And it lands on the worst host, not a rare one. Scan cost tracks how obfuscated the content is
// (0.26 s/file on obfuscated shells against 0.011 s/file on clean framework code), so the run most
// likely to hit the timeout is the run on the compromised host — and what it leaves is a decoded copy
// of the intruder's code, outside the tree the operator scanned, under a name they will not recognise.
//
// Nothing the probe does alone can fix this, which is why the fix lives here.

// terminateGrace is how long a probe gets between the polite signal and the unhandleable one.
//
// 5s, and the direction of the trade matters: too short and cleanup is cut off, which is the bug;
// too long and an operator waits on a probe that is already not answering. Cleanup is an os.RemoveAll
// over a directory the probe itself created, so it is fast when it works at all — and WaitDelay is a
// ceiling, not a sleep. A probe that exits immediately costs nothing.
const terminateGrace = 5 * time.Second

// politeTermination arranges SIGTERM-then-SIGKILL for a context-cancelled probe.
//
// Cross-platform without build tags: os.Process.Signal returns an error for SIGTERM on Windows
// ("not supported by windows"), and the fallback is the Kill that CommandContext would have done
// anyway. So Windows behaviour is unchanged and Linux gains the grace period.
func politeTermination(cmd *exec.Cmd) {
	cmd.Cancel = func() error {
		if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
			return cmd.Process.Kill()
		}
		return nil
	}
	// Without WaitDelay, Cancel sending a catchable signal to a probe that ignores it would hang the
	// scan forever — the previous behaviour at least always terminated. WaitDelay is what makes the
	// polite signal safe: SIGKILL follows if the probe has not exited.
	cmd.WaitDelay = terminateGrace
}
