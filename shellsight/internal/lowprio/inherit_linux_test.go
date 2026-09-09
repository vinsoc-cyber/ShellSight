package lowprio

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
)

// The property that decides whether --low-priority is worth anything.
//
// The core process barely touches the disk: the probes walk every file in every webroot, run YARA over
// each one and deobfuscate on top. Throttling only the core would throttle nothing that matters. So
// the throttle has to survive fork and exec.
//
// ioprio_set(2) documents I/O priority as inherited across fork; niceness likewise. This asserts the
// niceness half against a real child process, because "documented" and "true on this kernel" are not
// the same claim, and the whole feature rests on it.

func TestAChildProcessInheritsTheThrottle(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skipf("no shell to spawn a child with: %v", err)
	}
	r := Reduce()
	if !r.CPUApplied {
		t.Skipf("renice refused: %s", r.CPU)
	}

	// Field 19 of /proc/self/stat is the nice value. Read from the CHILD's own stat, so this is the
	// child reporting on itself rather than the parent guessing.
	out, err := exec.Command(sh, "-c", "awk '{print $19}' /proc/self/stat").Output()
	if err != nil {
		t.Skipf("cannot read the child's stat: %v", err)
	}
	got, err := strconv.Atoi(strings.TrimSpace(string(out)))
	if err != nil {
		t.Skipf("unexpected stat output %q: %v", out, err)
	}
	if got != niceness {
		t.Fatalf("a child process runs at nice %d, not the %d this scan was throttled to -- the "+
			"probes do the file walking, so a throttle they do not inherit throttles nothing", got, niceness)
	}
}

func TestTheParentIsWhereTheThrottleIsSet(t *testing.T) {
	// Guards against a tempting wrong fix: setting priority inside each probe instead of once in the
	// core. That would need every probe to grow the flag, and a probe launched by anything else --
	// the measurement harness, a debugging invocation -- would silently run at full speed.
	Reduce()
	self, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		t.Skipf("cannot read own stat: %v", err)
	}
	fields := strings.Fields(string(self))
	if len(fields) < 19 {
		t.Skipf("unexpected stat format")
	}
	got, err := strconv.Atoi(fields[18])
	if err != nil {
		t.Skipf("unexpected nice field %q", fields[18])
	}
	if got != niceness {
		t.Fatalf("the calling process itself must be throttled, got nice %d want %d", got, niceness)
	}
}
