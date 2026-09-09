package lowprio

import (
	"testing"

	"golang.org/x/sys/unix"
)

// The Linux half is where the syscall numbers live, and a wrong number is the failure mode that looks
// like success: Syscall returns 0 against some other call entirely, and the code would report a
// throttle that never happened.

func TestTheIOClassIsActuallyIdleAfterwards(t *testing.T) {
	before := ioClass()
	r := Reduce()
	if !r.IOApplied {
		t.Skipf("this kernel or container refused the I/O class (%s) -- the honest report is the "+
			"contract here, not the throttle", r.IO)
	}
	// Read back through the same path the caller does not trust: the point is that the KERNEL agrees,
	// not that our call returned zero.
	if got := ioClass(); got != ioprioClassIdle {
		t.Fatalf("Reduce claimed the idle class but the kernel reports %d (was %d before)", got, before)
	}
}

func TestTheNicenessIsActuallyInEffectAfterwards(t *testing.T) {
	r := Reduce()
	if !r.CPUApplied {
		t.Skipf("renice refused: %s", r.CPU)
	}
	got, err := unix.Getpriority(unix.PRIO_PROCESS, 0)
	if err != nil {
		t.Skipf("cannot read priority back: %v", err)
	}
	// Getpriority returns 20-nice, so nice 10 reads back as 10. Asserting the transform rather than
	// the raw number keeps this honest if the constant changes.
	if want := 20 - niceness; got != want {
		t.Fatalf("niceness not in effect: Getpriority reports %d, want %d for nice %d", got, want, niceness)
	}
}

func TestEveryShippedArchitectureHasAnIoprioNumber(t *testing.T) {
	// The release ships linux/amd64 and linux/arm64. An architecture missing from the table gets a
	// reason instead of a wrong syscall, which is safe -- but it also means no I/O throttle at all, so
	// the two we actually ship must be present.
	for _, arch := range []string{"amd64", "arm64"} {
		nums, ok := ioprioSyscalls[arch]
		if !ok {
			t.Errorf("linux/%s is a shipped target with no ioprio syscall number", arch)
			continue
		}
		// get is always set+1 in the kernel's tables; a transposed pair would set priority when asked
		// to read it.
		if nums.get != nums.set+1 {
			t.Errorf("linux/%s: get (%d) must be set (%d) + 1", arch, nums.get, nums.set)
		}
	}
}

func TestReduceIsIdempotent(t *testing.T) {
	// Called twice -- a retry, or a caller that is unsure -- must not degrade further or start failing.
	first := Reduce()
	second := Reduce()
	if first.CPUApplied != second.CPUApplied || first.IOApplied != second.IOApplied {
		t.Fatalf("not idempotent: %+v then %+v", first, second)
	}
}
