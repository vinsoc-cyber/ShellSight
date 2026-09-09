package lowprio

import (
	"fmt"
	"runtime"

	"golang.org/x/sys/unix"
)

// ioprio_set / ioprio_get syscall numbers.
//
// golang.org/x/sys/unix v0.46.0 wraps Setpriority but not ioprio, so these go through raw syscalls.
// The numbers are architecture-specific: amd64 predates the generic table, arm64 uses it.
//
// Kept as runtime values rather than build-tagged constants because they are only ever passed to
// Syscall as integers, and one table is easier to check against the kernel's own than four files
// holding one number each. An architecture that is absent gets a reason, not a wrong syscall.
var ioprioSyscalls = map[string]struct{ set, get uintptr }{
	"amd64": {251, 252},
	"arm64": {30, 31},
	"386":   {289, 290},
	"arm":   {314, 315},
}

// I/O priority is a class plus a level packed into one int: class in the top 3 bits.
const (
	ioprioClassShift = 13
	ioprioWhoProcess = 1
	ioprioClassIdle  = 3
	ioprioClassBE    = 2
	ioprioClassMask  = 0x07
)

// Reduce lowers CPU niceness and I/O priority, reporting what took effect.
//
// The two halves are independent on purpose. CPU niceness is almost always permitted -- lowering your
// own priority needs no privilege -- while the I/O class can be refused by a kernel or a container. A
// single boolean would hide which one an operator actually got.
func Reduce() Report {
	var r Report

	if err := unix.Setpriority(unix.PRIO_PROCESS, 0, niceness); err != nil {
		r.CPU = fmt.Sprintf("could not renice: %v", err)
	} else {
		r.CPU = fmt.Sprintf("nice %d", niceness)
		r.CPUApplied = true
	}

	nums, ok := ioprioSyscalls[runtime.GOARCH]
	if !ok {
		r.IO = "no ioprio syscall number known for " + runtime.GOARCH
		return r
	}
	// IDLE means "only when nothing else wants the disk", which is the right default for a sweep of a
	// live server: the web server's reads always win.
	if _, _, errno := unix.Syscall(nums.set, ioprioWhoProcess, 0,
		uintptr(ioprioClassIdle<<ioprioClassShift)); errno != 0 {
		r.IO = fmt.Sprintf("could not set the I/O class: %v", errno)
		return r
	}
	// Read it back rather than trusting the return. A wrong syscall number can succeed against some
	// other call entirely, and "it returned 0" would then be a lie told confidently.
	got, _, errno := unix.Syscall(nums.get, ioprioWhoProcess, 0, 0)
	if errno != 0 {
		r.IO = fmt.Sprintf("set, but unverifiable: %v", errno)
		r.IOApplied = true
		return r
	}
	class := (int(got) >> ioprioClassShift) & ioprioClassMask
	if class != ioprioClassIdle {
		r.IO = fmt.Sprintf("the kernel reports class %d, not idle", class)
		return r
	}
	r.IO = "idle class"
	r.IOApplied = true
	return r
}

// ioClass reports the process's current I/O class, for tests. -1 when it cannot be read.
func ioClass() int {
	nums, ok := ioprioSyscalls[runtime.GOARCH]
	if !ok {
		return -1
	}
	got, _, errno := unix.Syscall(nums.get, ioprioWhoProcess, 0, 0)
	if errno != 0 {
		return -1
	}
	return (int(got) >> ioprioClassShift) & ioprioClassMask
}
