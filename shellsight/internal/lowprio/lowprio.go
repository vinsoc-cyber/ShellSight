// Package lowprio lowers this process's CPU and I/O priority so that sweeping a live production web
// server does not degrade it (FR-042).
//
// WHY THIS IS A RELEASE ITEM AND NOT A NICETY. A webshell sweep is an I/O-bound walk of every file in
// every webroot, with YARA over each one and a deobfuscation pass on top. On the box a responder cares
// most about -- a production web server mid-incident -- that competes directly with the thing serving
// requests. The incumbent ships this as `-lowcpu`; we had no equivalent, which makes "run it now, on
// the live host" a harder sell than it should be.
//
// BEST EFFORT, AND HONEST ABOUT IT. Lowering priority can fail: an unprivileged process may not be
// allowed to change I/O class on some kernels, and a container may block it. A failure must never stop
// the scan -- the scan is the point -- so Reduce reports what it achieved and the caller says so
// rather than pretending. Reporting "low priority" when nothing changed would be worse than not having
// the flag: an operator would run a full-speed sweep believing it was throttled.
package lowprio

import "strings"

// Report is what Reduce actually managed to change.
type Report struct {
	// CPU and IO describe each half, e.g. "nice 10" or "not permitted: operation not permitted".
	CPU string
	IO  string
	// CPUApplied and IOApplied are the honest bits. An operator deciding whether to run this on a
	// live host needs to know which half took effect, not a single boolean that hides the other.
	CPUApplied bool
	IOApplied  bool
}

// Applied reports whether anything took effect at all.
func (r Report) Applied() bool { return r.CPUApplied || r.IOApplied }

// String is the operator-facing line.
func (r Report) String() string {
	var parts []string
	if r.CPU != "" {
		parts = append(parts, "cpu: "+r.CPU)
	}
	if r.IO != "" {
		parts = append(parts, "io: "+r.IO)
	}
	if len(parts) == 0 {
		return "unchanged"
	}
	return strings.Join(parts, ", ")
}

// niceness is how far to lower CPU priority.
//
// 10, not 19. 19 is "only run when the machine is otherwise completely idle", which on a busy web
// server can stretch a sweep from minutes to hours and invites an operator to kill it -- a scan that
// does not finish detects nothing. 10 yields decisively to the web server while still making progress.
const niceness = 10
