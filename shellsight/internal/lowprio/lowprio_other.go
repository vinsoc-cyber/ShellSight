//go:build !linux && !windows

package lowprio

import "runtime"

// Reduce is a no-op on platforms this release does not build for, and says so.
//
// Reporting success would be the dangerous failure: an operator would run a full-speed sweep of a live
// host believing it was throttled. Not-applied with a reason is the honest answer.
func Reduce() Report {
	msg := "lowering priority is not implemented on " + runtime.GOOS
	return Report{CPU: msg, IO: msg}
}

func ioClass() int { return -1 }
