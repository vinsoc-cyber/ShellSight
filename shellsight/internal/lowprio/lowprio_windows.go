package lowprio

import (
	"fmt"
	"syscall"
)

// PROCESS_MODE_BACKGROUND_BEGIN lowers CPU priority AND I/O priority in one call, which is exactly
// what FR-042 asks for. Documented by Microsoft as the way to mark a process as background so that it
// yields to foreground work -- the Windows equivalent of nice plus an idle I/O class.
const processModeBackgroundBegin = 0x00100000

var (
	kernel32           = syscall.NewLazyDLL("kernel32.dll")
	procSetPriority    = kernel32.NewProc("SetPriorityClass")
	procGetCurrentProc = kernel32.NewProc("GetCurrentProcess")
)

// Reduce puts this process into background mode.
//
// Windows is not what spec 002 is about, but the flag lives on the shared CLI, and a flag that
// silently does nothing on one platform is worse than one that is absent: an operator would believe a
// live Windows IIS host was being swept gently when it was not.
func Reduce() Report {
	handle, _, _ := procGetCurrentProc.Call()
	ret, _, err := procSetPriority.Call(handle, processModeBackgroundBegin)
	if ret == 0 {
		// The documented failure is ERROR_PROCESS_MODE_ALREADY_BACKGROUND, which is a success for our
		// purposes -- the process is already where we want it.
		if errno, ok := err.(syscall.Errno); ok && errno == 402 {
			return Report{
				CPU: "already background", IO: "already background",
				CPUApplied: true, IOApplied: true,
			}
		}
		msg := fmt.Sprintf("could not enter background mode: %v", err)
		return Report{CPU: msg, IO: msg}
	}
	return Report{
		CPU:        "background mode",
		IO:         "background mode",
		CPUApplied: true,
		IOApplied:  true,
	}
}

// ioClass has no meaning on Windows: background mode sets CPU and I/O together and exposes no class
// to read back.
func ioClass() int { return -1 }
