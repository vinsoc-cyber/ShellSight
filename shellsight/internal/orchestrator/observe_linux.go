//go:build linux

package orchestrator

import (
	"os"
	"strconv"
)

// peakWorkingSetSupported: Linux reports a resident-set high-water mark through /proc/<pid>/status.
const peakWorkingSetSupported = true

type processMem struct{ statusPath string }

func openProcessMem(pid int) (*processMem, error) {
	path := "/proc/" + strconv.Itoa(pid) + "/status"
	if _, err := os.Stat(path); err != nil {
		return nil, err
	}
	return &processMem{statusPath: path}, nil
}

// sample reads VmHWM (kB) — the kernel's own peak, so no sampling interval can miss a spike between
// polls. Parsing lives in parseVmHWMBytes (untagged) so it is testable on any host.
func (p *processMem) sample() (int64, error) {
	data, err := os.ReadFile(p.statusPath)
	if err != nil {
		return 0, err
	}
	return parseVmHWMBytes(data)
}

func (p *processMem) close() {}
