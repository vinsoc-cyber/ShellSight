//go:build !windows && !linux

package orchestrator

import "errors"

// peakWorkingSetSupported: no portable process-memory API on this platform, so the observation
// channel says so rather than reporting a fabricated zero as a measurement.
const peakWorkingSetSupported = false

var errPeakWorkingSetUnsupported = errors.New("process working-set sampling unsupported on this platform")

type processMem struct{}

func openProcessMem(int) (*processMem, error) { return nil, errPeakWorkingSetUnsupported }

func (p *processMem) sample() (int64, error) { return 0, errPeakWorkingSetUnsupported }

func (p *processMem) close() {}
