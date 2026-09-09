package orchestrator

import (
	"bytes"
	"errors"
	"io"
	"strconv"
	"time"
)

// Capture bounds for a probe's streams. Beyond these a probe is malfunctioning, so the run is
// covered as failed (stdout) or degraded (stderr) rather than trusted whole. They are vars, not
// consts, only so tests can exercise the overflow path without moving a quarter of a gigabyte
// through a pipe.
var (
	probeStdoutCaptureLimit int64 = 256 << 20 // 256 MiB
	probeStderrCaptureLimit int64 = 1 << 20   // 1 MiB
)

// memSampleInterval is how often a running probe's peak process memory is polled. Both platform
// backends read a HIGH-WATER MARK the OS maintains, so the interval does not determine accuracy —
// polling exists only because the counter cannot be read once the process has exited. Sampling is
// observation only: it never gates, delays or alters the probe's result, and it runs only when the
// caller asked for it (see probeRunOptions).
const memSampleInterval = 25 * time.Millisecond

// memSamplerJoinTimeout bounds how long stopping the sampler may hold up a scan. The peak channel is
// buffered, so a sampler still blocked in a platform read can publish and exit on its own afterwards
// rather than leaking; we simply stop waiting for a number that is pure telemetry.
const memSamplerJoinTimeout = 500 * time.Millisecond

// maxProbeStderrReasonBytes bounds how much captured stderr can appear in a coverage reason. It is
// NOT what os/exec's Output() did: that kept the first 32 KiB AND the last 32 KiB of stderr
// (prefixSuffixSaver) with an omission marker between them. We keep only the last 32 KiB, because a
// probe's fatal error is at the end of its output — so a reason is never larger than before, and for
// any realistic stderr it is byte-for-byte the same text operators already expect.
const maxProbeStderrReasonBytes = 32 << 10

// ProbeObservation is the host's view of one probe process: how long it ran, how much CPU it
// burned, and its peak process memory. It is telemetry for the measurement build — no field of it
// reaches detection, scoring or fusion. Wall and CPU nanoseconds come free from the process state;
// PeakWorkingSetBytes is 0 unless the caller asked for memory observation.
type ProbeObservation struct {
	WallNanos               int64 `json:"wall_nanos"`
	CPUNanos                int64 `json:"cpu_nanos"`
	PeakWorkingSetBytes     int64 `json:"peak_working_set_bytes"`
	PeakWorkingSetSupported bool  `json:"peak_working_set_supported"`
}

// captureResult is one fully drained stream, handed back over a channel. The buffer is built and
// owned by a single goroutine and published exactly once, so there is nothing to lock.
type captureResult struct {
	data     []byte
	overflow bool
}

// captureBounded drains r in its own goroutine, keeping at most limit bytes. It keeps reading past
// the limit (discarding) so the child can never wedge on a full pipe, and reports whether the
// stream exceeded the limit.
func captureBounded(r io.Reader, limit int64) <-chan captureResult {
	out := make(chan captureResult, 1)
	go func() {
		var kept bytes.Buffer
		var total int64
		chunk := make([]byte, 32<<10)
		for {
			n, err := r.Read(chunk)
			if n > 0 {
				total += int64(n)
				if room := limit - int64(kept.Len()); room > 0 {
					if int64(n) > room {
						kept.Write(chunk[:room])
					} else {
						kept.Write(chunk[:n])
					}
				}
			}
			if err != nil {
				break
			}
		}
		out <- captureResult{data: kept.Bytes(), overflow: total > limit}
	}()
	return out
}

// memSampler polls one process's peak memory until stopped. The peak lives only in the sampler
// goroutine and is published once over a channel, so the value needs no lock.
type memSampler struct {
	done chan struct{}
	peak chan int64
}

// openProcessMemFn is the platform hook the sampler attaches with. It is a var only so a test can
// prove the production path never attaches to the child at all.
var openProcessMemFn = openProcessMem

// startMemSampler begins sampling pid's peak process memory. On platforms without a working-set API
// the sampler still runs (and reports zero), so callers need no build-tagged branches. Callers that
// did not ask for memory observation must not call this at all — a nil *memSampler is a valid
// "sampling was never requested" and stop() reports 0 for it.
func startMemSampler(pid int) *memSampler {
	s := &memSampler{done: make(chan struct{}), peak: make(chan int64, 1)}
	go func() {
		var peak int64
		defer func() { s.peak <- peak }()

		handle, err := openProcessMemFn(pid)
		if err != nil {
			return
		}
		defer handle.close()

		ticker := time.NewTicker(memSampleInterval)
		defer ticker.Stop()
		for {
			if n, err := handle.sample(); err == nil && n > peak {
				peak = n
			}
			select {
			case <-s.done:
				return
			case <-ticker.C:
			}
		}
	}()
	return s
}

// stop ends sampling and returns the peak in bytes (0 if nothing was or could be sampled). It waits
// for the sampler's hand-off — which is also the happens-before edge that makes peak safe to read —
// but only for memSamplerJoinTimeout, so a wedged platform read can never hold up a scan. Call it
// exactly once.
func (s *memSampler) stop() int64 {
	if s == nil {
		return 0
	}
	close(s.done)
	select {
	case peak := <-s.peak:
		return peak
	case <-time.After(memSamplerJoinTimeout):
		return 0
	}
}

// errNoPeakWorkingSet reports that the platform did not expose a peak for this process (e.g. the
// /proc entry exists but carries no VmHWM line).
var errNoPeakWorkingSet = errors.New("peak working set not reported")

// parseVmHWMBytes extracts VmHWM — the kernel's resident-set high-water mark, the closest analogue of
// the Windows peak working set — from the contents of /proc/<pid>/status, in bytes. It lives here,
// untagged, so it is unit-testable on any host rather than only on the platform that calls it.
func parseVmHWMBytes(status []byte) (int64, error) {
	const maxKilobytes = (1<<63 - 1) / 1024
	for len(status) > 0 {
		line := status
		if index := bytes.IndexByte(status, '\n'); index >= 0 {
			line, status = status[:index], status[index+1:]
		} else {
			status = nil
		}
		rest, ok := bytes.CutPrefix(line, []byte("VmHWM:"))
		if !ok {
			continue
		}
		fields := bytes.Fields(rest)
		if len(fields) == 0 {
			return 0, errNoPeakWorkingSet
		}
		kilobytes, err := strconv.ParseInt(string(fields[0]), 10, 64)
		if err != nil {
			return 0, err
		}
		if kilobytes < 0 || kilobytes > maxKilobytes {
			return 0, errNoPeakWorkingSet
		}
		return kilobytes * 1024, nil
	}
	return 0, errNoPeakWorkingSet
}
