package orchestrator

import (
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"shellsight/internal/finding"
)

// The orchestrator test binary doubles as a mock probe: re-execing ourselves is cheaper and more
// portable than compiling a fixture per test iteration, and it exercises the real Start/Wait path.
// All fixture artifacts are inert path names — no payloads.
const mockProbeModeEnv = "SHELLSIGHT_ORCHESTRATOR_MOCK_PROBE"

// mockArtifactsOutput carries one complete, one degraded and one failed inert artifact.
const mockArtifactsOutput = `{"findings":[{"schema_version":"1.0","id":"mock-1","host":"WEB01","view":"mock",` +
	`"target":{"kind":"file","file":{"path":"inert/one.jar","sha256":"aa11"}},` +
	`"artifact":{"kind":"file-webshell","identity":"one.jar"},` +
	`"detection":{"basis":"heuristic","allowlisted":false},"score":40,"tier":"suspicious",` +
	`"classification":{"family":null,"capability":null,"source":null,"confidence":0},"artifacts":{}}],` +
	`"coverage":{"status":"degraded","reason":"java-class-malformed=1","targets_scanned":1},` +
	`"artifact_coverage":[` +
	`{"path":"inert/one.jar","sha256":"aa11","status":"complete","bytes":1024},` +
	`{"path":"inert/two.class","sha256":"bb22","status":"degraded","bytes":512,"diagnostic_codes":["java-class-malformed"]},` +
	`{"path":"inert/three.class","sha256":"","status":"failed","bytes":0,"diagnostic_codes":["java-artifact-read-failed"]}]}`

func TestMain(m *testing.M) {
	if mode := os.Getenv(mockProbeModeEnv); mode != "" {
		os.Exit(runMockProbe(mode))
	}
	os.Exit(m.Run())
}

func runMockProbe(mode string) int {
	_, _ = io.Copy(io.Discard, os.Stdin) // consume the target spec like a real probe
	switch mode {
	case "artifacts":
		os.Stdout.WriteString(mockArtifactsOutput)
	case "duplicate-paths":
		os.Stdout.WriteString(`{"findings":[],"artifact_coverage":[` +
			`{"path":"inert/one.jar","sha256":"aa11","status":"complete","bytes":1},` +
			`{"path":"inert/one.jar","sha256":"aa11","status":"degraded","bytes":1}]}`)
	case "sha-mismatch":
		os.Stdout.WriteString(`{"findings":[{"view":"mock","target":{"kind":"file",` +
			`"file":{"path":"inert/one.jar","sha256":"aa11"}}}],` +
			`"artifact_coverage":[{"path":"inert/one.jar","sha256":"ff99","status":"complete","bytes":1}]}`)
	case "flood-stdout":
		chunk := strings.Repeat("s", 4096)
		for i := 0; i < 8; i++ {
			os.Stdout.WriteString(chunk)
		}
	case "flood-stderr":
		chunk := strings.Repeat("e", 4096)
		for i := 0; i < 8; i++ {
			os.Stderr.WriteString(chunk)
		}
		os.Stdout.WriteString(`{"findings":[]}`)
	case "flood-stderr-bad-stdout":
		chunk := strings.Repeat("e", 4096)
		for i := 0; i < 8; i++ {
			os.Stderr.WriteString(chunk)
		}
		os.Stdout.WriteString(`{"findings":[`) // truncated document: the parse must still fail
	case "exit-with-stderr":
		os.Stderr.WriteString("mock probe: simulated failure\n")
		return 3
	case "burn":
		deadline := time.Now().Add(150 * time.Millisecond)
		sink := make([]byte, 0, 8<<20)
		for time.Now().Before(deadline) {
			sink = append(sink, make([]byte, 64<<10)...)
			if len(sink) > 6<<20 {
				sink = sink[:0]
			}
		}
		os.Stdout.WriteString(`{"findings":[],"coverage":{"status":"ran","targets_scanned":1}}`)
	case "hang":
		time.Sleep(30 * time.Second)
	default:
		os.Stderr.WriteString("mock probe: unknown mode " + mode + "\n")
		return 2
	}
	return 0
}

// mockProbe returns a Probe that re-execs this test binary in the requested mock mode.
func mockProbe(t *testing.T, mode string) Probe {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("locate test binary: %v", err)
	}
	t.Setenv(mockProbeModeEnv, mode) // inherited by the child process
	return Probe{View: "mock", Path: self}
}

func TestRunProbeDetailedSurfacesArtifactCoverage(t *testing.T) {
	run := RunProbeDetailed(context.Background(), mockProbe(t, "artifacts"), finding.TargetSpec{Host: "WEB01"}, 30*time.Second)
	if run.Coverage.Status != finding.CovDegraded || run.Coverage.TargetsScanned != 1 {
		t.Fatalf("aggregate coverage: %+v", run.Coverage)
	}
	if len(run.Output.Findings) != 1 {
		t.Fatalf("want 1 finding, got %+v", run.Output.Findings)
	}
	want := []string{finding.ArtifactCovComplete, finding.ArtifactCovDegraded, finding.ArtifactCovFailed}
	if len(run.Output.ArtifactCoverage) != len(want) {
		t.Fatalf("want %d artifacts, got %+v", len(want), run.Output.ArtifactCoverage)
	}
	for i, status := range want {
		got := run.Output.ArtifactCoverage[i]
		if got.Status != status {
			t.Fatalf("artifact %d: want status %s, got %+v", i, status, got)
		}
		if got.Path == "" {
			t.Fatalf("artifact %d has no path: %+v", i, got)
		}
	}
}

// RunProbe must stay source-compatible AND keep its exact two-value shape: findings plus the
// aggregate coverage record, with the artifact channel invisible to it.
func TestRunProbeStillReturnsFindingsAndAggregateCoverageOnly(t *testing.T) {
	fs, cov := RunProbe(context.Background(), mockProbe(t, "artifacts"), finding.TargetSpec{Host: "WEB01"}, 30*time.Second)
	if len(fs) != 1 || fs[0].Tier != finding.TierSuspicious {
		t.Fatalf("want 1 suspicious finding, got %+v", fs)
	}
	if cov.Status != finding.CovDegraded || cov.View != "mock" || cov.TargetsScanned != 1 {
		t.Fatalf("aggregate coverage: %+v", cov)
	}
}

func TestRunProbeDetailedFailsOnInconsistentArtifactCoverage(t *testing.T) {
	for _, mode := range []string{"duplicate-paths", "sha-mismatch"} {
		t.Run(mode, func(t *testing.T) {
			run := RunProbeDetailed(context.Background(), mockProbe(t, mode), finding.TargetSpec{Host: "WEB01"}, 30*time.Second)
			if run.Coverage.Status != finding.CovFailed {
				t.Fatalf("want failed coverage, got %+v", run.Coverage)
			}
			if len(run.Output.Findings) != 0 || len(run.Output.ArtifactCoverage) != 0 {
				t.Fatalf("failed run must surface nothing: %+v", run.Output)
			}
		})
	}
}

func TestProbeObservationRecordsWallCPUAndPeakWorkingSet(t *testing.T) {
	run := RunProbeDetailed(context.Background(), mockProbe(t, "burn"), finding.TargetSpec{Host: "WEB01"}, 30*time.Second)
	if run.Coverage.Status != finding.CovRan {
		t.Fatalf("want ran, got %+v", run.Coverage)
	}
	obs := run.Observation
	t.Logf("observation: wall=%v cpu=%v peak_working_set=%d supported=%v",
		time.Duration(obs.WallNanos), time.Duration(obs.CPUNanos), obs.PeakWorkingSetBytes, obs.PeakWorkingSetSupported)
	if obs.WallNanos <= 0 {
		t.Fatalf("wall nanos not recorded: %+v", obs)
	}
	if obs.CPUNanos < 0 {
		t.Fatalf("cpu nanos negative: %+v", obs)
	}
	wantSupported := runtime.GOOS == "windows" || runtime.GOOS == "linux"
	if obs.PeakWorkingSetSupported != wantSupported {
		t.Fatalf("peak working set support on %s: got %v want %v", runtime.GOOS, obs.PeakWorkingSetSupported, wantSupported)
	}
	if obs.PeakWorkingSetBytes < 0 {
		t.Fatalf("peak working set negative: %+v", obs)
	}
	if !wantSupported && obs.PeakWorkingSetBytes != 0 {
		t.Fatalf("unsupported platform must report zero peak: %+v", obs)
	}
}

// The capture and sampling goroutines must be joined by the time RunProbeDetailed returns: the
// sampler is stopped after Wait and both streams are handed back over channels, so a repeated run
// must not accumulate goroutines.
func TestProbeObservationGoroutinesAreJoinedNotLeaked(t *testing.T) {
	const runs = 8
	p := mockProbe(t, "artifacts")
	spec := finding.TargetSpec{Host: "WEB01"}
	RunProbeDetailed(context.Background(), p, spec, 30*time.Second) // warm up exec's bookkeeping
	settle := func() int {
		deadline := time.Now().Add(3 * time.Second)
		for {
			n := runtime.NumGoroutine()
			if time.Now().After(deadline) {
				return n
			}
			time.Sleep(20 * time.Millisecond)
			if runtime.NumGoroutine() <= n {
				return runtime.NumGoroutine()
			}
		}
	}
	baseline := settle()
	for i := 0; i < runs; i++ {
		if run := RunProbeDetailed(context.Background(), p, spec, 30*time.Second); run.Coverage.Status != finding.CovDegraded {
			t.Fatalf("run %d: %+v", i, run.Coverage)
		}
	}
	// Leaks would scale with runs (one sampler + two capture goroutines each); the small slack only
	// absorbs runtime workers.
	if got := settle(); got > baseline+2 {
		t.Fatalf("goroutines leaked across %d runs: baseline %d, now %d", runs, baseline, got)
	}
}

func TestProbeObservationStdoutOverflowIsFailedCoverage(t *testing.T) {
	restore := probeStdoutCaptureLimit
	probeStdoutCaptureLimit = 1024
	t.Cleanup(func() { probeStdoutCaptureLimit = restore })

	run := RunProbeDetailed(context.Background(), mockProbe(t, "flood-stdout"), finding.TargetSpec{Host: "WEB01"}, 30*time.Second)
	if run.Coverage.Status != finding.CovFailed {
		t.Fatalf("stdout overflow must fail coverage, got %+v", run.Coverage)
	}
	if !strings.Contains(run.Coverage.Reason, "stdout") {
		t.Fatalf("overflow reason must name the stream: %q", run.Coverage.Reason)
	}
	if len(run.Output.Findings) != 0 {
		t.Fatalf("overflowed run must surface no findings: %+v", run.Output)
	}
}

// A probe that exits 0 with a parseable document but floods STDERR has still delivered its scan:
// cmd.Output() never failed a run over stderr volume, and throwing the unit away would lose real
// coverage. The noise degrades the run; it does not discard it.
func TestProbeObservationStderrOverflowDegradesButKeepsTheScan(t *testing.T) {
	restore := probeStderrCaptureLimit
	probeStderrCaptureLimit = 1024
	t.Cleanup(func() { probeStderrCaptureLimit = restore })

	run := RunProbeDetailed(context.Background(), mockProbe(t, "flood-stderr"), finding.TargetSpec{Host: "WEB01"}, 30*time.Second)
	if run.Coverage.Status != finding.CovDegraded {
		t.Fatalf("stderr overflow must degrade, not fail, got %+v", run.Coverage)
	}
	if !strings.Contains(run.Coverage.Reason, "stderr") {
		t.Fatalf("overflow reason must name the stream: %q", run.Coverage.Reason)
	}
	if run.Output.Findings == nil {
		t.Fatalf("stderr overflow discarded a parsed stdout document: %+v", run.Output)
	}
}

// A stderr flood must not upgrade a genuinely failed parse into degraded, and it must not erase the
// reason the parse failed.
func TestProbeObservationStderrOverflowDoesNotSoftenABadDocument(t *testing.T) {
	restoreErr, restoreOut := probeStderrCaptureLimit, probeStdoutCaptureLimit
	probeStderrCaptureLimit = 1024
	t.Cleanup(func() { probeStderrCaptureLimit, probeStdoutCaptureLimit = restoreErr, restoreOut })

	run := RunProbeDetailed(context.Background(), mockProbe(t, "flood-stderr-bad-stdout"), finding.TargetSpec{Host: "WEB01"}, 30*time.Second)
	if run.Coverage.Status != finding.CovFailed {
		t.Fatalf("a bad document must stay failed, got %+v", run.Coverage)
	}
	if !strings.Contains(run.Coverage.Reason, "bad probe output") {
		t.Fatalf("parse failure reason lost: %q", run.Coverage.Reason)
	}
}

// Production sampling gate: RunProbe must not so much as OPEN the child process. The sampler costs an
// OpenProcess plus a poll per interval for the probe's whole lifetime, and RunProbe discards the
// observation, so the production path must not run it at all.
func TestRunProbeDoesNotSampleProcessMemory(t *testing.T) {
	var attaches atomic.Int64
	restore := openProcessMemFn
	openProcessMemFn = func(pid int) (*processMem, error) {
		attaches.Add(1)
		return restore(pid)
	}
	t.Cleanup(func() { openProcessMemFn = restore })

	if _, cov := RunProbe(context.Background(), mockProbe(t, "burn"), finding.TargetSpec{Host: "WEB01"}, 30*time.Second); cov.Status != finding.CovRan {
		t.Fatalf("want ran, got %+v", cov)
	}
	if got := attaches.Load(); got != 0 {
		t.Fatalf("production path attached to the child %d time(s) to sample memory", got)
	}

	// The opt-in path still samples: the gate must be a gate, not a removal.
	run := RunProbeDetailed(context.Background(), mockProbe(t, "burn"), finding.TargetSpec{Host: "WEB01"}, 30*time.Second)
	if run.Coverage.Status != finding.CovRan {
		t.Fatalf("want ran, got %+v", run.Coverage)
	}
	if got := attaches.Load(); got != 1 {
		t.Fatalf("observed path attached %d time(s), want exactly 1", got)
	}
}

// The un-sampled path must report a zero peak rather than a fabricated one, while wall/CPU — free
// from the process state — are still recorded.
func TestProbeProcessWithoutMemoryObservationReportsZeroPeak(t *testing.T) {
	p := mockProbe(t, "burn")
	cmd := exec.Command(p.Path)
	cmd.Stdin = strings.NewReader(`{"host":"WEB01"}`)
	result, obs := runProbeProcess(cmd, probeRunOptions{})
	if result.err != nil {
		t.Fatalf("mock probe failed: %v", result.err)
	}
	if obs.PeakWorkingSetBytes != 0 {
		t.Fatalf("un-sampled run reported a peak: %+v", obs)
	}
	if obs.WallNanos <= 0 {
		t.Fatalf("wall nanos not recorded without sampling: %+v", obs)
	}
}

// stop() must be safe and cheap when sampling was never requested.
func TestMemSamplerStopIsNilSafe(t *testing.T) {
	var sampler *memSampler
	if got := sampler.stop(); got != 0 {
		t.Fatalf("nil sampler must report no peak, got %d", got)
	}
}

// parseVmHWMBytes is the Linux backend's whole parsing surface; it lives untagged so it is testable
// here rather than only on a Linux host.
func TestParseVmHWMBytes(t *testing.T) {
	const status = "Name:\tprobe\nVmPeak:\t   99999 kB\nVmHWM:\t    4096 kB\nVmRSS:\t    2048 kB\n"
	got, err := parseVmHWMBytes([]byte(status))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got != 4096*1024 {
		t.Fatalf("kB scaling wrong: got %d want %d", got, 4096*1024)
	}
	// The last line may carry no trailing newline.
	if got, err := parseVmHWMBytes([]byte("VmRSS:\t1 kB\nVmHWM:\t7 kB")); err != nil || got != 7*1024 {
		t.Fatalf("unterminated last line: got %d err %v", got, err)
	}
	for name, in := range map[string]string{
		"missing":       "Name:\tprobe\nVmRSS:\t 2048 kB\n",
		"empty":         "",
		"no-value":      "VmHWM:\n",
		"not-a-number":  "VmHWM:\t   many kB\n",
		"negative":      "VmHWM:\t     -1 kB\n",
		"not-at-column": "NotVmHWM:\t 4096 kB\n",
	} {
		if got, err := parseVmHWMBytes([]byte(in)); err == nil {
			t.Errorf("%s: want an error, got %d bytes", name, got)
		}
	}
}

// Exit-error semantics must survive the Start/Wait rewrite verbatim: "exit <code>: <stderr>".
func TestProbeObservationPreservesExitErrorSemantics(t *testing.T) {
	run := RunProbeDetailed(context.Background(), mockProbe(t, "exit-with-stderr"), finding.TargetSpec{Host: "WEB01"}, 30*time.Second)
	if run.Coverage.Status != finding.CovFailed {
		t.Fatalf("want failed coverage, got %+v", run.Coverage)
	}
	if run.Coverage.Reason != "exit 3: mock probe: simulated failure" {
		t.Fatalf("exit-error reason changed: %q", run.Coverage.Reason)
	}
	if run.Observation.WallNanos <= 0 {
		t.Fatalf("failed run must still be observed: %+v", run.Observation)
	}
}

// Timeout semantics must survive the rewrite: the deadline branch wins over the exit error, and the
// sampler/capture goroutines must not hold the call open past the kill.
func TestProbeObservationPreservesTimeoutSemantics(t *testing.T) {
	start := time.Now()
	run := RunProbeDetailed(context.Background(), mockProbe(t, "hang"), finding.TargetSpec{Host: "WEB01"}, 500*time.Millisecond)
	if run.Coverage.Status != finding.CovFailed || !strings.HasPrefix(run.Coverage.Reason, "probe timed out") {
		t.Fatalf("timeout semantics changed: %+v", run.Coverage)
	}
	// The reason has to be actionable, not just accurate: a timeout is the one failure an operator
	// fixes by rerunning, so it must name the limit that was hit and the flag that raises it.
	// Scan cost tracks obfuscation rather than file count, so hitting it is not evidence of a hang.
	if !strings.Contains(run.Coverage.Reason, "500ms") || !strings.Contains(run.Coverage.Reason, "--timeout") {
		t.Errorf("timeout reason must name the limit and the remedy, got %q", run.Coverage.Reason)
	}
	if elapsed := time.Since(start); elapsed > 20*time.Second {
		t.Fatalf("timed-out probe held the call open for %v", elapsed)
	}
}

func TestProbeObservationSpawnFailureIsFailedCoverage(t *testing.T) {
	p := Probe{View: "mock", Path: filepath.Join(t.TempDir(), "no-such-probe.exe")}
	run := RunProbeDetailed(context.Background(), p, finding.TargetSpec{Host: "WEB01"}, 5*time.Second)
	if run.Coverage.Status != finding.CovFailed || run.Coverage.Reason == "" {
		t.Fatalf("spawn failure must be covered, not clean: %+v", run.Coverage)
	}
	if len(run.Output.Findings) != 0 {
		t.Fatalf("spawn failure must surface no findings: %+v", run.Output)
	}
}
