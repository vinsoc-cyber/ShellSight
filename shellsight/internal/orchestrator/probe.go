package orchestrator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
	"unicode/utf8"

	"shellsight/internal/finding"
)

// Probe is one detection view delivered by an external executable.
type Probe struct {
	View string   // e.g. "disk", "java-mem", "dotnet-mem", "mock"
	Path string   // path to the probe executable
	Args []string // fixed args (e.g. mode)
	// NotApplicable, when non-empty, states why this capability cannot exist on this host. Such a
	// probe is never executed; it contributes exactly one `n/a` coverage record carrying this reason.
	//
	// The DECISION is made at registration, from the capability table and the platform alone
	// (research.md R5) — never by trying to run something and interpreting the failure, which cannot
	// distinguish "this host has no .NET runtime" from "the .NET probe is broken". Carrying it on the
	// Probe keeps the requested set a single list, so "one coverage record per requested capability"
	// holds by construction instead of being maintained across two lists that can drift — which is
	// exactly how the capability literals and the registry drifted apart before US1.
	NotApplicable string
	// CannotRun, when non-empty, says why this view will not be attempted. Such a probe is never
	// executed; it contributes exactly one `failed` coverage record carrying this reason.
	//
	// The counterpart to NotApplicable, and the distinction is the whole point. NotApplicable is a
	// view that cannot exist here, or that the build declared it does not carry — expected, benign,
	// and it does NOT set `incomplete`. CannotRun is the package and its own declaration
	// disagreeing, which is never benign, and it does. Answering any of these with n/a turns a
	// broken or edited install into a smaller, quieter, apparently-successful scan.
	//
	// Three disagreements reach it, all found by measurement and each once silent:
	//
	//  1. the build declares a view and the component is ABSENT (registry.go's Optional path simply
	//     dropped it, and nothing downstream had anything to report);
	//  2. the build declares a name the capability table does not hold — a console newer than the
	//     release it stamped, or an edited agent.json;
	//  3. the component is PRESENT and the build does not declare it. That one reported
	//     "not included in this build" while the binary sat beside the scanner: not silence but a
	//     false statement, and the cheapest evasion of the three, since editing one line of
	//     agent.json is easier than deleting a file.
	//
	// It is named for what it does rather than for the first case, because it was called
	// MissingComponent while already serving the second, where nothing is missing.
	//
	// Always decided from the capability table and the filesystem, never by spawning something and
	// reading the failure: an exec error cannot tell "this package ships no jvmprobe" from "jvmprobe
	// is broken", and cannot name a component at all.
	CannotRun string
}

// ProbeRun is everything one probe invocation produced: the probe's full output (findings plus the
// optional per-artifact coverage channel), the aggregate coverage record fusion consumes, and the
// host-side observation of the probe process. Observation and artifact coverage are telemetry — the
// verdict is computed from Output.Findings and Coverage exactly as before.
type ProbeRun struct {
	Output      finding.ProbeOutput
	Coverage    finding.Coverage
	Observation ProbeObservation
}

// probeRunOptions are the internal knobs of one probe invocation. They are unexported on purpose:
// both public entry points are plan-pinned, and nothing here may change what a probe detects.
type probeRunOptions struct {
	// observeMemory turns on peak-process-memory sampling. Default OFF: the production path
	// (RunProbe) must not pay an OpenProcess plus a poll per interval for a number it discards.
	observeMemory bool
}

// RunProbe invokes one probe and returns its findings plus a coverage record.
// Coverage honesty: any error (spawn, timeout, non-zero exit, bad JSON) yields a
// "failed" coverage entry and zero findings — never a silent clean.
//
// This is the production path: it performs no process-memory sampling at all.
func RunProbe(ctx context.Context, p Probe, spec finding.TargetSpec, timeout time.Duration) ([]finding.Finding, finding.Coverage) {
	run := runProbe(ctx, p, spec, timeout, probeRunOptions{})
	return run.Output.Findings, run.Coverage
}

// RunProbeDetailed is RunProbe plus the observation channel: the artifact-coverage detail the probe
// reported, and the host's measurement of the probe process — including peak process memory, which
// is sampled only on this path. Coverage-honesty and timeout/exit semantics are identical to
// RunProbe: the deadline branch is checked first, then the process error, then stdout's bound, then
// the output is parsed (a stderr flood degrades the parsed result rather than discarding it).
func RunProbeDetailed(ctx context.Context, p Probe, spec finding.TargetSpec, timeout time.Duration) ProbeRun {
	return runProbe(ctx, p, spec, timeout, probeRunOptions{observeMemory: true})
}

func runProbe(ctx context.Context, p Probe, spec finding.TargetSpec, timeout time.Duration, opts probeRunOptions) ProbeRun {
	// A component that is not here is reported as the failure it is, not attempted. Checked BEFORE
	// NotApplicable so that a record carrying both — which selectProbes never produces, and which a
	// later caller must not be able to introduce quietly — resolves to the loud answer. An n/a that
	// swallowed a missing component is exactly the confusion this field exists to end.
	if p.CannotRun != "" {
		return ProbeRun{Coverage: finding.Coverage{
			View: p.View, Status: finding.CovFailed, Reason: p.CannotRun,
		}}
	}
	// A capability the platform cannot support is reported, not attempted. Spawning it would report
	// `failed` — indistinguishable from a component that should be here and is not, which is the one
	// distinction US4 exists to preserve.
	if p.NotApplicable != "" {
		return ProbeRun{Coverage: finding.Coverage{
			View: p.View, Status: finding.CovNA, Reason: p.NotApplicable,
		}}
	}

	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	specJSON, err := json.Marshal(spec)
	if err != nil {
		return failedRun(p.View, "marshal target spec: "+err.Error(), ProbeObservation{})
	}

	cmd := exec.CommandContext(cctx, p.Path, p.Args...)
	cmd.Stdin = strings.NewReader(string(specJSON))
	// A timed-out probe gets SIGTERM before SIGKILL so it can remove its decoded mirror. See
	// terminate.go: without this, a scan that exceeded --timeout left decoded webshells in /tmp.
	politeTermination(cmd)
	proc, obs := runProbeProcess(cmd, opts)

	if cctx.Err() == context.DeadlineExceeded {
		// Name the limit and the remedy. Scan cost tracks how obfuscated the content is, not how
		// many files there are (the disk probe measures 0.26 s/file on obfuscated shells vs
		// 0.011 s/file on clean framework code), so a timeout is not evidence of a hang and is
		// likeliest on the hosts worth scanning.
		return failedRun(p.View, fmt.Sprintf("probe timed out after %s — rerun with a longer --timeout", timeout), obs)
	}
	if proc.err != nil {
		reason := proc.err.Error()
		var exitErr *exec.ExitError
		if errors.As(proc.err, &exitErr) && len(proc.stderr) > 0 {
			reason = fmt.Sprintf("exit %d: %s", exitErr.ExitCode(), boundedStderr(proc.stderr))
		}
		return failedRun(p.View, reason, obs)
	}
	// A probe that floods STDOUT is malfunctioning and its view is truncated: report it, do not parse.
	if proc.stdoutOverflow {
		return failedRun(p.View, fmt.Sprintf("probe stdout exceeded the %d-byte capture limit", probeStdoutCaptureLimit), obs)
	}

	out, cov := parseProbeOutputDetailed(p.View, proc.stdout)
	// A flood of WARNINGS is not a failed scan. stdout parsed, so the findings stand; the run is
	// covered as degraded so the noise is still visible to the operator. cmd.Output() never failed a
	// run over stderr volume either, and discarding a successful scan unit over it would lose real
	// coverage.
	if proc.stderrOverflow && cov.Status != finding.CovFailed {
		cov.Status = finding.CovDegraded
		cov.Reason = appendCoverageReason(cov.Reason,
			fmt.Sprintf("probe stderr exceeded the %d-byte capture limit", probeStderrCaptureLimit))
	}
	return ProbeRun{Output: out, Coverage: cov, Observation: obs}
}

// withReason enforces FR-012: every coverage record whose status is not `ran` says why.
//
// A probe is free to emit `degraded` with an empty reason, and one that does leaves the operator
// holding a report that admits a gap and refuses to describe it. The orchestrator cannot invent the
// missing explanation, but it can state the part it knows — which view, and that the probe supplied
// nothing — so the gap is attributable instead of anonymous. `ran` gets nothing: inventing a reason
// there would put prose in every clean report and teach readers to skip the field.
func withReason(cov finding.Coverage) finding.Coverage {
	if cov.Status == finding.CovRan || strings.TrimSpace(cov.Reason) != "" {
		return cov
	}
	cov.Reason = fmt.Sprintf("the %s probe reported %q without a reason", cov.View, cov.Status)
	return cov
}

// appendCoverageReason adds one more reason to a coverage record without dropping what is there.
func appendCoverageReason(existing, addition string) string {
	if existing == "" {
		return addition
	}
	return existing + "; " + addition
}

func failedRun(view, reason string, obs ProbeObservation) ProbeRun {
	return ProbeRun{
		Coverage:    finding.Coverage{View: view, Status: finding.CovFailed, Reason: reason},
		Observation: obs,
	}
}

// boundedStderr renders captured stderr for a coverage reason, keeping the TAIL when it is too long:
// a failing probe's fatal error is at the end of its output, not the start.
func boundedStderr(stderr []byte) string {
	if len(stderr) > maxProbeStderrReasonBytes {
		stderr = stderr[len(stderr)-maxProbeStderrReasonBytes:]
		// Never start the reason mid-rune after cutting the head off.
		for len(stderr) > 0 && !utf8.RuneStart(stderr[0]) {
			stderr = stderr[1:]
		}
	}
	return strings.TrimSpace(string(stderr))
}

// probeProcessResult is the raw outcome of running the probe executable.
type probeProcessResult struct {
	stdout         []byte
	stderr         []byte
	stdoutOverflow bool
	stderrOverflow bool
	err            error
}

// runProbeProcess starts cmd, drains stdout and stderr concurrently under fixed bounds, waits for
// it, and — only when opts.observeMemory is set — samples the process's peak memory while it runs.
// Stream buffers are owned by one goroutine each and published over channels, and the sampler is
// joined (under a bound) before returning, so nothing is shared without synchronization and no
// goroutine survives past its own publish. Wall and CPU time come from the process state and cost
// nothing, so they are always recorded.
func runProbeProcess(cmd *exec.Cmd, opts probeRunOptions) (probeProcessResult, ProbeObservation) {
	var result probeProcessResult
	obs := ProbeObservation{PeakWorkingSetSupported: peakWorkingSetSupported}

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		result.err = err
		return result, obs
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		// Nothing will call Wait, so close the pipe we already own rather than leaking it.
		_ = stdoutPipe.Close()
		result.err = err
		return result, obs
	}

	started := time.Now()
	if err := cmd.Start(); err != nil {
		result.err = err
		obs.WallNanos = time.Since(started).Nanoseconds()
		return result, obs
	}

	stdoutCh := captureBounded(stdoutPipe, probeStdoutCaptureLimit)
	stderrCh := captureBounded(stderrPipe, probeStderrCaptureLimit)
	var sampler *memSampler // nil ⇒ memory observation was not requested; nothing is sampled
	if opts.observeMemory {
		sampler = startMemSampler(cmd.Process.Pid)
	}

	// os/exec contract: both pipes must be fully read before Wait, which closes them.
	stdout := <-stdoutCh
	stderr := <-stderrCh
	result.err = cmd.Wait()
	peak := sampler.stop()

	obs.WallNanos = time.Since(started).Nanoseconds()
	if state := cmd.ProcessState; state != nil {
		obs.CPUNanos = state.UserTime().Nanoseconds() + state.SystemTime().Nanoseconds()
	}
	if peak > 0 {
		obs.PeakWorkingSetBytes = peak
	}
	result.stdout, result.stdoutOverflow = stdout.data, stdout.overflow
	result.stderr, result.stderrOverflow = stderr.data, stderr.overflow
	return result, obs
}

// parseProbeOutput accepts BOTH the new object form ({findings, coverage}) and the legacy bare
// []Finding array. The object form lets a probe self-report honest coverage (degraded/failed +
// reason + real targets_scanned); the array form defaults to ran/len(findings).
func parseProbeOutput(view string, out []byte) ([]finding.Finding, finding.Coverage) {
	output, cov := parseProbeOutputDetailed(view, out)
	return output.Findings, cov
}

// parseProbeOutputDetailed additionally carries the optional per-artifact coverage channel. The
// aggregate coverage record it derives is computed from findings + the probe's coverage block only,
// exactly as before — artifact coverage never contributes to it.
func parseProbeOutputDetailed(view string, out []byte) (finding.ProbeOutput, finding.Coverage) {
	trimmed := bytes.TrimSpace(out)
	if len(trimmed) > 0 && trimmed[0] == '{' {
		var po finding.ProbeOutput
		if err := json.Unmarshal(trimmed, &po); err != nil {
			return finding.ProbeOutput{}, finding.Coverage{View: view, Status: finding.CovFailed, Reason: "bad probe output: " + err.Error()}
		}
		if reason := validateArtifactCoverage(po); reason != "" {
			return finding.ProbeOutput{}, finding.Coverage{View: view, Status: finding.CovFailed, Reason: reason}
		}
		cov := finding.Coverage{View: view, Status: finding.CovRan, TargetsScanned: len(po.Findings)}
		if po.Coverage != nil {
			if po.Coverage.Status != "" {
				cov.Status = po.Coverage.Status
			}
			cov.Reason = po.Coverage.Reason
			cov.TargetsScanned = po.Coverage.TargetsScanned
			cov.Skipped = po.Coverage.Skipped
			cov.Discovery = po.Coverage.Discovery
			cov.Scratch = po.Coverage.Scratch
			cov.Truncated = po.Coverage.Truncated
		}
		return po, withReason(cov)
	}
	var findings []finding.Finding
	if err := json.Unmarshal(trimmed, &findings); err != nil {
		return finding.ProbeOutput{}, finding.Coverage{View: view, Status: finding.CovFailed, Reason: "bad probe output: " + err.Error()}
	}
	return finding.ProbeOutput{Findings: findings},
		finding.Coverage{View: view, Status: finding.CovRan, TargetsScanned: len(findings)}
}

// validateArtifactCoverage returns a bounded reason when the artifact channel contradicts itself or
// the findings it accompanies: an entry without a path, the same artifact described twice, or a
// digest that disagrees with the finding reported for the same path. An inconsistent channel means
// the probe's own bookkeeping is wrong, so the run is covered as failed rather than trusted.
// Reasons carry only an index — never a probe-supplied path — so nothing attacker-controlled leaks.
func validateArtifactCoverage(po finding.ProbeOutput) string {
	if len(po.ArtifactCoverage) == 0 {
		return ""
	}
	findingSHA := make(map[string]string, len(po.Findings))
	for _, f := range po.Findings {
		if f.Target.File != nil && f.Target.File.Path != "" && f.Target.File.SHA256 != "" {
			findingSHA[f.Target.File.Path] = f.Target.File.SHA256
		}
	}
	seen := make(map[string]struct{}, len(po.ArtifactCoverage))
	for i, entry := range po.ArtifactCoverage {
		if entry.Path == "" {
			return fmt.Sprintf("artifact coverage entry %d has no path", i)
		}
		if _, duplicate := seen[entry.Path]; duplicate {
			return fmt.Sprintf("artifact coverage entry %d repeats an earlier path", i)
		}
		seen[entry.Path] = struct{}{}
		if sha, ok := findingSHA[entry.Path]; ok && entry.SHA256 != "" && sha != entry.SHA256 {
			return fmt.Sprintf("artifact coverage entry %d sha256 disagrees with the finding for the same path", i)
		}
	}
	return ""
}
