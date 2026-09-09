//go:build linux

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"shellsight/internal/finding"
	"shellsight/internal/jvmattach"
	"shellsight/internal/jvmprov"
	"shellsight/internal/jvmtarget"
	"shellsight/internal/jvmtriage"
)

// procRoot is indirected so an integration test can point the probe at a fabricated tree.
var procRoot = "/proc"

// scanResult is one JVM after every stage has run.
type scanResult struct {
	findings []finding.Finding
	// incomplete is non-empty when the agent stopped early (class cap or wall-clock budget). It is
	// COVERAGE: a truncated sweep saw part of the JVM, and reporting it as a full one is how a
	// scanner comes to claim clean about something it never looked at.
	incomplete string
	attached   bool
}

func run(spec finding.TargetSpec) finding.ProbeOutput {
	sweep := jvmtarget.Sweep(procRoot)

	// An explicit PID list narrows the sweep, but discovery still RUNS so the report can
	// distinguish "no JVM on this host" from "the pid you named is not a JVM".
	if len(spec.PIDs) > 0 {
		want := map[int]bool{}
		for _, p := range spec.PIDs {
			want[p] = true
		}
		var keep []jvmtarget.Target
		for _, t := range sweep.Targets {
			if want[t.PID] {
				keep = append(keep, t)
			}
		}
		sweep.Targets = keep
	}

	// No JVM is not a clean scan, it is an inapplicable one.
	if len(sweep.Targets) == 0 {
		return finding.ProbeOutput{
			Findings: []finding.Finding{},
			Coverage: &finding.ProbeCoverage{
				Status: "n/a",
				Reason: fmt.Sprintf("no JVM process found (%d examined, %d unreadable)",
					sweep.Examined, sweep.Unreadable),
			},
		}
	}

	var all []finding.Finding
	var incompletes []string
	attachFailures := 0

	for _, tg := range sweep.Targets {
		// scanOne is a function, not an inlined block, SO THAT ITS defer RUNS PER JVM. A
		// `defer os.RemoveAll(...)` written inline in this loop would hold every handoff directory
		// open until the whole scan finished.
		r := scanOne(tg)
		all = append(all, r.findings...)
		if !r.attached {
			attachFailures++
		}
		if r.incomplete != "" {
			incompletes = append(incompletes, fmt.Sprintf("pid %d: %s", tg.PID, r.incomplete))
		}
	}

	// Status vocabulary is ran|degraded|failed|n/a. There is no "complete".
	status, reason := "ran", ""
	switch {
	case attachFailures == len(sweep.Targets):
		status = "failed"
		reason = "no JVM could be inspected in-process; external evidence only"
	case attachFailures > 0:
		status = "degraded"
		reason = fmt.Sprintf("%d of %d JVM(s) could not be inspected in-process; external evidence only for those",
			attachFailures, len(sweep.Targets))
	}
	// An in-JVM sweep that stopped early is an UNBOUNDED gap: the agent cannot say what was in the
	// classes it never reached. That is what `truncated` records, and it is the reason a clean tier
	// becomes `unknown` rather than being reported as a clean host.
	//
	// Attach failures deliberately do NOT set it. Those are bounded and already counted -- "2 of 3
	// JVM(s) could not be inspected in-process" -- and Stage 1 external triage still ran against
	// those PIDs, so the scan can still say something true about them.
	truncated := truncatedFrom(incompletes)
	if truncated {
		status = "degraded"
		reason = strings.TrimSpace(reason + " in-JVM sweep truncated — " + strings.Join(incompletes, "; "))
	}
	if all == nil {
		all = []finding.Finding{}
	}
	return finding.ProbeOutput{
		Findings: all,
		Coverage: &finding.ProbeCoverage{
			Status: status, Reason: reason, TargetsScanned: len(sweep.Targets),
			Truncated: truncated,
		},
	}
}


// truncatedFrom reports whether the agent's own coverage statements describe an UNBOUNDED gap.
//
// Named rather than inlined so the rule is testable: the difference between "stopped early, and
// cannot say what was missed" and "covered less, and said exactly what" decides whether a clean
// verdict means anything, and it was previously a bare length check with no test on it.
func truncatedFrom(incompletes []string) bool {
	return len(incompletes) > 0
}

// preAttachChannel snapshots the HotSpot attach channel BEFORE this scan touches it.
//
// jvmtriage.Channel only reports PRESENCE, and its whole meaning is "something attached to this JVM
// before this scan". Reading it after jvmattach.Attach inverts that: our own attach starts the
// listener and creates /tmp/.java_pid<nspid>, so the signal fires on every JVM alive. It did --
// a clean, untouched Tomcat 9 came back verdict=suspicious, exit 2, in the published archive, on
// nothing but ShellSight's own footprint. Every clean Java host would have reported the same.
//
// The nspid therefore cannot come from the attach Result: obtaining it that way is what makes the
// observation too late. It is resolved here from /proc/<pid>/status instead. When the kernel does
// not export NStgid the signal is dropped rather than guessed at with the host pid, which would
// name a socket that never exists and silently turn the check off.
func preAttachChannel(base, nsRoot string) []jvmtriage.Signal {
	st, err := jvmattach.ParseStatus(filepath.Join(base, "status"))
	if err != nil || st.NSPID == 0 {
		return nil
	}
	return jvmtriage.Channel(filepath.Join(nsRoot, "tmp"), st.NSPID)
}

// scanOne runs Stages 1-5 against one JVM. Its defers are scoped to this call.
func scanOne(tg jvmtarget.Target) scanResult {
	base := filepath.Join(procRoot, fmt.Sprint(tg.PID))
	nsRoot := filepath.Join(base, "root")
	pt := procTarget{PID: tg.PID, Server: tg.Server, Argv: tg.Argv}

	// Stage 1 ALWAYS runs first and never depends on attach succeeding. When attach is refused it
	// is the only evidence there is.
	var external []jvmtriage.Signal
	external = append(external, jvmtriage.Maps(filepath.Join(base, "maps"))...)
	external = append(external, jvmtriage.FDs(filepath.Join(base, "fd"))...)
	external = append(external, jvmtriage.Cmdline(tg.Argv)...)
	external = append(external, preAttachChannel(base, nsRoot)...)

	handoff, err := os.MkdirTemp(filepath.Join(nsRoot, "tmp"), "ss-handoff-")
	if err != nil {
		external = append(external, jvmtriage.Signal{
			Code:     "attach-refused",
			Detail:   "cannot create a handoff directory in the target's filesystem: " + err.Error(),
			Severity: jvmtriage.SevWeak,
		})
		return scanResult{findings: fuse(pt, nil, external)}
	}
	defer os.RemoveAll(handoff)

	// GIVE THE HANDOFF TO THE TARGET'S USER. MkdirTemp made it 0700 owned by US; the agent runs
	// inside the JVM and writes its output as the JVM'S user. Where those differ the agent cannot
	// write at all, and since ExtractAgent wraps its writes in catch(Exception ignore) the failure
	// is silent -- no DONE marker, and the probe reports a truncated in-JVM sweep, which is the one
	// thing it is not. See handoffOwner and docs/measurements/2026-09-02-nonroot-jvm-handoff/.
	if st, serr := jvmattach.ParseStatus(filepath.Join(base, "status")); serr == nil {
		if uid, gid, needed := handoffOwner(st.EUID, st.EGID, os.Geteuid()); needed {
			if cerr := os.Chown(handoff, uid, gid); cerr != nil {
				// Refuse honestly rather than attach into a handoff the agent cannot write. A
				// degraded "no DONE marker" here would blame the agent for our own permissions.
				external = append(external, jvmtriage.Signal{
					Code: "attach-refused",
					Detail: fmt.Sprintf(
						"the JVM runs as uid %d and this probe as uid %d, and the handoff directory "+
							"could not be given to uid %d (%v); the in-JVM agent would not be able to "+
							"write its output. Re-run with privileges that allow chown.",
						st.EUID, os.Geteuid(), uid, cerr),
					Severity: jvmtriage.SevWeak,
				})
				return scanResult{findings: fuse(pt, nil, external)}
			}
		}
	}

	// The agent opens these paths in ITS namespace, so hand it the target's view.
	targetHandoff := filepath.Join("/tmp", filepath.Base(handoff))
	agentArgs := targetHandoff
	if cfg := stageAgentConfig(handoff); cfg != "" {
		agentArgs = targetHandoff + "|" + filepath.Join(targetHandoff, filepath.Base(cfg))
	}

	res, attachErr := jvmattach.Attach(jvmattach.Options{HostPID: tg.PID, AgentArgs: agentArgs})

	if attachErr != nil || !res.Attached {
		// Never a silent clean. The refusal reason joins the external evidence so the report
		// explains itself.
		external = append(external, jvmtriage.Signal{
			Code:     "attach-refused",
			Detail:   res.Refusal,
			Severity: jvmtriage.SevWeak,
		})
		return scanResult{findings: fuse(pt, nil, external)}
	}

	classes, incomplete := readHandoff(handoff, nsRoot)
	return scanResult{findings: fuse(pt, classes, external), incomplete: incomplete, attached: true}
}

// stageAgentConfig writes the agent's line-oriented config into the handoff directory and returns
// its path on OUR side, or "" if there is nothing to configure.
//
// Written as a file rather than passed inline because the attach args string has a length limit.
// WITHOUT this the agent's retransform watchlist is empty and Agent-type detection is silently off.
func stageAgentConfig(handoff string) string {
	contracts := memContracts()
	if len(contracts) == 0 {
		return ""
	}
	p := filepath.Join(handoff, "agent.cfg")
	// The agent parses sentinel lines followed by one entry each. WATCHLIST first so a future
	// caller can add retransform targets without reordering.
	body := "WATCHLIST\n" + strings.Join(retransformWatchlist, "\n") + "\n" +
		"CONTRACTS\n" + strings.Join(contracts, "\n") + "\n"
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		return "" // the agent falls back to compiled-in defaults, which is a safe degrade
	}
	return p
}

// retransformWatchlist names the known Agent-type hook points. These classes are jar-backed and
// carry no pipeline contract, so nothing else would make them candidates — and the bytecode diff is
// the ONLY signal an Agent-type shell produces.
var retransformWatchlist = []string{
	"org.apache.catalina.core.ApplicationFilterChain",
	"org.apache.catalina.core.StandardWrapperValve",
	"org.apache.catalina.core.StandardContextValve",
	"org.apache.catalina.core.StandardHostValve",
	"javax.servlet.http.HttpServlet",
	"jakarta.servlet.http.HttpServlet",
	"org.springframework.web.servlet.FrameworkServlet",
}

// readHandoff parses every <n>.facts the agent wrote, verifies each claim against the real
// filesystem, and attributes any captured bytes. The second return is the agent's own coverage
// statement: non-empty when it stopped early.
func readHandoff(dir, nsRoot string) ([]classResult, string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, "handoff unreadable: " + err.Error()
	}
	var names []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".facts") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names) // deterministic report order

	var out []classResult
	for _, n := range names {
		claim, err := jvmprov.ParseClaim(filepath.Join(dir, n))
		if err != nil || claim.ClassName == "" {
			continue
		}
		cr := classResult{
			Claim: claim,
			// THE inversion: the agent said what the JVM CLAIMS; Go opens the claimed jar itself,
			// through the target's namespace root. A ClassLoader cannot lie to a process outside it.
			Verification: jvmprov.Verify(claim, nsRoot),
		}
		if b, err := os.ReadFile(filepath.Join(dir, strings.TrimSuffix(n, ".facts")+".class")); err == nil {
			cr.Family, cr.Capabilities = jvmprov.Attribute(b)
		}
		out = append(out, cr)
	}

	// The agent records budget exhaustion as "incomplete: <reason>" in errors.log. Dropping that
	// would convert a truncated sweep into an apparently complete one.
	incomplete := ""
	if b, err := os.ReadFile(filepath.Join(dir, "errors.log")); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if after, ok := strings.CutPrefix(strings.TrimSpace(line), "incomplete: "); ok {
				incomplete = after
				break
			}
		}
	}
	// DONE is written last by the agent. Its absence means the agent died mid-sweep, which is
	// coverage even when nothing wrote an "incomplete:" line.
	if _, err := os.Stat(filepath.Join(dir, "DONE")); err != nil && incomplete == "" {
		incomplete = "the agent did not signal completion (no DONE marker)"
	}
	return out, incomplete
}
