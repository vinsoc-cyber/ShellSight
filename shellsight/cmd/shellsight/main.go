// shellsight — IR/SOC webshell detector (core skeleton; Plan 2).
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"shellsight/cmd/rules"
	"shellsight/internal/discover"
	"shellsight/internal/finding"
	"shellsight/internal/lowprio"
	"shellsight/internal/orchestrator"
	"shellsight/internal/output"
)

const Version = "1.0.0"

// defaultTimeoutSec is the per-probe budget. 120s was far too low to be safe: the disk probe needs
// 4m16s on 989 obfuscated shells, and cost scales with how obfuscated the content is rather than
// with file count (0.26 s/file obfuscated vs 0.011 s/file on clean framework code). So the old
// default expired soonest on exactly the hosts worth scanning, and a timeout renders the run
// incomplete. 30 minutes suits a real webroot; the memory views finish in seconds regardless.
const defaultTimeoutSec = 1800

// artifactsDir is where the memory probes write recovered and decompiled artifacts. It is NOT the
// run folder: RUNBOOK.md used to claim otherwise, and nothing copies them across, so an analyst
// looking in --out for decompiled memshell source would not find it. Reported in report.json so the
// evidence is at least locatable.
func artifactsDir() string { return filepath.Join(exeDir(), "artifacts") }

// exeDir is the directory of the running shellsight binary (where bundled assets live).
//
// os.Executable reads /proc/self/exe on Linux, and a chroot or a container built from scratch has no
// /proc. Measured inside an Alpine chroot: os.Executable failed, this returned ".", and
// filepath.Join(".", "diskprobe") collapses to the bare name "diskprobe" -- which exec.Command
// resolves through PATH, not relative to the working directory. The scan failed with
// `exec: "diskprobe": executable file not found in $PATH` while the probe sat beside the binary.
//
// So argv[0] is tried next. It is how the process was invoked, so when it carries a path -- which it
// does for any absolute or relative invocation, including the one an unpacked release uses -- it names
// the install directory without needing /proc at all.
func exeDir() string {
	if exe, err := os.Executable(); err == nil {
		return filepath.Dir(exe)
	}
	if argv0 := os.Args[0]; strings.ContainsAny(argv0, `/\`) {
		if abs, err := filepath.Abs(argv0); err == nil {
			return filepath.Dir(abs)
		}
		return filepath.Dir(argv0)
	}
	// Invoked by bare name through PATH, with no /proc to ask. The working directory is the only
	// remaining guess, and it is returned as an absolute path so a joined probe path keeps a separator
	// and is not searched for on PATH -- which is the specific failure this function exists to avoid.
	if wd, err := os.Getwd(); err == nil {
		return wd
	}
	return "."
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: shellsight <scan|rules|components|version> [flags]")
		os.Exit(1)
	}
	switch os.Args[1] {
	case "version":
		fmt.Println("shellsight", Version)
		os.Exit(0)
	case "rules":
		os.Exit(rules.Run(os.Args[2:]))
	case "scan":
		os.Exit(runScan(os.Args[2:]))
	case "components":
		// Emitted at PACKAGE time, one document per target, because a generator cannot ask the
		// binary: the console runs on one platform and builds agents for three, and it cannot
		// execute a linux-arm64 binary to interrogate it.
		os.Exit(runComponentsCmd(os.Args[2:]))
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", os.Args[1])
		os.Exit(1)
	}
}

func runScan(args []string) int {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	views := fs.String("views", defaultViews, "comma-separated views to run")
	outDir := fs.String("out", ".", "output directory for the run folder")
	asJSON := fs.Bool("json", false, "print report.json path as the only stdout line")
	paths := fs.String("path", "", "comma-separated webroot paths to scan (disk view); empty = auto-discover")
	pids := fs.String("pid", "", "comma-separated PIDs to analyze (dotnet-mem); empty = auto-discover w3wp.exe")
	discoveryRefuse := fs.String("discovery-refuse", "", discover.RefusalHelp())
	offlineRoot := fs.String("root", "",
		"scan a filesystem mounted here -- an image, a snapshot -- rather than this host: discovery "+
			"reads that filesystem's own configuration instead of this one's")
	lowPriority := fs.Bool("low-priority", false,
		"lower this scan's CPU and I/O priority so sweeping a live production web server does not "+
			"degrade it; the probes inherit it")
	dump := fs.String("dump", "", "path to a process dump to analyze (dotnet-mem)")
	timeoutSec := fs.Int("timeout", defaultTimeoutSec, "per-probe timeout in seconds")
	rulesDir := fs.String("rules-dir", "", "rule tree to scan with (default: kb/rules beside the binary)")
	rulesBlob := fs.String("rules-blob", "",
		"compiled rule set (.yarc) to scan with, in place of a rule tree")
	configPath := fs.String("config", "",
		"path to an agent.json build configuration (default: beside the binary, if present)")
	_ = fs.Parse(args)

	// The build's own declaration of what it carries and what it prefers. Absent is normal -- a
	// scanner run by hand has none and falls back to built-in defaults -- but a config that exists
	// and cannot be read is fatal: falling back would scan with a default view set and whatever
	// rules happen to sit beside the binary, then report success. That is a scan nobody configured,
	// presented as the one they asked for.
	cfg, cfgPath, err := loadAgentConfig(*configPath, exeDir())
	if err != nil {
		fmt.Fprintf(os.Stderr, "shellsight: %v\n", err)
		return 1
	}
	// Explicit CLI options > agent.json > built-in defaults (C3). The ladder lives in config.go as
	// pure functions so it is assertable without building a scan; here it is only applied.
	//
	// Every refusal below exits 1, which is what runScan already returns for a usage error. Never a
	// verdict code: 0 and 2-5 are scan RESULTS, and an automation harness reading one of those from
	// a run that never started would be reading a verdict about a host nothing looked at.
	viewSet := resolveViews(*views, flagWasSet(fs, "views"), cfg, defaultViews)
	scanScope := resolveScanScope(*paths, flagWasSet(fs, "path"), cfg)
	blob, err := resolveRulesBlob(*rulesBlob, *rulesDir, cfg, agentDirFor(cfgPath))
	if err != nil {
		fmt.Fprintf(os.Stderr, "shellsight: %v\n", err)
		return 1
	}
	useJSON, err := resolveJSONOutput(*asJSON, flagWasSet(fs, "json"), cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "shellsight: %v\n", err)
		return 1
	}
	useLowPriority, err := resolveLowPriority(*lowPriority, flagWasSet(fs, "low-priority"), cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "shellsight: %v\n", err)
		return 1
	}

	reg := probeRegistry(*rulesDir, blob)
	// carriedViews, not viewSet: what was REQUESTED and what the build CARRIES are different
	// questions. An explicit -views overrules the first and cannot touch the second -- naming a view
	// on the command line does not put a component into a package that never shipped one.
	probes, runnable, unknown := selectProbes(reg, strings.Split(viewSet, ","), runtime.GOOS,
		carriedViews(cfg), packageCarriesIn(exeDir(), runtime.GOOS))
	for _, v := range unknown {
		fmt.Fprintf(os.Stderr, "warning: unknown view %q (skipped)\n", v)
	}
	// Runnable, not merely requested. A run whose every capability is not-applicable examined
	// nothing, and n/a does not set `incomplete` — so continuing would emit a clean verdict and
	// exit 0 for a scan that never looked at anything. That is the one output this tool must never
	// produce, so it stays a usage error.
	if runnable == 0 {
		fmt.Fprintln(os.Stderr, "no runnable views selected")
		return 1
	}

	// Run the x86 companion alongside dotnet-mem so 32-bit app pools aren't silently skipped: the x64
	// probe analyzes 64-bit workers and defers 32-bit ones to dotnet-mem-x86 (and vice-versa).
	hasDotnetMem, hasX86 := false, false
	for _, p := range probes {
		if p.NotApplicable != "" || p.CannotRun != "" {
			continue // a capability that will not be executed here has no companion to pair with
		}
		switch p.View {
		case "dotnet-mem":
			hasDotnetMem = true
		case "dotnet-mem-x86":
			hasX86 = true
		}
	}
	if hasDotnetMem && !hasX86 {
		if p, ok := reg["dotnet-mem-x86"]; ok {
			probes = append(probes, p)
		}
	}

	// FR-042. Applied BEFORE the probes are launched, because on Linux both niceness and the I/O
	// priority are inherited across fork and exec (ioprio_set(2)) -- and the probes are where the
	// actual file walking happens, so throttling only the core would throttle nothing that matters.
	//
	// Never fatal. A kernel or container may refuse the I/O class, and a scan that refuses to run
	// because it could not be polite is useless. But it must not claim a throttle it did not get:
	// an operator would then sweep a live host at full speed believing otherwise.
	if useLowPriority {
		if r := lowprio.Reduce(); r.Applied() {
			fmt.Fprintf(os.Stderr, "low priority: %s\n", r)
		} else {
			fmt.Fprintf(os.Stderr, "warning: --low-priority had no effect (%s); the scan will run at "+
				"normal priority\n", r)
		}
	}

	// FR-039. Forwarded rather than acted on here: the disk probe is what discovers, and the core
	// must not grow a second opinion about which mechanisms ran.
	// FR-034's mounted-image case. Forwarded to the probe that does the discovering, like the
	// refusal list, so the core keeps no second opinion about what was scanned.
	if *offlineRoot != "" {
		for i := range probes {
			if probes[i].View == "disk" && probes[i].NotApplicable == "" {
				probes[i].Args = append(probes[i].Args, "--root", *offlineRoot)
			}
		}
	}
	if *discoveryRefuse != "" {
		_, unknown := discover.ParseRefusal(*discoveryRefuse)
		for _, u := range unknown {
			fmt.Fprintf(os.Stderr, "warning: unknown discovery mechanism %q (not refused)\n", u)
		}
		for i := range probes {
			if probes[i].View == "disk" && probes[i].NotApplicable == "" {
				probes[i].Args = append(probes[i].Args, "--discovery-refuse", *discoveryRefuse)
			}
		}
	}

	runID := time.Now().UTC().Format("20060102_150405")
	host, _ := os.Hostname()
	// Spec 007 US3: the run folder exists before the probes run, so the disk probe can fall back to
	// <runDir>/scratch for its temporary workspace on a read-only root filesystem (scratch.go).
	preparedRun, scratch, err := prepareRunDir(*outDir, host, runID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "write output: %v\n", err)
		return 1
	}
	probes = withScratch(probes, preparedRun)
	spec := finding.TargetSpec{Host: host}
	// scanScope, not *paths: -path wins, else the build's baked scope, else empty for
	// auto-discover. Reading the flag directly here would make the baked value inert -- the defect
	// shape this repo has now hit twice, where a resolver existed and the use site ignored it.
	for _, p := range strings.Split(scanScope, ",") {
		if p = strings.TrimSpace(p); p != "" {
			spec.Webroots = append(spec.Webroots, p)
		}
	}
	for _, p := range strings.Split(*pids, ",") {
		if p = strings.TrimSpace(p); p != "" {
			if n, err := strconv.Atoi(p); err == nil {
				spec.PIDs = append(spec.PIDs, n)
			} else {
				fmt.Fprintf(os.Stderr, "warning: bad --pid %q (skipped)\n", p)
			}
		}
	}
	spec.DumpPath = strings.TrimSpace(*dump)
	rep := orchestrator.Scan(context.Background(), probes, spec, Version, runID, time.Duration(*timeoutSec)*time.Second)
	// The probe removed its own files; remove the directory so the run folder holds only the report.
	cleanupScratch(scratch)
	if u, err := user.Current(); err == nil {
		rep.Scan.Operator = u.Username
	}
	rep.Scan.Invocation = strings.Join(os.Args, " ")
	// The scope the disk view was actually given, which Invocation cannot report: a scope baked into
	// agent.json never appears on the command line, and one that came from discovery appears
	// nowhere. Recorded from the spec rather than re-derived, so it is what the probes were handed.
	rep.Scan.Webroots = spec.Webroots
	// Only when the directory exists: a disk-only scan produces none, and pointing at an absent
	// path would be noise.
	if ad := artifactsDir(); ad != "" {
		if _, err := os.Stat(ad); err == nil {
			rep.ArtifactsDir = ad
		}
	}
	runDir, err := output.Write(rep, *outDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "write output: %v\n", err)
		return 1
	}

	if useJSON {
		fmt.Println(filepath.Join(runDir, "report.json"))
	} else {
		fmt.Printf("verdict=%s incomplete=%v -> %s\n", rep.Verdict.Tier, rep.Verdict.Incomplete, runDir)
	}
	return exitCode(rep.Verdict)
}

// exitCode: 0 clean / 2 suspicious / 3 likely / 4 confirmed; 5 = unknown (a view failed or timed
// out and nothing was found — NOT clean). 5 must never be treated as an all-clear by a caller.
func exitCode(v finding.Verdict) int {
	switch v.Tier {
	case finding.TierConfirmed:
		return 4
	case finding.TierLikely:
		return 3
	case finding.TierSuspicious:
		return 2
	case finding.TierUnknown:
		return 5
	default:
		if v.Incomplete {
			return 5
		}
		return 0
	}
}
