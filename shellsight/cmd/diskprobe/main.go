// diskprobe — the disk webshell view. Reads a TargetSpec on stdin, scans the
// webroots with the bundled `yr` engine + our rules, emits []Finding on stdout.
//
// Coverage honesty (project invariant, spec §7): the probe must never report a
// silent clean. If it cannot actually perform the scan it was asked for — bad
// spec, unusable rules, an explicitly-requested root that does not exist, or
// every resolved root failing to scan — it exits non-zero so the core marks the
// view failed rather than clean. Partial root and Java-analysis failures retain
// findings and report degraded coverage with bounded reasons.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"shellsight/internal/discover"
	"shellsight/internal/finding"
)

// exit codes: 0 = scan completed (findings may be empty); 2 = coverage failure
// (could not scan what was asked); 1 = internal error (e.g. marshal).
const (
	exitOK       = 0
	exitInternal = 1
	exitCoverage = 2
)

func main() {
	// SIGTERM as well as SIGINT: the core sends SIGTERM to a probe that exceeds --timeout so that
	// the deobfuscation mirror is removed before SIGKILL follows. Without SIGTERM here the grace
	// period the core grants would be spent ignoring the signal, and the mirror would survive.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(runDiskProbe(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func runDiskProbe(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("diskprobe", flag.ContinueOnError)
	flags.SetOutput(stderr)
	yr := flags.String("yr", "", "path to the yara-x `yr` binary")
	rules := flags.String("rules", "", "path to the YARA rules directory")
	rulesBlob := flags.String("rules-blob", "",
		"path to a compiled rule set (.yarc); mutually exclusive with -rules")
	// FR-039. Discovery reads config files and (later) execs server binaries an intruder on a
	// compromised host may have replaced, so an operator must be able to refuse it. Refusing it
	// without naming a path is an error, not an empty scan -- see webrootGate.
	discovery := flags.Bool("discover", true,
		"locate webroots from server configuration and conventional locations when none are supplied")
	refuseSpec := flags.String("discovery-refuse", "", discover.RefusalHelp())
	offlineRoot := flags.String("root", "",
		"discover webroots inside a filesystem mounted here -- an image, a snapshot -- rather than on "+
			"this host; configuration is read in that filesystem's namespace")
	deobf := flags.Bool("deobf", true, "statically unwrap obfuscated layers (base64/gzinflate/str_rot13/hex/eval-arg) and scan them too")
	// Spec 007 US3: the run directory's scratch subdirectory, used for the scan list and the decoded
	// mirror when the default temporary location is not writable (a read-only container root).
	flags.StringVar(&scratchDir, "scratch", "",
		"directory to use for temporary files when the default temporary location is not writable")
	javaPolicy := flags.String("java-policy", "", "path to a bounded Java analysis policy")
	// Observation only, for the measurement build: report how completely each Java artifact was
	// analyzed. Off by default, and when off the emitted JSON is byte-identical to the shipped
	// schema. It changes no rule, score, tier, source, sink or transform either way.
	artifactCoverage := flags.Bool("artifact-coverage", false, "additionally report per-artifact Java analysis coverage (measurement only)")
	if err := flags.Parse(args); err != nil {
		return exitCoverage
	}
	// Explicit rather than one polymorphic flag that guesses from the path. A build carries exactly
	// one of these, and silently preferring one when both are given is how an agent ends up
	// scanning with rules nobody chose.
	if *rules != "" && *rulesBlob != "" {
		fmt.Fprintln(stderr, "diskprobe: -rules and -rules-blob are mutually exclusive")
		return exitCoverage
	}
	if *rules == "" && *rulesBlob == "" {
		fmt.Fprintln(stderr, "diskprobe: one of -rules or -rules-blob is required")
		return exitCoverage
	}
	rulesPath, compiledRules := *rules, false
	if *rulesBlob != "" {
		rulesPath, compiledRules = *rulesBlob, true
	}
	// One scan per process in production; the tests drive several through this function, and the
	// fallback record must not leak from one scan into the next scan's report.
	scratchUsed = ""

	javaOpts, err := loadJavaOptions(*javaPolicy)
	if err != nil {
		fmt.Fprintln(stderr, "diskprobe: Java policy unusable:", boundedMessage(err.Error(), 512))
		return exitCoverage
	}

	specBytes, _ := io.ReadAll(stdin)
	var spec finding.TargetSpec
	if len(specBytes) > 0 {
		if err := json.Unmarshal(specBytes, &spec); err != nil {
			// A spec we can't parse means we don't know the requested scope.
			// Fail loudly instead of silently falling through to auto-discovery
			// of the wrong (or empty) target set.
			fmt.Fprintln(stderr, "diskprobe: bad TargetSpec on stdin:", err)
			return exitCoverage
		}
	}

	// Detection capability must exist: a missing or empty rules path means we
	// can detect nothing, which is a failure — not a clean result.
	if err := rulesUsable(rulesPath); err != nil {
		fmt.Fprintln(stderr, "diskprobe: rules unusable:", err)
		return exitCoverage
	}

	refuse, unknownMechs := discover.ParseRefusal(*refuseSpec)
	for _, u := range unknownMechs {
		// A typo must not read as a successful refusal: an operator who believes they blocked an exec
		// on an incident host, and did not, has been told something false.
		fmt.Fprintf(stderr, "diskprobe: warning: unknown discovery mechanism %q (not refused)\n", u)
	}
	discovered := resolveDiscovery(spec.Webroots, discover.Options{
		Disabled: !*discovery, Refuse: refuse, Root: *offlineRoot,
	})
	roots := discovered.Paths()
	// Nothing to scan is a coverage failure, whether the operator named roots that are gone,
	// discovery came up empty on an unfamiliar host, or every candidate it proposed was refused.
	// See webrootGate.
	if msg := webrootGate(len(spec.Webroots), discovered); msg != "" {
		fmt.Fprintln(stderr, "diskprobe:", msg)
		return exitCoverage
	}

	var findings []finding.Finding
	var scannedOK int
	var failedRoots []string
	var javaDiagnostics []javaDiagnosticSummary
	var javaScan javaArtifactScan
	var skips scanSkips
	if *deobf {
		result := scanWithDeobfDetailed(ctx, *yr, rulesPath, compiledRules, roots, spec.Host, javaOpts, *artifactCoverage)
		findings, scannedOK, failedRoots, javaScan = result.Findings, result.ScannedOK, result.FailedRoots, result.Java
		skips = result.Skips
		javaDiagnostics = summarizeJavaDiagnostics(javaScan.Diagnostics)
	} else {
		var enumerated []rootPaths
		enumerated, skips = enumerateScannable(roots)
		findings, scannedOK, failedRoots = scanWebroots(ctx, *yr, rulesPath, compiledRules, enumerated, spec.Host)
		// Its own cache: this fallback branch runs each pass independently, and scanWebroots keeps
		// one internally. Sharing would save a re-read of the rare unknown-extension file, not
		// change any answer.
		javaScan = javadiskScan(ctx, roots, spec.Host, javaOpts, *artifactCoverage, newSignCache())
		findings = append(findings, javaScan.Findings...)
		javaDiagnostics = summarizeJavaDiagnostics(javaScan.Diagnostics)
	}

	// Had roots to scan but every one failed → failed view (no findings lost).
	if len(roots) > 0 && scannedOK == 0 {
		fmt.Fprintf(stderr, "diskprobe: all %d webroot(s) failed to scan: %s\n", len(roots),
			boundedMessage(strings.Join(failedRoots, "; "), 1500))
		return exitCoverage
	}
	for _, fr := range failedRoots {
		fmt.Fprintf(stderr, "diskprobe: warning: webroot not fully scanned: %s\n", fr)
	}

	if findings == nil {
		findings = []finding.Finding{}
	}
	// Report honest coverage: targets_scanned is the count of webroots actually scanned (NOT
	// len(findings)); degrade if some requested roots failed while others succeeded.
	cov := &finding.ProbeCoverage{Status: finding.CovRan, TargetsScanned: scannedOK}
	// Where the temporary workspace went, but only when the fallback was taken: an ordinary run's
	// coverage block must stay byte-identical (spec 007 FR-012).
	cov.Scratch = scratchUsed
	// How the roots were located travels with the result (FR-036). Always attached, even for an
	// explicit target set, so a reader can tell "the operator named this" from "we guessed this"
	// without inferring it from a missing field -- the same reason ScanSkips is always present.
	cov.Discovery = discoveryReport(discovered)
	// Always attached, including all-zero: "nothing was skipped" has to be an assertion the report
	// makes, not something a reader infers from a missing field (data-model E3).
	cov.Skipped = &finding.ScanSkips{
		NonRegular:         skips.NonRegular(),
		Unreadable:         skips.Unreadable(),
		OversizeSkipped:    skips.Oversize(),
		NoLanguageDetector: skips.NoLangDetector(),
	}
	if len(failedRoots) > 0 {
		cov.Status = finding.CovDegraded
		cov.Reason = fmt.Sprintf("%d of %d webroot(s) failed to scan: %s", len(failedRoots), len(roots),
			boundedMessage(strings.Join(failedRoots, ", "), 1500))
	} else if cov.Skipped.Total() > 0 {
		// Degraded, never failed: the remaining files WERE examined (FR-014), so this discloses a
		// gap rather than invalidating the scan.
		cov.Status = finding.CovDegraded
		cov.Reason = skipReason(*cov.Skipped)
	}
	applyJavaDiagnostics(cov, javaDiagnostics)
	// Per-artifact coverage is emitted ONLY when asked for. A root-level scan failure has already
	// returned exitCoverage above, so this channel can never soften an aggregate coverage failure.
	var artifacts []finding.ArtifactCoverage
	if *artifactCoverage {
		artifacts = javaArtifactCoverage(javaScan)
	}
	out, err := marshalProbeOutput(findings, cov, artifacts)
	if err != nil {
		fmt.Fprintln(stderr, "diskprobe: marshal:", err)
		return exitInternal
	}
	if _, err := stdout.Write(out); err != nil {
		fmt.Fprintln(stderr, "diskprobe: write output:", err)
		return exitInternal
	}
	return exitOK
}

// marshalProbeOutput assembles the probe's stdout document. artifactCoverage is nil unless the
// operator asked for it; `omitempty` on that field then keeps the bytes identical to the schema
// diskprobe has always emitted.
func marshalProbeOutput(findings []finding.Finding, coverage *finding.ProbeCoverage, artifactCoverage []finding.ArtifactCoverage) ([]byte, error) {
	return json.Marshal(finding.ProbeOutput{Findings: findings, Coverage: coverage, ArtifactCoverage: artifactCoverage})
}

func boundedMessage(message string, limit int) string {
	message = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return '?'
		}
		return r
	}, message)
	if len(message) > limit {
		return message[:limit]
	}
	return message
}

// skipReason renders the coverage reason so that the total it states is accounted for by the terms
// it enumerates.
//
// It did not, once. When the fourth counter was added the format string kept naming three, so a run
// over 28,088 unknown-extension files reported "23367 entr(ies) not examined: 0 non-regular, 0
// unreadable, 0 oversize" -- a total contradicted by its own breakdown, on the one field whose entire
// job is to tell a responder honestly what was not looked at.
//
// The last term is spelled out rather than abbreviated because it is the one that needs qualifying:
// those files WERE scanned by the unscoped rule engine, and only the language-specific detectors
// passed them by.
func skipReason(s finding.ScanSkips) string {
	return fmt.Sprintf(
		"%d entr(ies) not examined: %d non-regular, %d unreadable, %d oversize, "+
			"%d examined by no language-specific detector (still scanned by the unscoped rules)",
		s.Total(), s.NonRegular, s.Unreadable, s.OversizeSkipped, s.NoLanguageDetector)
}

// rulesUsable reports whether the rules path can actually drive a scan: it must
// exist, and if it is a directory it must contain at least one .yar/.yara file.
// An empty rules dir compiles to zero rules, so every scan would be a false
// clean — that is a coverage failure, not a clean result.
func rulesUsable(path string) error {
	if path == "" {
		return fmt.Errorf("no rules path provided (--rules)")
	}
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return nil // a single rules file
	}
	var count int
	walkErr := filepath.WalkDir(path, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		switch strings.ToLower(filepath.Ext(p)) {
		case ".yar", ".yara":
			count++
		}
		return nil
	})
	if walkErr != nil {
		return walkErr
	}
	if count == 0 {
		return fmt.Errorf("rules dir %q contains no .yar/.yara files", path)
	}
	return nil
}

// scanWebroots runs yr over each webroot and maps matches to Findings. It returns
// the findings, the count of roots scanned successfully, and the roots that
// failed (so the caller can decide whether coverage is honest).
func scanWebroots(ctx context.Context, yrPath, rulesPath string, compiled bool, webroots []rootPaths, host string) (findings []finding.Finding, scannedOK int, failedRoots []string) {
	// One cache per scan. A sign is consulted only for a file that ALREADY produced a match from a
	// language-declaring rule and whose name claims nothing -- rare -- but several rules can match
	// the same file, and each would otherwise re-read it.
	signs := newSignCache()
	for _, rp := range webroots {
		root := rp.Root
		// An empty list is a root with nothing readable under it -- every entry was a device, a
		// FIFO, or a link out of scope. That is a scanned root that found nothing, not a failure,
		// so runYaraX returns empty output for it rather than invoking the engine.
		ndjson, err := runYaraX(ctx, yrPath, rulesPath, compiled, rp.Paths)
		if err != nil {
			fmt.Fprintf(os.Stderr, "diskprobe: yr on %s: %v\n", root, err)
			// The reason travels with the root: when every root fails, the summary line is all the
			// core relays, and "temporary workspace unavailable: … set TMPDIR …" is the line a
			// responder in a read-only container needs to see (spec 007 US3).
			failedRoots = append(failedRoots, fmt.Sprintf("%s (%v)", root, err))
			continue
		}
		scannedOK++
		for _, fm := range parseNDJSON(ndjson) {
			findings = append(findings, findingsFromFileMatch(fm, host, signs)...)
		}
	}
	return findings, scannedOK, failedRoots
}

func findingsFromFileMatch(fm yaraxFileMatch, host string, signs *signCache) []finding.Finding {
	sha := sha256File(fm.Path)
	out := make([]finding.Finding, 0, len(fm.Rules))
	for _, r := range fm.Rules {
		basis := ruleAdmission(fm.Path, r, modeWidened, signs)
		if basis == admitRefused {
			continue
		}
		f := findingFromRule(fm.Path, sha, r, host)
		if basis == admitUnknownLanguage {
			// Triage information, never a confidence signal: the score and tier are exactly what
			// the same rule would give this file under a name that agreed. What it tells an analyst
			// is that the name on disk disagrees with the content, which on a compromised host is
			// itself a lead. Carried in Context because Detection.Evidence is hashed into the
			// fingerprint the runbook presents as the SIEM suppression key.
			if f.Context == nil {
				f.Context = map[string]string{}
			}
			f.Context["rule_scope"] = string(admitUnknownLanguage)
		}
		out = append(out, f)
	}
	return out
}

func sha256File(path string) string {
	file, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return ""
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func shortID(sha, rule string) string {
	if len(sha) >= 12 {
		return sha[:12] + "-" + rule
	}
	return rule
}

// findingFromRule maps a single YARA rule match to a Finding, reading score and family from YARA meta.
func findingFromRule(filePath, sha string, r yaraxRuleMatch, host string) finding.Finding {
	score := 70
	tier := finding.TierLikely
	// The rule name IS the identity, unconditionally. A `reference` meta is provenance — a URL or
	// free text — and it used to overwrite this. That destroyed identity for 5,193 of the 5,859
	// shipped rules (88.6%) and collapsed 2,773 of them onto 215 shared strings, 626 onto one
	// SEKOIA URL alone. Two costs: the report named a URL (or "Internal Research") instead of a
	// rule an analyst could look up, tune or suppress; and dedupByOriginRule keys on this ref, so
	// independent rules matching the same file merged into one finding and the corroboration was
	// deleted before anything could score it. Provenance now rides in Context beside rule_author.
	knowledgeRef := "kb:yara/" + r.Identifier

	if r.Meta != nil {
		if s, ok := r.Meta["score"]; ok {
			if n, err := strconv.Atoi(s); err == nil {
				score = n
				tier = scoreToTier(score)
			}
		}
	}

	// Name the patterns that actually fired. "YARA rule DodgyPhp matched" restates the rule name and
	// leaves an analyst to grep kb/rules/ and diff the rule's strings against the file by hand;
	// "matched: $eval_var" answers the question outright. Identifiers only — the offsets and matched
	// bytes go to Context, because Evidence is hashed into the fingerprint the RUNBOOK presents as
	// the SIEM suppression key, and it must not move when a benign file shifts by a byte.
	//
	// NOTE: this is a one-time fingerprint change for YARA findings. Suppressions written against
	// pre-change fingerprints stop matching and belong in release notes, exactly as the C1
	// rule-identity restore did.
	evidence := "YARA rule " + r.Identifier + " matched"
	patternNames, patternDetail := patternSummary(r.Strings)
	if patternNames != "" {
		evidence += ": " + patternNames
	}

	f := finding.Finding{
		SchemaVersion: finding.SchemaVersion,
		ID:            shortID(sha, r.Identifier),
		Host:          host,
		View:          "disk",
		Target:        finding.Target{Kind: "file", File: &finding.File{Path: filePath, SHA256: sha}},
		Artifact:      finding.Artifact{Kind: "file-webshell", Identity: filepath.Base(filePath), Location: filePath},
		Detection:     finding.Detection{Basis: "signature", KnowledgeRef: knowledgeRef, Evidence: evidence},
		Score:         score,
		Tier:          tier,
	}
	// Context carries everything that must NOT perturb the dedup fingerprint: rule provenance, and
	// the offset/text of each pattern hit. DRL-1.1 requires the author be surfaced on match; the
	// reference is here because it is provenance, not identity.
	ctx := map[string]string{}
	if patternDetail != "" {
		ctx["yara_matches"] = patternDetail
	}
	if r.Meta != nil {
		if fam, ok := r.Meta["family"]; ok && fam != "" {
			f.Classification.Family = &fam
		}
		if author, ok := r.Meta["author"]; ok && author != "" {
			ctx["rule_author"] = author
		}
		if ref, ok := r.Meta["reference"]; ok && ref != "" {
			ctx["rule_reference"] = ref
		}
		// The technique cells this rule claims to detect. Surfaced on the finding, not merely
		// validated at build time, so an analyst reading a detection can reach the prior-art review
		// that justifies it -- which is the whole point of tying a rule to a cell.
		if cells := ruleCells(r); len(cells) > 0 {
			ctx["technique_cells"] = strings.Join(cells, ",")
		}
	}
	if len(ctx) > 0 {
		f.Context = ctx
	}
	return f
}

// scoreToTier converts a THOR-style 0-100 score to a ShellSight tier.
func scoreToTier(score int) finding.Tier {
	switch {
	case score >= 85:
		return finding.TierConfirmed
	case score >= 60:
		return finding.TierLikely
	case score >= 40:
		return finding.TierSuspicious
	default:
		return finding.TierClean
	}
}
