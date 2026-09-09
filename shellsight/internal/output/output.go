// Package output writes a self-contained, chain-of-custody run folder.
package output

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"shellsight/internal/finding"
)

// Write creates <outDir>/run_<host>_<runID>/ with report.json, summary.txt, manifest.json.
// Returns the run folder path. manifest.json holds the SHA-256 of every other file.
func Write(rep finding.Report, outDir string) (string, error) {
	runDir := RunDirFor(outDir, rep.Scan.Host, rep.Scan.RunID)
	if err := os.MkdirAll(runDir, 0o755); err != nil {
		return "", err
	}

	reportJSON, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(runDir, "report.json"), reportJSON, 0o644); err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(runDir, "summary.txt"), []byte(summary(rep)), 0o644); err != nil {
		return "", err
	}

	// SOC-ready stream: one OCSF Detection Finding per line (NDJSON — the form Splunk HEC
	// and Elastic _bulk ingest directly). Empty file when there are no findings (valid NDJSON).
	ndjson := strings.Join(ocsfLines(rep), "\n")
	if ndjson != "" {
		ndjson += "\n"
	}
	if err := os.WriteFile(filepath.Join(runDir, "findings.ndjson"), []byte(ndjson), 0o644); err != nil {
		return "", err
	}

	manifest, err := buildManifest(runDir)
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(runDir, "manifest.json"), manifest, 0o644); err != nil {
		return "", err
	}
	return runDir, nil
}

// RunDirFor names the run folder for a scan. It is the one formula, shared with the core, which
// creates the folder BEFORE the probes run so the disk probe can fall back to it for its temporary
// workspace (spec 007 US3); Write then finds it already present.
func RunDirFor(outDir, host, runID string) string {
	return filepath.Join(outDir, fmt.Sprintf("run_%s_%s", sanitize(host), sanitize(runID)))
}

// writeScratch says where the temporary workspace went when the default location was not writable.
// Silent otherwise: the line exists to tell a responder that transient content briefly lived in the
// evidence folder, and an ordinary run has nothing to tell.
func writeScratch(b *strings.Builder, c finding.Coverage) {
	if c.Scratch == "" {
		return
	}
	fmt.Fprintf(b, "      scratch workspace: %s (default temporary location not writable)\n", c.Scratch)
}

// writeDiscovery renders how the scanned roots were located (FR-036).
//
// The distinction it exists to draw is between a directory read out of live configuration and one
// guessed off a distro default. Those are not the same evidence: if a scan came back clean and every
// root was a guess, the responder's next question is whether the real webroot was ever looked at.
// That was previously unanswerable from the report -- discovery returned bare paths -- and it is the
// gap the prior-art review found no OSS scanner filling.
//
// Mechanisms that found nothing are printed too. "No nginx on this host" and "nginx is here and
// named no root" mean different things during an IR, and a list that shows only successes cannot
// express either.
func writeDiscovery(b *strings.Builder, d *finding.DiscoveryReport) {
	if d == nil {
		return
	}
	for _, r := range d.Roots {
		via := r.Mechanism
		if r.Source != "" {
			via += " (" + r.Source + ")"
		}
		if len(r.AlsoFoundBy) > 0 {
			via += ", also " + strings.Join(r.AlsoFoundBy, ", ")
		}
		if r.InFilesystem != "" && r.InFilesystem != r.Path {
			// The scanned filesystem's own name for the directory. On a mounted image this is what the
			// compromised host was serving; r.Path is only where the disk is attached right now.
			via += ", served as " + r.InFilesystem
		}
		fmt.Fprintf(b, "      root %s  via %s\n", r.Path, via)
		for _, sub := range r.Subsumes {
			// Covered by scanning the parent. Shown so the report does not look like it dropped a
			// root that was genuinely discovered.
			fmt.Fprintf(b, "           covers %s\n", sub)
		}
	}
	var quiet []string
	for _, m := range d.Mechanisms {
		if m.Roots == 0 {
			note := m.Mechanism + "=" + m.Status
			if m.Detail != "" {
				note += " (" + m.Detail + ")"
			}
			quiet = append(quiet, note)
		}
	}
	if len(quiet) > 0 {
		fmt.Fprintf(b, "      found nothing: %s\n", strings.Join(quiet, "; "))
	}
	for _, r := range d.Rejected {
		// A config naming a directory that vanished, or one pointing at the filesystem root, is
		// itself worth seeing during an incident.
		fmt.Fprintf(b, "      REFUSED %s  (%s: %s)\n", r.Path, r.Mechanism, r.Reason)
	}
	// The list is bounded because its length is attacker-chosen. Saying so is what keeps a bounded
	// list from reading as a complete one.
	if extra := d.RejectedTotal - len(d.Rejected); extra > 0 {
		fmt.Fprintf(b, "      ...and %d further refused path(s) not shown (%d proposed in total)\n",
			extra, d.RejectedTotal)
	}
}

func summary(rep finding.Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "ShellSight scan — host=%s verdict=%s (score=%d)%s\n",
		rep.Scan.Host, rep.Verdict.Tier, rep.Verdict.Score, incompleteNote(rep.Verdict.Incomplete))
	fmt.Fprintf(&b, "tool=%s run=%s\n\nCoverage:\n", rep.Scan.ToolVersion, rep.Scan.RunID)
	for _, c := range rep.Coverage {
		// 14, not 12: `dotnet-mem-x86` is the longest view name and overflowed the column, pushing
		// its status out of alignment in every report that includes it.
		fmt.Fprintf(&b, "  %-14s %-8s %s\n", c.View, c.Status, c.Reason)
		writeDiscovery(&b, c.Discovery)
		writeScratch(&b, c)
	}
	// One block per finding rather than one line. Triaging a false positive needs the rule that fired
	// and the exact file; the old single line carried neither — only a basename, so on a real tree
	// (phpMyAdmin ships examples/openid.php) the analyst could not even identify the file. All of
	// this was already in report.json, so this is purely a rendering fix.
	fmt.Fprintf(&b, "\nFindings (%d):\n", len(rep.Findings))
	for _, f := range rep.Findings {
		fmt.Fprintf(&b, "  [%s] %s score=%d — %s\n", f.Tier, f.View, f.Score, findingTarget(f))

		attrs := []string{"rule=" + f.Detection.KnowledgeRef, "basis=" + f.Detection.Basis}
		if f.Classification.Family != nil && *f.Classification.Family != "" {
			attrs = append(attrs, "family="+*f.Classification.Family)
		}
		line := "      " + strings.Join(attrs, "  ")
		if len(f.Mitre) > 0 {
			line += "  [" + strings.Join(f.Mitre, ",") + "]"
		}
		fmt.Fprintln(&b, line)

		if f.Detection.Evidence != "" {
			fmt.Fprintf(&b, "      %s\n", f.Detection.Evidence)
		}
		// The matched bytes are the fastest way to judge a signature FP. Already bounded and
		// one-lined by the probe (see cmd/diskprobe patternSummary).
		if m := f.Context["yara_matches"]; m != "" {
			fmt.Fprintf(&b, "      matched: %s\n", m)
		}
	}
	fmt.Fprintf(&b, "\nSIEM: findings.ndjson (OCSF Detection Finding, one per line)\n")
	if rep.Scan.Operator != "" {
		fmt.Fprintf(&b, "Operator: %s\n", rep.Scan.Operator)
	}
	return b.String()
}

// findingTarget is what the finding is about, preferring the full on-disk path. Memory findings have
// no file, so they fall back to the artifact identity (a class or module name) — never blank.
func findingTarget(f finding.Finding) string {
	if f.Target.File != nil && f.Target.File.Path != "" {
		return f.Target.File.Path
	}
	if f.Artifact.Location != "" {
		return f.Artifact.Location
	}
	if f.Artifact.Identity != "" {
		return f.Artifact.Identity
	}
	return "(unidentified target)"
}

func incompleteNote(inc bool) string {
	if inc {
		return " [INCOMPLETE — some views did not run]"
	}
	return ""
}

// buildManifest hashes every file already in runDir (sorted for determinism).
func buildManifest(runDir string) ([]byte, error) {
	entries, err := os.ReadDir(runDir)
	if err != nil {
		return nil, err
	}
	hashes := map[string]string{}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)
	for _, name := range names {
		data, err := os.ReadFile(filepath.Join(runDir, name))
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(data)
		hashes[name] = hex.EncodeToString(sum[:])
	}
	return json.MarshalIndent(hashes, "", "  ")
}

func sanitize(s string) string {
	if s == "" {
		return "unknown"
	}
	repl := func(r rune) rune {
		if r == '/' || r == '\\' || r == ':' || r == ' ' {
			return '_'
		}
		return r
	}
	return strings.Map(repl, s)
}
