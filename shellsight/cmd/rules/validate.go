package rules

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"shellsight/internal/platform"
)

// runValidate checks the rule set an analyst is about to deploy.
//
// Exit codes are deliberately three-valued:
//
//	0 = validated       — the rules compile AND fire on nothing in the benign corpus
//	1 = FAILED          — they do not compile, or they hit benign files
//	3 = INCOMPLETE      — they compile, but the false-positive check could not run
//
// 3 exists because this used to return 0 when there was no benign corpus, printing
// "nothing to validate". The shipped bundle carries no corpus, so RUNBOOK.md's "validate before
// deploying" step always no-opped while reporting success — and an analyst reads exit 0 as "my rule
// is safe". Reporting success for work that did not happen is the same defect as a timed-out scan
// reporting clean, so it gets the same treatment: say what was not done, and do not exit 0.
func runValidate(args []string, w io.Writer) int {
	dir := rulesDir(args)
	layer := ""
	for i, a := range args {
		if a == "--layer" && i+1 < len(args) {
			layer = args[i+1]
		}
	}

	// mem-contracts.json drives the memory probes; a broken one is a hard failure.
	if !validateMemContracts(dir, w) {
		return 1
	}

	// compileTarget mirrors what cmd/diskprobe actually loads, so a cross-layer problem (a duplicate
	// rule identifier, say) surfaces here rather than at scan time. A named layer is compiled alone
	// because that is the question the analyst asked.
	compileTarget := dir
	var ruleDirs []string
	if layer != "" {
		p := filepath.Join(dir, layer)
		if _, err := os.Stat(p); err != nil {
			fmt.Fprintf(w, "validate: FAIL — layer %q not found at %s\n", layer, p)
			return 1
		}
		compileTarget = p
		ruleDirs = []string{p}
	} else {
		for _, l := range []string{"foundation", "own", "custom"} {
			p := filepath.Join(dir, l)
			if _, err := os.Stat(p); err == nil {
				ruleDirs = append(ruleDirs, p)
			}
		}
	}

	exe, _ := os.Executable()
	yr := filepath.Join(filepath.Dir(exe), "third_party", "yara-x", platform.ExeName("yr", runtime.GOOS))
	if p := os.Getenv("SHELLSIGHT_YR_PATH"); p != "" {
		yr = p
	}

	// 1) Compile check. This needs no corpus, so it is the one real check that always runs — and it
	// catches the class that would otherwise ship silently: a custom rule that does not parse.
	if stderr, err := compileRules(yr, compileTarget); err != nil {
		fmt.Fprintf(w, "validate: FAIL — rules do not compile (%s):\n%s\n", compileTarget, boundLines(stderr, 20))
		return 1
	}
	fmt.Fprintf(w, "validate: rules compile (%s)\n", compileTarget)

	// 2) False-positive check against the benign corpus.
	benignDir := filepath.Join(dir, "..", "..", "lab", "corpus", "disk", "benign")
	if _, err := os.Stat(benignDir); err != nil {
		fmt.Fprintf(w, "validate: false-positive check SKIPPED — no benign corpus at %s\n", benignDir)
		fmt.Fprintln(w, "validate: INCOMPLETE — the rules compile, but they have NOT been checked against")
		fmt.Fprintln(w, "  benign code. This is not a clean bill of health: the usual way a new rule hurts")
		fmt.Fprintln(w, "  is by firing on legitimate files, and that is exactly what was not tested.")
		fmt.Fprintln(w, "  Supply a corpus at lab/corpus/disk/benign, or scan a known-clean webroot with")
		fmt.Fprintln(w, "  `shellsight scan --views disk --path <webroot>` and review every finding.")
		return 3
	}

	fpCount := 0
	for _, ruleDir := range ruleDirs {
		out, err := exec.Command(yr, "scan", "--output-format", "ndjson", "--recursive", ruleDir, benignDir).Output()
		if err != nil && len(out) == 0 {
			fmt.Fprintf(w, "validate: yr scan failed for %s: %v\n", ruleDir, err)
			return 1
		}
		for _, line := range strings.Split(string(out), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			var hit struct {
				Rules []json.RawMessage `json:"rules"`
			}
			if err := json.Unmarshal([]byte(line), &hit); err == nil && len(hit.Rules) > 0 {
				fpCount++
			}
		}
	}
	if fpCount > 0 {
		fmt.Fprintf(w, "validate: FAIL — %d false-positive hit(s) on benign corpus\n", fpCount)
		return 1
	}
	fmt.Fprintln(w, "validate: OK — rules compile and produce 0 false positives on benign corpus")
	return 0
}

// compileRules compiles target to a throwaway binary and returns yr's diagnostics.
//
// Both streams are captured together: yr does not put all of its compile diagnostics on stderr, so
// reading stderr alone reported a failure with an empty explanation. The error is authoritative for
// pass/fail — yr prints style warnings while exiting 0 (the shipped foundation tree emits several),
// so treating any output as failure would reject valid rules.
func compileRules(yr, target string) (string, error) {
	tmp, err := os.MkdirTemp("", "shellsight-rulecheck-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(tmp)
	cmd := exec.Command(yr, "compile", "-o", filepath.Join(tmp, "rules.bin"), target)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	runErr := cmd.Run()
	diag := strings.TrimSpace(out.String())
	if runErr != nil && diag == "" {
		diag = "(yr produced no diagnostics; exit: " + runErr.Error() + ")"
	}
	return diag, runErr
}

// boundLines keeps a compiler error report readable when a file has many faults.
func boundLines(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\r\n"), "\n")
	if len(lines) <= n {
		return strings.Join(lines, "\n")
	}
	return strings.Join(lines[:n], "\n") + fmt.Sprintf("\n  ... and %d more line(s)", len(lines)-n)
}
