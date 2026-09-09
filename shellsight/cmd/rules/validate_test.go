package rules_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"shellsight/cmd/rules"
)

// yrPath locates the bundled engine, or skips: bin/ is gitignored, so it is absent in a clean CI
// checkout and these cases genuinely cannot run there.
func yrPath(t *testing.T) string {
	t.Helper()
	p, err := filepath.Abs(filepath.Join("..", "..", "bin", "third_party", "yara-x", "yr.exe"))
	if err != nil {
		t.Skipf("cannot resolve yr path: %v", err)
	}
	if _, err := os.Stat(p); err != nil {
		t.Skipf("bundled yr.exe not present (bin/ is gitignored): %v", err)
	}
	return p
}

// mkRules builds a rules tree at <root>/kb/rules with a real mem-contracts.json (validate checks it
// first), one rule in the named layer, and optionally a benign corpus at the path validate expects
// (<rulesDir>/../../lab/corpus/disk/benign). Returns the rules dir.
func mkRules(t *testing.T, layer, ruleBody, benignFile string) string {
	t.Helper()
	root := t.TempDir()
	rulesDir := filepath.Join(root, "kb", "rules")
	if err := os.MkdirAll(filepath.Join(rulesDir, layer), 0o755); err != nil {
		t.Fatal(err)
	}
	mc, err := os.ReadFile(filepath.Join("testdata", "rules", "mem-contracts.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rulesDir, "mem-contracts.json"), mc, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rulesDir, layer, "r.yar"), []byte(ruleBody), 0o644); err != nil {
		t.Fatal(err)
	}
	if benignFile != "" {
		benign := filepath.Join(root, "lab", "corpus", "disk", "benign")
		if err := os.MkdirAll(benign, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(benign, "sample.php"), []byte(benignFile), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return rulesDir
}

const okRule = "rule ok_rule {\n  strings:\n    $a = \"AcmeUniqueMarkerZZZ\"\n  condition:\n    $a\n}\n"

// RUNBOOK.md tells the analyst to run this before deploying a rule. In the shipped bundle there is
// no benign corpus, so it used to print "nothing to validate" and return 0 — an analyst reads exit 0
// as "my rule is validated". Reporting success for work that did not happen is the same defect as a
// timed-out scan reporting clean.
func TestValidateWithoutBenignCorpusDoesNotReportSuccess(t *testing.T) {
	yr := yrPath(t)
	t.Setenv("SHELLSIGHT_YR_PATH", yr)
	dir := mkRules(t, "custom", okRule, "")

	var buf strings.Builder
	code := rules.RunWithWriter([]string{"validate", "--rules-dir", dir, "--layer", "custom"}, &buf)
	out := buf.String()

	if code == 0 {
		t.Fatalf("validate must not report success with no corpus to validate against; got 0 and:\n%s", out)
	}
	if code != 3 {
		t.Errorf("want exit 3 (INCOMPLETE, distinct from 1=FAILED), got %d", code)
	}
	// "validate: OK" is the success verdict. (Sub-checks may legitimately report their own OK, e.g.
	// "mem-contracts.json OK", so match the verdict line rather than the bare word.)
	if strings.Contains(out, "validate: OK") {
		t.Errorf("output must not read as OK when the FP check did not run:\n%s", out)
	}
	if !strings.Contains(out, "SKIPPED") {
		t.Errorf("output must say plainly that the FP check was skipped:\n%s", out)
	}
}

// The compile check needs no corpus, so a syntactically broken rule must be caught even in the
// shipped bundle. Previously validate returned before compiling anything, so a broken custom rule
// shipped silently.
func TestValidateCatchesSyntaxErrorWithoutCorpus(t *testing.T) {
	yr := yrPath(t)
	t.Setenv("SHELLSIGHT_YR_PATH", yr)
	broken := "rule broken_rule {\n  strings:\n    $a = \"x\"\n  conditionX\n    $a\n}\n"
	dir := mkRules(t, "custom", broken, "")

	var buf strings.Builder
	code := rules.RunWithWriter([]string{"validate", "--rules-dir", dir, "--layer", "custom"}, &buf)
	out := buf.String()

	if code != 1 {
		t.Fatalf("a rule that does not compile must FAIL (exit 1), got %d and:\n%s", code, out)
	}
	if !strings.Contains(out, "r.yar") {
		t.Errorf("the error must name the offending file:\n%s", out)
	}
}

// A clean run is the only thing allowed to say OK.
func TestValidateReportsOKOnlyWithACleanCorpus(t *testing.T) {
	yr := yrPath(t)
	t.Setenv("SHELLSIGHT_YR_PATH", yr)
	dir := mkRules(t, "custom", okRule, "<?php echo \"nothing to see\";\n")

	var buf strings.Builder
	code := rules.RunWithWriter([]string{"validate", "--rules-dir", dir, "--layer", "custom"}, &buf)
	out := buf.String()

	if code != 0 {
		t.Fatalf("a compiling rule with 0 benign hits must pass, got %d and:\n%s", code, out)
	}
	if !strings.Contains(out, "OK") {
		t.Errorf("a clean validation should say OK:\n%s", out)
	}
}

// And a rule that fires on the benign corpus must fail, distinctly from "incomplete".
func TestValidateFailsOnBenignHit(t *testing.T) {
	yr := yrPath(t)
	t.Setenv("SHELLSIGHT_YR_PATH", yr)
	dir := mkRules(t, "custom", okRule, "<?php // AcmeUniqueMarkerZZZ\n")

	var buf strings.Builder
	code := rules.RunWithWriter([]string{"validate", "--rules-dir", dir, "--layer", "custom"}, &buf)
	out := buf.String()

	if code != 1 {
		t.Fatalf("a rule matching benign content must FAIL (exit 1), got %d and:\n%s", code, out)
	}
	if !strings.Contains(out, "false-positive") {
		t.Errorf("the failure must name the cause:\n%s", out)
	}
}

// Asking for a layer that is not present is an error, not a silent pass.
func TestValidateMissingLayerIsAnError(t *testing.T) {
	yr := yrPath(t)
	t.Setenv("SHELLSIGHT_YR_PATH", yr)
	dir := mkRules(t, "own", okRule, "<?php echo 1;\n")

	var buf strings.Builder
	code := rules.RunWithWriter([]string{"validate", "--rules-dir", dir, "--layer", "custom"}, &buf)
	if code == 0 {
		t.Fatalf("validating an absent layer must not pass; got 0 and:\n%s", buf.String())
	}
}
