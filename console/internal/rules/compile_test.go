package rules

import (
	"shellsightconsole/internal/consoletest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// yrPath finds the bundled engine, or skips. Tests must not silently pass on a machine with no yr.
func yrPath(t *testing.T) string {
	t.Helper()
	if p := consoletest.FindYr(); p != "" {
		return p
	}
	t.Skip("no yr binary found; set CONSOLE_TEST_YR")
	return ""
}

const validRule = `rule ok_rule {
  meta:
    shellsight_lang = "php"
  strings:
    $a = "eval("
  condition:
    $a
}`

const brokenRule = `rule broken_rule {
  strings:
    $a = "x"
  condition:
    $a and
}`

func TestCheckRuleAcceptsAValidRule(t *testing.T) {
	c := NewCompiler(yrPath(t))
	if err := c.CheckRule(validRule, nil); err != nil {
		t.Fatalf("valid rule was rejected: %v", err)
	}
}

func TestCheckRuleRejectsABrokenRuleAndReportsYrsMessage(t *testing.T) {
	c := NewCompiler(yrPath(t))
	err := c.CheckRule(brokenRule, nil)
	if err == nil {
		t.Fatal("expected a broken rule to be rejected, got nil")
	}
	// The analyst must see the compiler's own words, not ours.
	if !strings.Contains(err.Error(), "syntax error") {
		t.Fatalf("error must carry yr's message, got: %v", err)
	}
}

const helperRule = `private rule Helper_PRIVATE {
  strings:
    $h = "helper"
  condition:
    $h
}`

const dependentRule = `rule needs_helper {
  strings:
    $a = "aaa"
  condition:
    Helper_PRIVATE and $a
}`

func TestARuleWithADependencyFailsWithoutContext(t *testing.T) {
	// This is the defect that made an isolated compile check wrong. Measured over the shipped
	// packs, 50 rules reference another rule; 16 of the first 400 in the YARA-Forge pack fail
	// exactly like this. Checking them in isolation would reject valid rules.
	c := NewCompiler(yrPath(t))
	err := c.CheckRule(dependentRule, nil)
	if err == nil {
		t.Fatal("expected a rule with an unresolved reference to fail without context")
	}
	if !strings.Contains(err.Error(), "unknown identifier") {
		t.Fatalf("expected an unknown-identifier error, got: %v", err)
	}
}

func TestTheSameRulePassesWithItsDependencySupplied(t *testing.T) {
	c := NewCompiler(yrPath(t))
	ctx := map[string]string{"Helper_PRIVATE": helperRule}
	if err := c.CheckRule(dependentRule, ctx); err != nil {
		t.Fatalf("valid rule rejected despite its dependency being supplied: %v", err)
	}
}

func TestContextDoesNotMaskTheEditedRulesOwnSyntaxError(t *testing.T) {
	// Supplying context must not turn the check into "does the set compile" -- a broken edit
	// still has to fail.
	c := NewCompiler(yrPath(t))
	ctx := map[string]string{"Helper_PRIVATE": helperRule}
	if err := c.CheckRule(brokenRule, ctx); err == nil {
		t.Fatal("expected a syntactically broken rule to fail even with context supplied")
	}
}

func TestCompileDirProducesABlob(t *testing.T) {
	c := NewCompiler(yrPath(t))
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.yar"), []byte(validRule), 0o644); err != nil {
		t.Fatal(err)
	}
	blob, err := c.CompileDir(dir)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if len(blob) == 0 {
		t.Fatal("expected a non-empty .yarc blob")
	}
}

func TestOneBrokenRuleYieldsNoBlobAtAll(t *testing.T) {
	// Measured 2026-08-30: 56 valid rules plus 1 malformed rule produce exit 1 and no output.
	// There is no partial-success mode, which is why the freeze gate exists.
	c := NewCompiler(yrPath(t))
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "good.yar"), []byte(validRule), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "bad.yar"), []byte(brokenRule), 0o644); err != nil {
		t.Fatal(err)
	}
	blob, err := c.CompileDir(dir)
	if err == nil {
		t.Fatal("expected the whole directory compile to fail")
	}
	if blob != nil {
		t.Fatalf("expected no blob on failure, got %d bytes", len(blob))
	}
}

func TestCompileDirDetectsDuplicateIdentifiersAcrossFiles(t *testing.T) {
	// The cross-rule failure a per-rule check structurally cannot see.
	c := NewCompiler(yrPath(t))
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.yar"), []byte(validRule), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b.yar"), []byte(validRule), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := c.CompileDir(dir); err == nil {
		t.Fatal("expected a duplicate rule identifier to fail the compile")
	}
}
