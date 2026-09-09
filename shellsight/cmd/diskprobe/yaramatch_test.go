package main

import (
	"strings"
	"testing"
)

// Every YARA finding used to report evidence of "YARA rule X matched" — a restatement of the rule
// name and nothing else. Triaging a false positive meant grepping kb/rules/ for the definition and
// working out by hand which of its patterns hit. Naming the matched patterns turns that into a
// single read. Compare the taint engine, which already says
// "AST taint: assert(...) called with request input".
func TestEvidenceNamesMatchedPatterns(t *testing.T) {
	r := yaraxRuleMatch{
		Identifier: "php_eval_request_webshell",
		Strings: []yaraxPatternMatch{
			{Identifier: "$eval_var", Offset: 39, Match: "eval($x)"},
		},
	}
	f := findingFromRule(`C:\web\x.php`, "deadbeef", r, "WEB01")
	if !strings.Contains(f.Detection.Evidence, "$eval_var") {
		t.Fatalf("evidence must name the matched pattern, got %q", f.Detection.Evidence)
	}
	if !strings.Contains(f.Detection.Evidence, "php_eval_request_webshell") {
		t.Errorf("evidence must still name the rule, got %q", f.Detection.Evidence)
	}
}

// The volatile detail — byte offset and matched text — belongs in Context, which is
// fingerprint-neutral (fusion.fingerprint hashes Evidence). Pattern IDENTIFIERS are part of the
// rule, so they are stable across cosmetic edits to the file; offsets are not. Putting offsets in
// evidence would move a finding's fingerprint every time a benign file shifts by a byte, silently
// breaking any SIEM suppression keyed on it.
func TestMatchOffsetAndTextGoToContextNotEvidence(t *testing.T) {
	r := yaraxRuleMatch{
		Identifier: "r1",
		Strings:    []yaraxPatternMatch{{Identifier: "$a", Offset: 4096, Match: "eval($x)"}},
	}
	f := findingFromRule("/tmp/x.php", "abc", r, "h")
	if strings.Contains(f.Detection.Evidence, "4096") {
		t.Errorf("offset must NOT be in evidence (fingerprint stability), got %q", f.Detection.Evidence)
	}
	got := f.Context["yara_matches"]
	if !strings.Contains(got, "4096") || !strings.Contains(got, "eval($x)") {
		t.Fatalf("context yara_matches must carry offset and matched text, got %q", got)
	}
}

// Backwards compatibility: rules whose matches yr did not report keep the original wording, so
// nothing that reads evidence has to special-case an empty pattern list.
func TestEvidenceUnchangedWhenNoPatternsReported(t *testing.T) {
	f := findingFromRule("/tmp/x.php", "abc", yaraxRuleMatch{Identifier: "r1"}, "h")
	if f.Detection.Evidence != "YARA rule r1 matched" {
		t.Fatalf("want the original wording with no patterns, got %q", f.Detection.Evidence)
	}
	if _, ok := f.Context["yara_matches"]; ok {
		t.Errorf("no patterns must mean no yara_matches context key, got %q", f.Context["yara_matches"])
	}
}

// A pattern that matches many times must be named once, and a rule with dozens of patterns must not
// produce an unreadable evidence line.
func TestMatchedPatternsAreDedupedAndBounded(t *testing.T) {
	var pats []yaraxPatternMatch
	for i := 0; i < 4; i++ {
		pats = append(pats, yaraxPatternMatch{Identifier: "$dup", Offset: int64(i) * 10, Match: "x"})
	}
	for i := 0; i < 12; i++ {
		pats = append(pats, yaraxPatternMatch{Identifier: "$p" + string(rune('a'+i)), Offset: int64(i), Match: "y"})
	}
	f := findingFromRule("/tmp/x.php", "abc", yaraxRuleMatch{Identifier: "r1", Strings: pats}, "h")
	ev := f.Detection.Evidence

	if strings.Count(ev, "$dup") != 1 {
		t.Errorf("a repeated pattern must be named once, got %q", ev)
	}
	if !strings.Contains(ev, "more") {
		t.Errorf("a long pattern list must be truncated with a count, got %q", ev)
	}
	if len(ev) > 400 {
		t.Errorf("evidence must stay readable, got %d chars: %q", len(ev), ev)
	}
}

// Matched bytes are attacker-controlled: they must not break the one-line-per-finding shape of
// summary.txt or NDJSON, and must be length-bounded.
func TestMatchedTextIsOneLinedAndBounded(t *testing.T) {
	long := strings.Repeat("A", 500)
	r := yaraxRuleMatch{
		Identifier: "r1",
		Strings: []yaraxPatternMatch{
			{Identifier: "$a", Offset: 1, Match: "line1\nline2\r\n\tline3"},
			{Identifier: "$b", Offset: 2, Match: long},
		},
	}
	f := findingFromRule("/tmp/x.php", "abc", r, "h")
	ctx := f.Context["yara_matches"]
	if strings.ContainsAny(ctx, "\n\r\t") {
		t.Errorf("matched text must be one-lined, got %q", ctx)
	}
	if strings.Contains(ctx, long) {
		t.Errorf("matched text must be length-bounded, got %d chars", len(ctx))
	}
	if !strings.Contains(f.Detection.Evidence, "$a") || !strings.Contains(f.Detection.Evidence, "$b") {
		t.Errorf("both patterns should still be named, got %q", f.Detection.Evidence)
	}
}
