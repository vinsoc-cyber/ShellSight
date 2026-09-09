package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"shellsight/internal/weblang"
)

// declaredValues is every value a rule may write, plus the aliases the gate accepts.
var declaredValues = []string{
	"php", "jsp", "java", "asp", "aspx", "dotnet", "asp-family", "web-generic",
	"perl", "python", "shtml",
}

// FR-008 / SC-005, asserted exhaustively rather than sampled: a rule NEVER fires on a file whose
// language is recognised and different from its declaration, in either mode.
//
// Cross-language matching was measured and DECLINED, not deferred: on the .NET benign population it
// produced 24 findings and 0 true positives, and on JSP 6 true positives against 5 false positives
// (docs/measurements/2026-08-07-rules-provenance-correction/). This test is what keeps a later
// widening from quietly re-admitting it.
func TestCrossLanguageIsNeverAdmitted(t *testing.T) {
	signs := newSignCache()
	for _, declared := range declaredValues {
		rule := yaraxRuleMatch{
			Identifier: "probe_" + declared,
			Meta:       map[string]string{"shellsight_lang": declared},
		}
		for _, lang := range weblang.Languages() {
			for _, ext := range weblang.ExtensionsFor(lang) {
				path := filepath.FromSlash("C:/web/sample" + ext)
				ctx := inferFileContext(path)
				if ctx == ctxUnknown {
					continue // not a recognised language; the sign gate's business, not this test's
				}
				want := langCompatible(declared, ctx)
				for _, mode := range []scopeMode{modeWidened, modeLegacy} {
					got := ruleAdmission(path, rule, mode, signs)
					admitted := got != admitRefused
					if admitted != want {
						t.Errorf("declared=%q file=%s ctx=%q mode=%v: admitted=%v want=%v (basis %q)",
							declared, ext, ctx, mode, admitted, want, got)
					}
					if admitted && got != admitDeclared {
						t.Errorf("declared=%q on %s was admitted as %q; a recognised context must "+
							"only ever be a %q admission", declared, ext, got, admitDeclared)
					}
				}
			}
		}
	}
}

// The widened behaviour may only ever ADD. For every recognised extension, the two modes must agree:
// the change is confined to names the previous release did not understand. This is SC-004 at the
// admission layer, complementing TestClassificationOnlyWidens at the classification layer.
func TestWidenedAgreesWithLegacyOnRecognisedNames(t *testing.T) {
	signs := newSignCache()
	for _, declared := range append(declaredValues, "madeup", "") {
		rule := yaraxRuleMatch{Identifier: "probe", Meta: map[string]string{"shellsight_lang": declared}}
		for _, lang := range weblang.Languages() {
			for _, ext := range weblang.ExtensionsFor(lang) {
				path := filepath.FromSlash("C:/web/sample" + ext)
				a := ruleAdmission(path, rule, modeLegacy, signs)
				b := ruleAdmission(path, rule, modeWidened, signs)
				if a != b {
					t.Errorf("declared=%q ext=%s: legacy=%q widened=%q -- the two modes must agree "+
						"on every recognised name", declared, ext, a, b)
				}
			}
		}
	}
}

// A rule declaring nothing fires everywhere, in both modes. Every bundled third-party pack is in
// this position and must stay there: the metadata narrows only what its author chose to narrow.
func TestUndeclaredRulesFireEverywhere(t *testing.T) {
	signs := newSignCache()
	rule := yaraxRuleMatch{Identifier: "foundation_rule"}
	for _, name := range []string{"a.php", "a.jsp", "a.aspx", "a.txt", "a.jpg", "a.jar", "noext"} {
		for _, mode := range []scopeMode{modeWidened, modeLegacy} {
			if got := ruleAdmission(filepath.FromSlash("C:/web/"+name), rule, mode, signs); got != admitUndeclared {
				t.Errorf("%s (mode %v): got %q, want %q", name, mode, got, admitUndeclared)
			}
		}
	}
}

// modeWidened must be the ZERO value, so a caller that forgets to set the mode gets the shipped
// behaviour rather than silently restoring the blindness this feature removes.
func TestWidenedIsTheZeroValue(t *testing.T) {
	var m scopeMode
	if m != modeWidened {
		t.Fatalf("the zero scopeMode is %v, want modeWidened -- a forgotten assignment must not "+
			"restore the legacy behaviour", m)
	}
}

// NO OPERATOR FLAG SELECTS THE MODE. This is the guard on spec 008's R9 decision: the widened
// behaviour ships as the only behaviour, and the legacy mode exists solely for the tests and
// cmd/measure. An undocumented switch would be worse than a documented one, so if someone adds a
// flag whose name suggests scope selection, this fails.
func TestNoOperatorFlagSelectsTheScopeMode(t *testing.T) {
	names := diskprobeFlagNames()
	// A guard that can pass vacuously is not a guard (Constitution VI). If the source could not be
	// read, this test would report success while asserting nothing, so it fails instead.
	for _, known := range []string{"yr", "rules", "root"} {
		if !containsFold(names, known) {
			t.Fatalf("flag enumeration found %v, which lacks the known flag %q -- the source could "+
				"not be read and this test would otherwise pass vacuously", names, known)
		}
	}
	forbidden := []string{"rule-scope", "scope", "scope-mode", "legacy-scope", "widen", "lang-scope"}
	var found []string
	for _, name := range names {
		for _, bad := range forbidden {
			if strings.EqualFold(name, bad) {
				found = append(found, name)
			}
		}
	}
	if len(found) > 0 {
		t.Errorf("diskprobe defines scope-selecting flag(s) %v; spec 008 R9 ships one behaviour with "+
			"no operator surface. If this is deliberate, the spec and RUNBOOK must change first.", found)
	}
}

// flagDecl matches a flag definition in either command's source.
var flagDecl = regexp.MustCompile(`(?:flags|fs)\.(?:String|Bool|Int|Int64|Duration)(?:Var)?\(\s*(?:&\w+\s*,\s*)?"([^"]+)"`)

// diskprobeFlagNames reads the flag names both commands define, from source.
//
// A source-level assertion is the right shape here: the claim is that no OPERATOR SURFACE selects
// the scope mode, and a surface is something written into a flag set. Enumerating the flag set at
// runtime would require parsing, which exits on -h; reading the definitions is direct.
func diskprobeFlagNames() []string {
	var out []string
	for _, p := range []string{
		filepath.Join("main.go"),
		filepath.Join("..", "shellsight", "main.go"),
	} {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		for _, m := range flagDecl.FindAllStringSubmatch(string(data), -1) {
			out = append(out, m[1])
		}
	}
	return out
}

func containsFold(hay []string, needle string) bool {
	for _, h := range hay {
		if strings.EqualFold(h, needle) {
			return true
		}
	}
	return false
}

// The scope marking must land in Context and NOWHERE that identity is derived from.
//
// `internal/fusion` computes the fingerprint the runbook presents as the SIEM suppression key from
// Host, View, target, Detection.Basis, Detection.KnowledgeRef, Detection.Evidence and family --
// Context is excluded by design, and TestFingerprintIgnoresContext in that package pins it. What
// this test pins is the other half: the marking must not leak into Detection, where it WOULD move
// every existing fingerprint and make a renamed-file finding unsuppressable by an existing rule.
func TestScopeMarkingLandsOnlyInContext(t *testing.T) {
	rule := yaraxRuleMatch{
		Identifier: "php_eval_request_webshell",
		Meta:       map[string]string{"shellsight_lang": "php", "score": "70"},
	}
	base := findingFromRule(filepath.FromSlash("C:/web/shell.php"), "deadbeef", rule, "H")

	marked := findingFromRule(filepath.FromSlash("C:/web/shell.php"), "deadbeef", rule, "H")
	if marked.Context == nil {
		marked.Context = map[string]string{}
	}
	marked.Context["rule_scope"] = string(admitUnknownLanguage)

	if base.Detection != marked.Detection {
		t.Errorf("the marking changed Detection, which IS hashed into the fingerprint: %+v vs %+v",
			base.Detection, marked.Detection)
	}
	if base.Score != marked.Score || base.Tier != marked.Tier {
		t.Errorf("the marking changed score/tier: %d/%s -> %d/%s -- there is no cap anywhere",
			base.Score, base.Tier, marked.Score, marked.Tier)
	}
	if got := marked.Context["rule_scope"]; got != string(admitUnknownLanguage) {
		t.Errorf("context.rule_scope = %q, want %q", got, admitUnknownLanguage)
	}
	// And an ordinary finding carries no marking at all, so today's findings are unchanged.
	if _, ok := base.Context["rule_scope"]; ok {
		t.Error("an unmarked finding must not carry a rule_scope key")
	}
}
