package main

import "testing"

func TestInferFileContext(t *testing.T) {
	cases := map[string]fileContext{
		`C:\inetpub\wwwroot\a.php`:   ctxPHP,
		`C:\app\view.phtml`:          ctxPHP,
		`C:\app\shell.jsp`:           ctxJSP,
		`C:\app\shell.jspx`:          ctxJSP,
		`C:\app\legacy.asp`:          ctxASP,
		`C:\app\legacy.cer`:          ctxASP,
		`C:\app\handler.ashx`:        ctxASPX,
		`C:\app\page.aspx`:           ctxASPX,
		`C:\app\control.ascx`:        ctxASPX,
		`C:\app\web.config`:          ctxConfig,
		`C:\app\template.html`:       ctxStatic,
		`C:\app\unknown.webshelltmp`: ctxUnknown,
		// languages added 2026-08-11 to close a measured coverage gap
		`/var/www/cgi-bin/shell.pl`: ctxPerl,
		`/var/www/lib/Foo.pm`:       ctxPerl,
		`/var/www/app/shell.py`:     ctxPython,
		`/var/www/cgi-bin/x.cgi`:    ctxCGI,
		`/var/www/x.fcgi`:           ctxCGI,
		`/var/www/index.shtml`:      ctxShtml,
		`/var/www/index.stm`:        ctxShtml,
	}
	for path, want := range cases {
		if got := inferFileContext(path); got != want {
			t.Fatalf("inferFileContext(%q)=%q want %q", path, got, want)
		}
	}
}

// A .cgi file may be Perl or Python, so both languages' rules must be allowed to fire on it;
// each language's rules must NOT fire on the other's dedicated extension.
func TestRuleCompatiblePerlPythonShtml(t *testing.T) {
	perl := yaraxRuleMatch{Identifier: "perl_x", Meta: map[string]string{"author": "ShellSight", "shellsight_lang": "perl"}}
	py := yaraxRuleMatch{Identifier: "py_x", Meta: map[string]string{"author": "ShellSight", "shellsight_lang": "python"}}
	ssi := yaraxRuleMatch{Identifier: "ssi_x", Meta: map[string]string{"author": "ShellSight", "shellsight_lang": "shtml"}}

	check := func(rule yaraxRuleMatch, path string, want bool) {
		if got := ruleCompatible(path, rule); got != want {
			t.Errorf("ruleCompatible(%q, %s)=%v want %v", path, rule.Meta["shellsight_lang"], got, want)
		}
	}
	check(perl, `/v/shell.pl`, true)
	check(perl, `/v/x.cgi`, true) // .cgi is shared
	check(perl, `/v/shell.py`, false)
	check(py, `/v/shell.py`, true)
	check(py, `/v/x.cgi`, true) // .cgi is shared
	check(py, `/v/shell.pl`, false)
	check(ssi, `/v/index.shtml`, true)
	check(ssi, `/v/index.stm`, true)
	check(ssi, `/v/shell.pl`, false)
}

func TestRuleCompatibleUsesShellSightLangMeta(t *testing.T) {
	jspRule := yaraxRuleMatch{Identifier: "owned_jsp", Meta: map[string]string{"author": "ShellSight", "shellsight_lang": "jsp"}}
	if !ruleCompatible(`C:\web\a.jsp`, jspRule) {
		t.Fatal("jsp rule should be compatible with .jsp")
	}
	if ruleCompatible(`C:\web\a.aspx`, jspRule) {
		t.Fatal("jsp rule should not be compatible with .aspx")
	}
	generic := yaraxRuleMatch{Identifier: "owned_generic", Meta: map[string]string{"author": "ShellSight", "shellsight_lang": "web-generic"}}
	if !ruleCompatible(`C:\web\a.jsp`, generic) || !ruleCompatible(`C:\web\a.aspx`, generic) {
		t.Fatal("web-generic rule should be compatible with web source contexts")
	}
}

// A rule that DECLARES a language is honored whoever wrote it.
//
// This gate used to require author == "ShellSight", so an analyst following RUNBOOK.md and writing
// `shellsight_lang = "php"` had it silently ignored: the rule fired on .php, .jsp, .aspx and .js
// alike (measured). That is precisely the shape that produced 23 of 24 .NET false positives from a
// single over-broad ASP rule — the failure this gate exists to prevent — and it left an operator no
// way to scope their own rule short of putting the vendor's name in their author field.
//
// Safe by construction: the meta is opt-in, and no rule in any of the four foundation packs
// declares it (44 of 44 in kb/rules/own do), so third-party rules keep the permissive default
// asserted by TestRuleCompatibleUnknownCommunityRuleStillEmits.
func TestRuleCompatibleHonorsLangMetaFromAnyAuthor(t *testing.T) {
	analyst := yaraxRuleMatch{Identifier: "acme_php_only", Meta: map[string]string{"author": "Acme SOC", "shellsight_lang": "php"}}
	if !ruleCompatible(`C:\web\a.php`, analyst) {
		t.Fatal("an analyst php rule must fire on .php")
	}
	for _, p := range []string{`C:\web\a.aspx`, `C:\web\a.jsp`, `C:\web\a.js`, `C:\web\a.asp`} {
		if ruleCompatible(p, analyst) {
			t.Errorf("an analyst rule scoped to php must not fire on %s", p)
		}
	}
	// No author at all is just as valid — the meta is what scopes, not who wrote it.
	anon := yaraxRuleMatch{Identifier: "anon_jsp", Meta: map[string]string{"shellsight_lang": "jsp"}}
	if ruleCompatible(`C:\web\a.aspx`, anon) {
		t.Error("an unattributed rule scoped to jsp must not fire on .aspx")
	}
	if !ruleCompatible(`C:\web\a.jsp`, anon) {
		t.Error("an unattributed rule scoped to jsp must fire on .jsp")
	}
}

func TestRuleCompatibleUnknownOwnedLangRejectsUnknownExtension(t *testing.T) {
	owned := yaraxRuleMatch{Identifier: "owned_unknown", Meta: map[string]string{"author": "ShellSight", "shellsight_lang": "madeup"}}
	if ruleCompatible(`C:\web\a.webshelltmp`, owned) {
		t.Fatal("unknown owned language must not be compatible with an unknown extension")
	}
}

func TestRuleCompatibleUnknownCommunityRuleStillEmits(t *testing.T) {
	community := yaraxRuleMatch{Identifier: "community_rule_without_meta"}
	if !ruleCompatible(`C:\web\a.jsp`, community) {
		t.Fatal("community/foundation rules without metadata must continue to emit")
	}
}

func TestFindingsFromFileMatchSuppressesIncompatibleRule(t *testing.T) {
	fm := yaraxFileMatch{
		Path: `C:\tomcat\webapps\ROOT\index.jsp`,
		Rules: []yaraxRuleMatch{
			// Carries the declaration the SHIPPED rule carries. It used to be given a score and no
			// language, which suppressed it only through a hard-coded identifier branch in
			// ruleCompatible -- deleted in spec 008, because both rules now declare `asp-family` and
			// the branch was unreachable. A fixture that omits the declaration tests the branch, not
			// the rule.
			{Identifier: "asp_html_hybrid_webshell",
				Meta: map[string]string{"score": "65", "shellsight_lang": "asp-family"}},
			{Identifier: "jsp_command_exec_webshell", Meta: map[string]string{"score": "75", "shellsight_lang": "jsp"}},
		},
	}
	fs := findingsFromFileMatch(fm, "WEB01", newSignCache())
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1: %+v", len(fs), fs)
	}
	if fs[0].Detection.KnowledgeRef != "kb:yara/jsp_command_exec_webshell" {
		t.Fatalf("wrong finding survived: %+v", fs[0].Detection)
	}
}

// Prior art scopes Python rules to py/py3/pyi/pyp/pyx/cgi/fcgi. A Python shell dropped as .pyx must
// not fall through to ctxUnknown, which would discard every language-scoped rule match on it.
func TestPythonContextCoversAllVCSExtensions(t *testing.T) {
	for _, p := range []string{
		`/var/www/app/shell.py`,
		`/var/www/app/shell.pyw`,
		`/var/www/app/shell.py3`,
		`/var/www/app/shell.pyi`,
		`/var/www/app/shell.pyp`,
		`/var/www/app/shell.pyx`,
	} {
		if got := inferFileContext(p); got != ctxPython {
			t.Errorf("inferFileContext(%q) = %q, want %q", p, got, ctxPython)
		}
	}
}

// The technique-cell reference (spec 003, T085). A rule that names cells must surface them; a rule
// that names none must still fire, because a metadata omission may not silently disable detection.
func TestRuleCellsParsesTheCommaSeparatedList(t *testing.T) {
	r := yaraxRuleMatch{Meta: map[string]string{"shellsight_cells": "php/dispatch/eval, php/obfuscation/base64"}}
	got := ruleCells(r)
	if len(got) != 2 || got[0] != "php/dispatch/eval" || got[1] != "php/obfuscation/base64" {
		t.Fatalf("ruleCells = %v", got)
	}
}

func TestRuleCellsIsNilWhenAbsent(t *testing.T) {
	if got := ruleCells(yaraxRuleMatch{Meta: map[string]string{}}); got != nil {
		t.Fatalf("expected nil for a rule that declares no cells, got %v", got)
	}
}

func TestRuleCellsIgnoresEmptyEntries(t *testing.T) {
	r := yaraxRuleMatch{Meta: map[string]string{"shellsight_cells": " php/dispatch/eval , , "}}
	if got := ruleCells(r); len(got) != 1 || got[0] != "php/dispatch/eval" {
		t.Fatalf("ruleCells = %v", got)
	}
}

func TestDeclaringCellsDoesNotChangeWhetherARuleFires(t *testing.T) {
	// Gating on this field would trade a documentation failure for a security one: a rule whose
	// metadata was never backfilled would stop detecting.
	withCells := yaraxRuleMatch{Identifier: "x", Meta: map[string]string{
		"shellsight_lang": "php", "shellsight_cells": "php/dispatch/eval"}}
	without := yaraxRuleMatch{Identifier: "x", Meta: map[string]string{"shellsight_lang": "php"}}
	for _, path := range []string{"a.php", "a.jsp", "a.txt"} {
		if ruleCompatible(path, withCells) != ruleCompatible(path, without) {
			t.Fatalf("%s: declaring cells changed compatibility", path)
		}
	}
}

func TestAThirdPartyRuleWithNoCellsStaysPermissive(t *testing.T) {
	r := yaraxRuleMatch{Identifier: "SomeForgeRule", Meta: map[string]string{}}
	if !ruleCompatible("anything.php", r) {
		t.Fatal("a rule declaring neither a language nor a cell must keep firing everywhere")
	}
}
