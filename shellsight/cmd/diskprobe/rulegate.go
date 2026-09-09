package main

import (
	"strings"

	"shellsight/internal/weblang"
)

type fileContext string

const (
	ctxPHP     fileContext = "php"
	ctxJSP     fileContext = "jsp"
	ctxASP     fileContext = "asp"
	ctxASPX    fileContext = "aspx"
	ctxPerl    fileContext = "perl"
	ctxPython  fileContext = "python"
	ctxShtml   fileContext = "shtml"
	ctxCGI     fileContext = "cgi" // .cgi/.fcgi — ambiguous Perl-or-Python, accepted by both
	ctxConfig  fileContext = "config"
	ctxStatic  fileContext = "static"
	ctxJVM     fileContext = "jvm" // .java/.class/.jar/.war — the bytecode scanner's, never the rule layer's
	ctxUnknown fileContext = "unknown"
)

// fromWeblang maps the shared table's answer onto this package's context type. The two enumerations
// are deliberately separate: `fileContext` is what the gate reasons about (and carries ctxUnknown as
// a first-class outcome), while weblang.Lang is what a NAME claims.
var fromWeblang = map[weblang.Lang]fileContext{
	weblang.PHP: ctxPHP, weblang.JSP: ctxJSP, weblang.ASP: ctxASP, weblang.ASPX: ctxASPX,
	weblang.Perl: ctxPerl, weblang.Python: ctxPython, weblang.CGI: ctxCGI,
	weblang.Shtml: ctxShtml, weblang.Config: ctxConfig, weblang.Static: ctxStatic,
	weblang.JVMArtifact: ctxJVM,
}

// inferFileContext reports what a path's NAME claims the file is.
//
// The extension lists live in internal/weblang, not here, because seven places in this project made
// this decision and two of them had already diverged while asserting they had not -- putting 1,005
// .cshtml files into a published benign denominator that no language-tagged rule could fire on. The
// invariant is now TestExtensionTableParity and TestHarnessScannerExtensionParity rather than a
// comment. See specs/008-rule-scope-policy/contracts/extension-table.md.
//
// Compound suffixes resolve to the last RECOGNISED one (weblang.Classify), so `shell.php.bak` is PHP.
// Whenever the final suffix is recognised the answer is identical to the previous `filepath.Ext`
// behaviour, which is what bounds this feature's change to names we did not previously understand.
func inferFileContext(path string) fileContext {
	if ctx, ok := fromWeblang[weblang.Classify(path)]; ok {
		return ctx
	}
	return ctxUnknown
}

// ruleCompatible decides whether a rule may fire on a given file.
//
// A rule that DECLARES a language is scoped to it, whoever wrote it. This used to be conditional on
// author == "ShellSight", which meant an analyst following RUNBOOK.md and writing
// `shellsight_lang = "php"` had it silently ignored — their rule fired on .php, .jsp, .aspx and .js
// alike. That is the exact shape that produced 23 of 24 .NET false positives from one over-broad
// ASP rule, and it left an operator no way to scope a custom rule short of putting the vendor's
// name in their own author field.
//
// The meta is opt-in, so this only ever narrows a rule its author chose to narrow: no rule in any
// foundation pack declares it, and rules without it stay permissive (below).
func ruleCompatible(filePath string, r yaraxRuleMatch) bool {
	return ruleAdmission(filePath, r, modeWidened, nil) != admitRefused
}

// scopeMode selects which admission rule is in force. INTERNAL ONLY -- there is no flag, no
// environment variable and no configuration key, because an IR responder should not have to know a
// mode exists in order to find a renamed webshell (spec 008 R9). Two callers need the other value:
// the test suite, which proves the widened behaviour preserves the old one, and cmd/measure, which
// must reproduce pre-008 published figures and record which behaviour produced any figure it
// publishes.
//
// modeWidened is the ZERO VALUE deliberately. A caller that forgets to set the mode gets the shipped
// behaviour, not the blindness this feature exists to remove.
type scopeMode int

const (
	modeWidened scopeMode = iota // shipped: an unrecognised name is decided by content
	modeLegacy                   // pre-008: an unrecognised name admits nothing. Tests and cmd/measure only.
)

// admission is why a rule was allowed to fire on a file, or that it was not.
type admission string

const (
	admitDeclared        admission = "declared"         // the file's language matches the declaration
	admitUndeclared      admission = "undeclared"       // the rule declares nothing (every third-party pack)
	admitUnknownLanguage admission = "unknown-language" // the name claimed nothing; content agreed
	admitRefused         admission = "refused"
)

// ruleAdmission decides whether a rule may fire on a file, and on what basis.
//
// A rule that DECLARES a language is scoped to it, whoever wrote it. This used to be conditional on
// author == "ShellSight", which meant an analyst following RUNBOOK.md and writing
// `shellsight_lang = "php"` had it silently ignored -- their rule fired on .php, .jsp, .aspx and .js
// alike. That is the exact shape that produced 23 of 24 .NET false positives from one over-broad
// ASP rule, and it left an operator no way to scope a custom rule short of putting the vendor's
// name in their own author field.
//
// WHAT SPEC 008 CHANGED. A declared language no longer means "only names ending this way". When the
// file's name claims NOTHING recognisable, the rule is admitted if the file's CONTENT is plausibly
// that language (the sign gate). Measured 2026-08-26, that is the difference between detecting a real
// JSP or ASP.NET webshell renamed `.txt` and reporting nothing at all on it.
//
// WHAT IT DELIBERATELY DID NOT CHANGE. A rule still never fires on a file whose language IS
// recognised and different. Cross-language matching was measured and declined, not deferred: on the
// .NET benign population it produced 24 findings and 0 true positives, and on JSP 6 true positives
// against 5 false positives. See specs/008-rule-scope-policy/research.md R3.
//
// The meta is opt-in, so this only ever narrows a rule its author chose to narrow: no rule in any
// foundation pack declares it, and rules without it stay permissive.
func ruleAdmission(filePath string, r yaraxRuleMatch, mode scopeMode, signs *signCache) admission {
	lang := strings.ToLower(strings.TrimSpace(r.Meta["shellsight_lang"]))
	if lang == "" {
		// `shellsight_cells` is read alongside `shellsight_lang` -- see ruleCells below. It does not
		// affect whether a rule fires; it is what makes the rule accountable to a technique cell.
		// No declared language: third-party packs carry no such meta and must keep firing everywhere.
		//
		// The two identifiers this branch used to hard-code -- asp_html_hybrid_webshell and
		// asp_jscript_server_webshell -- are gone from it: both now declare
		// `shellsight_lang = "asp-family"`, so the branch above returns first and this one was
		// unreachable for them. TestTheTwoFormerlyHardcodedRulesStayScoped keeps their scope pinned.
		return admitUndeclared
	}
	ctx := inferFileContext(filePath)
	if langCompatible(lang, ctx) {
		return admitDeclared
	}
	if ctx != ctxUnknown || mode == modeLegacy {
		// A recognised-but-different language, a non-web context, or the legacy behaviour.
		return admitRefused
	}
	// The name claims nothing. Let the content decide, for every contract language this declaration
	// covers -- `asp-family` asks about both halves.
	if signs == nil {
		return admitRefused
	}
	for _, l := range declaredWeblangs(lang) {
		if signs.admits(filePath, l) {
			return admitUnknownLanguage
		}
	}
	return admitRefused
}

// declaredWeblangs maps a `shellsight_lang` value onto the languages whose content sign may admit it.
// It mirrors langCompatible's grouping, and the two are checked against each other by
// TestDeclaredWeblangsMirrorsLangCompatible so they cannot drift.
func declaredWeblangs(lang string) []weblang.Lang {
	switch lang {
	case "php":
		return []weblang.Lang{weblang.PHP}
	case "jsp", "java":
		return []weblang.Lang{weblang.JSP}
	case "asp":
		return []weblang.Lang{weblang.ASP}
	case "aspx", "dotnet":
		return []weblang.Lang{weblang.ASPX}
	case "asp-family":
		return []weblang.Lang{weblang.ASP, weblang.ASPX}
	case "web-generic":
		return []weblang.Lang{weblang.PHP, weblang.JSP, weblang.ASP, weblang.ASPX}
	case "perl":
		return []weblang.Lang{weblang.Perl, weblang.CGI}
	case "python":
		return []weblang.Lang{weblang.Python, weblang.CGI}
	case "shtml":
		return []weblang.Lang{weblang.Shtml}
	default:
		// An unrecognised value declares nothing as far as scoping is concerned. Fail-OPEN is the
		// documented choice (contracts/rule-metadata.md): the closed direction turns a metadata typo
		// into a silently disabled detector. `langkit validate` reports the typo.
		return nil
	}
}

// langCompatible reports whether a declared language covers a RECOGNISED file context. It is the
// "declared" half of ruleAdmission and is unchanged from the pre-008 release -- which is what makes
// findings on recognised extensions byte-identical (SC-004).
func langCompatible(lang string, ctx fileContext) bool {
	switch lang {
	case "web-generic":
		return ctx == ctxPHP || ctx == ctxJSP || ctx == ctxASP || ctx == ctxASPX || ctx == ctxConfig
	case "php":
		return ctx == ctxPHP
	case "jsp", "java":
		return ctx == ctxJSP
	case "asp":
		return ctx == ctxASP
	case "aspx", "dotnet":
		return ctx == ctxASPX
	case "asp-family":
		return ctx == ctxASP || ctx == ctxASPX || ctx == ctxConfig
	case "perl":
		return ctx == ctxPerl || ctx == ctxCGI // .cgi may be Perl
	case "python":
		return ctx == ctxPython || ctx == ctxCGI // .cgi may be Python
	case "shtml":
		return ctx == ctxShtml
	default:
		// An unrecognised value. Fail-OPEN on every recognised context, documented in
		// contracts/rule-metadata.md: the closed direction turns a metadata typo into a silently
		// disabled detector, which this project has been bitten by twice. `langkit validate`
		// reports the typo so fail-open is not also fail-silent.
		return ctx != ctxUnknown
	}
}

// metaCells is the metadata field a ShellSight-authored rule uses to name the technique cells it
// detects: a comma-separated list of `<lang>/<axis>/<name>` ids resolving in that language's
// langkit/<lang>/taxonomy.yaml.
//
// WHY A RULE NAMES A CELL AT ALL. The repository's standing rule is that no detection method ships
// without a cited, verified prior-art review of how the field detects that technique and why the
// chosen method works. A cell is where that review lives. Without a link from the shipped rule back
// to the cell, the rule and its justification drift apart silently, and the check degenerates into
// a promise. `langkit validate` reads this field (V2) and fails any rule that declares a language
// and names no resolvable cell.
//
// It deliberately does NOT gate matching. A rule with no cell still fires; what it does not do is
// pass validation. Making it gate would mean a metadata omission silently disabling detection,
// which trades a documentation failure for a security one.
const metaCells = "shellsight_cells"

// ruleCells returns the technique cells a rule declares, or nil.
//
// Third-party packs carry no such meta and are not expected to: V2 narrows only what its author
// chose to narrow, exactly as `shellsight_lang` does.
func ruleCells(r yaraxRuleMatch) []string {
	raw := strings.TrimSpace(r.Meta[metaCells])
	if raw == "" {
		return nil
	}
	var out []string
	for _, part := range strings.Split(raw, ",") {
		if id := strings.TrimSpace(part); id != "" {
			out = append(out, id)
		}
	}
	return out
}
