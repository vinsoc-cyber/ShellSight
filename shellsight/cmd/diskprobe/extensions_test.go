package main

import (
	"testing"

	"shellsight/internal/weblang"
)

// TestExtensionTableParity asserts the gate's context enumeration covers the shared table totally.
//
// The failure this guards is silent: a language added to internal/weblang but not mapped here falls
// through `fromWeblang` to ctxUnknown, and every rule scoped to it stops firing -- a detector
// disabled by an omission rather than a decision. That is the same shape as the two defects this
// feature exists to fix, so it gets a test rather than a convention.
func TestExtensionTableParity(t *testing.T) {
	for _, lang := range weblang.Languages() {
		ctx, ok := fromWeblang[lang]
		if !ok {
			t.Errorf("weblang defines %q but fromWeblang does not map it -- every rule scoped to "+
				"that language would silently stop firing", lang)
			continue
		}
		if ctx == ctxUnknown {
			t.Errorf("weblang %q maps to ctxUnknown; a named language must have its own context", lang)
		}
		for _, ext := range weblang.ExtensionsFor(lang) {
			if got := inferFileContext("sample" + ext); got != ctx {
				t.Errorf("inferFileContext(sample%s) = %q, want %q (weblang says %q)",
					ext, got, ctx, lang)
			}
		}
	}
}

// The reverse: no context in this package is unreachable from the table. An orphan context is a
// branch in langCompatible that can never be taken, which reads as coverage and is not.
func TestEveryContextIsReachable(t *testing.T) {
	reachable := map[fileContext]bool{ctxUnknown: true}
	for _, ctx := range fromWeblang {
		reachable[ctx] = true
	}
	for _, ctx := range []fileContext{
		ctxPHP, ctxJSP, ctxASP, ctxASPX, ctxPerl, ctxPython, ctxShtml, ctxCGI,
		ctxConfig, ctxStatic, ctxJVM, ctxUnknown,
	} {
		if !reachable[ctx] {
			t.Errorf("context %q is declared but no extension produces it", ctx)
		}
	}
}

// The FR-015 additions must reach the gate, not merely exist in the table. Before this feature these
// nine names produced ctxUnknown and no language-tagged rule could fire on them -- which is why a
// real ASP.NET webshell copied to `.cshtml` or `.asax` scored 0 in the 2026-08-26 baseline.
func TestFR015ExtensionsReachTheGate(t *testing.T) {
	want := map[string]fileContext{
		"x.phar": ctxPHP,
		"x.jsw":  ctxJSP, "x.jsv": ctxJSP, "x.jhtml": ctxJSP,
		"x.asax": ctxASPX, "x.cshtml": ctxASPX, "x.vbhtml": ctxASPX,
		"x.master": ctxASPX, "x.svc": ctxASPX,
		"x.cdx": ctxASP,
	}
	for name, ctx := range want {
		if got := inferFileContext(name); got != ctx {
			t.Errorf("FR-015: inferFileContext(%s) = %q, want %q", name, got, ctx)
		}
	}
}

// Compiled and archived Java gets its own context so the rule layer can refuse it explicitly. Before
// the shared table these fell to ctxUnknown, which refused them too -- the behaviour is unchanged,
// the reason is now stated rather than incidental.
func TestJVMArtifactsGetTheirOwnContext(t *testing.T) {
	for _, name := range []string{"a.jar", "b.war", "c.class", "d.java"} {
		if got := inferFileContext(name); got != ctxJVM {
			t.Errorf("inferFileContext(%s) = %q, want ctxJVM", name, got)
		}
	}
	// And no language-declaring rule may fire on them, exactly as before.
	for _, lang := range []string{"php", "jsp", "asp", "aspx", "perl", "python", "shtml", "asp-family", "web-generic"} {
		if langCompatible(lang, ctxJVM) {
			t.Errorf("rule declaring %q is compatible with a JVM artifact; it must not be", lang)
		}
	}
}
