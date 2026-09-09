// Package weblang is the single definition of which file extensions identify which web language.
//
// WHY THIS PACKAGE EXISTS. Seven places in this project decided a file's language from its name, each
// holding its own list: the tagged rule layer, the PHP taint pass, the Perl/Python taint pass, the
// Classic ASP taint pass, the Java bytecode scanner, the deobfuscation passes, and -- outside the
// scanner entirely -- the measurement harness's sample enumeration. Two of them had already diverged
// while asserting they had not: `cmd/measure`'s list carried a comment reading "Mirrors
// inferFileContext in cmd/diskprobe/rulegate.go. Keep the two in step", and on 2026-08-26 it counted
// .phar, .jsw, .jsv, .jhtml, .asax, .cshtml and .cdx as samples that the scanner refused to fire any
// language-tagged rule on.
//
// That is not a tidiness problem. Those files sit in published recall and false-positive DENOMINATORS
// while no language-specific detector can fire on them -- measured exposure, 1,005 .cshtml files in
// dotnet/benign, which is exactly the gap between the published .NET benign basis of 1,581 and the
// strict ASP.NET-family basis of 576 that the 2026-08-07 run-set flagged without finding its cause.
//
// A comment cannot hold that invariant. A test can, so the lists live here and TestExtensionParity
// fails when any consumer drifts. See specs/008-rule-scope-policy/contracts/extension-table.md.
//
// This package deliberately holds no detection logic. It answers one question -- "what language does
// this NAME claim?" -- and says Unknown when the name claims nothing. Deciding what an Unknown file
// actually is, from its content, belongs to the caller.
package weblang

import (
	"path/filepath"
	"sort"
	"strings"
)

// Lang is what a filename claims a file is. Unknown means the name claims nothing, which is a
// positive statement about the name and NOT a statement about the bytes.
type Lang string

const (
	PHP    Lang = "php"
	JSP    Lang = "jsp"
	ASP    Lang = "asp"
	ASPX   Lang = "aspx"
	Perl   Lang = "perl"
	Python Lang = "python"
	// CGI is its own language rather than a Perl or Python alias: a CGI script's language is not
	// fixed by its name, both languages' rules fire on it, and it carries its own measurement
	// denominator.
	CGI   Lang = "cgi"
	Shtml Lang = "shtml"
	// Config is web.config and friends -- an ASP-family surface, not a language of its own, but it
	// needs a context because `asp-family` and `web-generic` rules are scoped to include it.
	Config Lang = "config"
	// Static is markup and client-side assets. Deliberately NOT Unknown: benign web content lives
	// here in volume, so admitting every language's detectors to it is a separate decision with a
	// different false-positive profile, and this feature does not take it.
	Static Lang = "static"
	// JVMArtifact is compiled or archived Java -- the bytecode scanner's business, never the JSP
	// rule layer's. Folding these into JSP would fire ASP.NET and JSP source rules on .jar files.
	JVMArtifact Lang = "jvm"
	Unknown     Lang = "unknown"
)

// extensions maps each language to the extensions that identify it. Every entry is lower-case and
// carries its leading dot.
//
// ROWS MARKED (008) WERE ADDED BY specs/008-rule-scope-policy (FR-015). They were not invented: each
// was already counted as a sample for that language by the measurement harness, so they were already
// in published denominators while no rule could fire on them. `.cshtml` and `.asax` are further
// corroborated by the ASP.NET taxonomy, which carries aspx/surface/cshtml-razor and
// aspx/surface/asax-application as cited technique cells -- the taxonomy recognised those surfaces
// before this list did.
//
// Rows with no corpus exposure (.master, .svc, .vbhtml, .jsw, .jsv, .jhtml, .cdx) ship as REASONED
// structural coverage derived from the server's parsing behaviour, and are recorded as unmeasured
// rather than as measured wins -- see docs/measurements/2026-08-26-rule-scope-policy/02-fpr-web.md.
var extensions = map[Lang][]string{
	PHP: {".php", ".php3", ".php4", ".php5", ".php7", ".phtml", ".pht", ".inc",
		".phar"}, // (008) the tool ships php_phar_agent_webshell, which could not fire on a PHAR
	JSP: {".jsp", ".jspx", ".jspf",
		".jsw", ".jsv", ".jhtml"}, // (008) Tomcat-servable; already in the bytecode scanner's list
	ASP: {".asp", ".asa", ".cer",
		".cdx"}, // (008)
	ASPX: {".aspx", ".ascx", ".ashx", ".asmx",
		".asax", ".cshtml", ".vbhtml", ".master", ".svc"}, // (008)
	Perl:        {".pl", ".pm", ".plx", ".pl6"},
	Python:      {".py", ".pyw", ".py3", ".pyi", ".pyp", ".pyx"},
	CGI:         {".cgi", ".fcgi"},
	Shtml:       {".shtml", ".shtm", ".stm"},
	Config:      {".config"},
	Static:      {".html", ".htm", ".js", ".css"},
	JVMArtifact: {".java", ".class", ".jar", ".war"},
}

// byExt is the reverse index, built once. A duplicate extension across two languages would be a
// silent mis-classification, so init panics rather than letting one win by map order.
var byExt = func() map[string]Lang {
	m := make(map[string]Lang, 64)
	for lang, exts := range extensions {
		for _, e := range exts {
			if prior, dup := m[e]; dup {
				panic("weblang: extension " + e + " claimed by both " + string(prior) + " and " + string(lang))
			}
			m[e] = lang
		}
	}
	return m
}()

// Classify reports what a path's NAME claims the file is.
//
// COMPOUND SUFFIXES ARE WALKED (spec 008 FR-005). `shell.php.bak` is PHP, not Unknown: `filepath.Ext`
// returns only ".bak", and reading only the last suffix is what let a renamed webshell drop from
// `confirmed` to `likely-malicious` in the 2026-08-26 baseline. MITRE ATT&CK T1036.007 (Masquerading:
// Double File Extension, retrieved 2026-08-26) names this as an adversary technique; its write-up
// covers the user-execution case where the SECOND extension is the true type, and the webroot case is
// the mirror image -- the FIRST extension is the served type, and the trailing one is camouflage.
//
// THE WALK IS RIGHT-TO-LEFT, and that direction is load-bearing. The last suffix is the one a server
// uses to pick a handler, so it must win when it is recognised; earlier suffixes are consulted only
// when the trailing one means nothing to us.
//
// Left-to-right was tried first and is WRONG. `Foo.class.php` is an extremely common PHP naming
// convention, and a left-to-right walk hits `.class`, calls the file a JVM artifact, and either
// mis-routes it or -- if contradictions are treated as unknown -- drops it out of PHP classification
// entirely. That would remove detection from a widespread real naming pattern, which is a regression
// on a RECOGNISED extension and would breach SC-004. Right-to-left also removes the need for a
// contradiction rule: `a.php.jsp` is served as JSP, so JSP is the honest answer.
//
// Consequence worth stating: whenever the final suffix is recognised, this returns exactly what
// `filepath.Ext` would have. The behaviour change is confined to names whose final suffix we do not
// recognise, which is precisely the renamed-webshell case this feature exists for.
// ONLY THE FINAL SUFFIX MAY NAME A NON-SOURCE CONTEXT. Walking back past an unrecognised suffix is
// how a renamed webshell is found, and that threat applies to server-parsed SOURCE languages. It does
// not apply to Config, Static or JVMArtifact, and admitting them from an inner suffix mis-classifies
// ordinary files: `.config` is a whole-name convention (`web.config`), so a right-to-left walk that
// accepts it anywhere turns `jest.config.cjs` and `babel.config.json` into Config -- a context that
// `asp-family` and `web-generic` rules are scoped to include.
//
// That is not hypothetical. Measured over 37,614 corpus files on 2026-08-26, accepting any language
// from an inner suffix mis-classified exactly three: `jest.config.cjs`, `webpack.config.cjs` and
// `babel.config.json`. Three files is small; three files newly eligible for ASP-family rules in every
// JavaScript project on earth is not.
func Classify(path string) Lang {
	base := strings.ToLower(filepath.Base(path))
	// A dotfile's leading dot is part of the name, not a suffix separator.
	parts := strings.Split(strings.TrimLeft(base, "."), ".")
	for i := len(parts) - 1; i >= 1; i-- {
		lang, ok := byExt["."+parts[i]]
		if !ok {
			continue
		}
		if i == len(parts)-1 || IsWebSource(lang) {
			return lang
		}
		// A non-source context named by an inner suffix: keep looking rather than accept it.
	}
	return Unknown
}

// ExtensionsFor returns the extensions that identify lang, sorted. The returned slice is a copy:
// a consumer that mutated the table would reintroduce exactly the divergence this package closes.
func ExtensionsFor(lang Lang) []string {
	src := extensions[lang]
	out := make([]string, len(src))
	copy(out, src)
	sort.Strings(out)
	return out
}

// Languages returns every language the table defines, sorted, including the non-source contexts
// (Config, Static, JVMArtifact). Used by the parity tests.
func Languages() []Lang {
	out := make([]Lang, 0, len(extensions))
	for l := range extensions {
		out = append(out, l)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// IsWebSource reports whether lang is a server-parsed web source language -- the set the
// deobfuscation passes run over. Config, Static, JVMArtifact and Unknown are not.
func IsWebSource(lang Lang) bool {
	switch lang {
	case PHP, JSP, ASP, ASPX, Perl, Python, CGI, Shtml:
		return true
	}
	return false
}
