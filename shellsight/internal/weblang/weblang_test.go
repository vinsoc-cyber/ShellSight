package weblang

import (
	"strings"
	"testing"
)

// Every extension resolves to exactly the language the table claims, in either case.
func TestClassifySimpleExtensions(t *testing.T) {
	for _, lang := range Languages() {
		for _, ext := range ExtensionsFor(lang) {
			for _, name := range []string{"shell" + ext, "SHELL" + strings.ToUpper(ext)} {
				if got := Classify(name); got != lang {
					t.Errorf("Classify(%q) = %q, want %q", name, got, lang)
				}
			}
		}
	}
}

func TestClassifyUnknown(t *testing.T) {
	for _, name := range []string{
		"shell.txt", "shell.bak", "shell.jpg", "shell.log", "shell.dat",
		"noextension", "", ".gitignore", "shell.",
	} {
		if got := Classify(name); got != Unknown {
			t.Errorf("Classify(%q) = %q, want Unknown", name, got)
		}
	}
}

// FR-005 / MITRE T1036.007: a compound suffix resolves to the language its inner extension names.
func TestClassifyCompoundSuffix(t *testing.T) {
	cases := map[string]Lang{
		"shell.php.bak":       PHP,
		"shell.php.suspected": PHP,
		"config.jsp.bak":      JSP,
		"x.aspx.old":          ASPX,
		"a.php.txt":           PHP,
		"deep.php.bak.old":    PHP,
		"SHELL.PHP.BAK":       PHP,
	}
	for name, want := range cases {
		if got := Classify(name); got != want {
			t.Errorf("Classify(%q) = %q, want %q", name, got, want)
		}
	}
}

// The walk is RIGHT-to-left, because the last suffix is what a server uses to pick a handler. This
// is the case that made the direction non-negotiable: Foo.class.php is a widespread PHP naming
// convention, and a left-to-right walk would call it a JVM artifact and drop it out of PHP
// classification -- a regression on a recognised extension (SC-004).
func TestClassifyLastRecognisedSuffixWins(t *testing.T) {
	cases := map[string]Lang{
		"Foo.class.php": PHP, // the case that killed left-to-right
		"Bar.inc.php":   PHP,
		"a.php.jsp":     JSP, // served as JSP; no contradiction rule needed
		"x.aspx.php":    PHP,
		"y.pl.py":       Python,
	}
	for name, want := range cases {
		if got := Classify(name); got != want {
			t.Errorf("Classify(%q) = %q, want %q", name, got, want)
		}
	}
}

// Whenever the final suffix IS recognised, Classify must agree with what filepath.Ext would have
// given -- that equality is what bounds this feature's behaviour change to unrecognised names, and
// it is the mechanical half of SC-004.
func TestClassifyAgreesWithFilepathExtWhenRecognised(t *testing.T) {
	for _, lang := range Languages() {
		for _, ext := range ExtensionsFor(lang) {
			for _, name := range []string{"a" + ext, "a.class" + ext, "a.b.c" + ext} {
				if got := Classify(name); got != lang {
					t.Errorf("Classify(%q) = %q, want %q (final suffix %s)", name, got, lang, ext)
				}
			}
		}
	}
}

// Compiled and archived Java is the bytecode scanner's business, never the JSP rule layer's.
// Folding these into JSP would fire ASP.NET and JSP source rules on .jar files.
func TestJVMArtifactsAreNotJSP(t *testing.T) {
	for _, name := range []string{"a.jar", "b.war", "c.class", "d.java"} {
		if got := Classify(name); got != JVMArtifact {
			t.Errorf("Classify(%q) = %q, want JVMArtifact", name, got)
		}
	}
	for _, name := range []string{"a.jsp", "b.jspx", "c.jspf", "d.jsw", "e.jsv", "f.jhtml"} {
		if got := Classify(name); got != JSP {
			t.Errorf("Classify(%q) = %q, want JSP", name, got)
		}
	}
}

// Markup and client-side assets are Static, deliberately not Unknown: benign web content lives here
// in volume, and admitting every language's detectors to it is a decision this feature does not take.
func TestStaticIsNotUnknown(t *testing.T) {
	for _, name := range []string{"index.html", "a.htm", "app.js", "site.css"} {
		if got := Classify(name); got != Static {
			t.Errorf("Classify(%q) = %q, want Static", name, got)
		}
	}
}

// The FR-015 additions must be present, or the extension-list half of the feature has silently
// regressed. Named explicitly rather than counted, so a deletion cannot pass by replacement.
func TestFR015AdditionsPresent(t *testing.T) {
	want := map[string]Lang{
		".phar": PHP,
		".jsw":  JSP, ".jsv": JSP, ".jhtml": JSP,
		".asax": ASPX, ".cshtml": ASPX, ".vbhtml": ASPX, ".master": ASPX, ".svc": ASPX,
		".cdx": ASP,
	}
	for ext, lang := range want {
		if got := Classify("x" + ext); got != lang {
			t.Errorf("FR-015: Classify(x%s) = %q, want %q", ext, got, lang)
		}
	}
}

func TestIsWebSource(t *testing.T) {
	for _, l := range []Lang{PHP, JSP, ASP, ASPX, Perl, Python, CGI, Shtml} {
		if !IsWebSource(l) {
			t.Errorf("IsWebSource(%q) = false, want true", l)
		}
	}
	for _, l := range []Lang{Config, Static, JVMArtifact, Unknown} {
		if IsWebSource(l) {
			t.Errorf("IsWebSource(%q) = true, want false", l)
		}
	}
}

// ExtensionsFor must hand back a copy: a consumer that mutated the table would reintroduce exactly
// the divergence this package exists to close.
func TestExtensionsForReturnsCopy(t *testing.T) {
	got := ExtensionsFor(PHP)
	if len(got) == 0 {
		t.Fatal("no PHP extensions")
	}
	got[0] = ".mutated"
	if Classify("x.mutated") != Unknown {
		t.Error("mutating the returned slice changed the table")
	}
	if Classify("x.php") != PHP {
		t.Error("mutating the returned slice broke PHP classification")
	}
}

// Only the FINAL suffix may name a non-source context. Walking back past an unrecognised suffix
// finds renamed webshells, and that threat is about server-parsed SOURCE. `.config` is a whole-name
// convention, so accepting it from an inner suffix turns every JavaScript project's tooling into
// Config -- a context `asp-family` and `web-generic` rules are scoped to include.
//
// Measured over 37,614 corpus files on 2026-08-26, the unrestricted walk mis-classified exactly
// three real files, all of them here.
func TestInnerSuffixCannotNameANonSourceContext(t *testing.T) {
	for _, name := range []string{
		"jest.config.cjs", "webpack.config.cjs", "babel.config.json", // the three measured
		"tsconfig.build.json", "readme.html.txt", "app.js.map", "lib.jar.bak",
	} {
		if got := Classify(name); got != Unknown {
			t.Errorf("Classify(%q) = %q, want Unknown (a non-source context may only be named by "+
				"the final suffix)", name, got)
		}
	}
	// The final suffix still names them, as it always did.
	for name, want := range map[string]Lang{
		"web.config": Config, "index.html": Static, "app.jar": JVMArtifact,
	} {
		if got := Classify(name); got != want {
			t.Errorf("Classify(%q) = %q, want %q", name, got, want)
		}
	}
	// And a source language from an inner suffix is still accepted -- that is the feature.
	if got := Classify("shell.php.bak"); got != PHP {
		t.Errorf("Classify(shell.php.bak) = %q, want PHP", got)
	}
}
