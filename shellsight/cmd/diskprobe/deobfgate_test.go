package main

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"shellsight/internal/finding"
	"shellsight/internal/javadisk"
)

// FR-003: the widened behaviour applies at EVERY extension gate, not only the rule layer. The
// deobfuscation mirror is one of the seven the spec enumerates, and it is the one that matters most
// for an obfuscated shell: the literal-anchored rules never see the payload unless a decoded layer
// is written for the file.
//
// Measured 2026-08-26 on the 14 real samples in curated/disk/php/obfuscated, staged twice under
// `.php` and `.txt`: with this gate narrow, nine rule firings present on the `.php` copy were absent
// on the byte-identical `.txt` copy, and two samples dropped from 75 to 70 -- including the
// unscoped third-party rules SIGNATURE_BASE_WEBSHELL_PHP_Generic_Eval and DodgyPhp, which fire on
// every file whatever its name and were lost only because no decoded layer existed to fire on.
//
// This is exactly the failure FR-003 names: a widened rule layer over a narrow decoder reports a
// file as examined by a detector that never read it.
func TestDecodedMirrorAdmitsAFileWhoseNameClaimsNothing(t *testing.T) {
	payload := `<?php system($_GET["c"]); ?>`
	body := `<?php eval(base64_decode("` + base64.StdEncoding.EncodeToString([]byte(payload)) + `")); ?>`

	for _, name := range []string{"shell.php", "shell.txt", "shell", "shell.jpg"} {
		t.Run(name, func(t *testing.T) {
			web := t.TempDir()
			if err := os.WriteFile(filepath.Join(web, name), []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}
			_, n, err := buildDecodedMirror(enumeratedPaths(web), t.TempDir(), newSignCache())
			if err != nil {
				t.Fatal(err)
			}
			if n == 0 {
				t.Fatalf("%s: no decoded layer written; the deobfuscation gate is still narrow", name)
			}
		})
	}
}

// A file whose name claims nothing AND whose content is not a web source language must stay out of
// the mirror. The sign gate is what keeps the widening from turning every binary in a webroot into
// a decode attempt.
func TestDecodedMirrorStillRefusesNonWebContent(t *testing.T) {
	web := t.TempDir()
	// A PNG header followed by bytes that would otherwise trip the hex-run pre-filter. No language
	// sign matches, so nothing here is a web source file under any name.
	blob := append([]byte("\x89PNG\r\n\x1a\n"), []byte(strings.Repeat(`\x41`, 40))...)
	if err := os.WriteFile(filepath.Join(web, "logo.dat"), blob, 0o644); err != nil {
		t.Fatal(err)
	}
	_, n, err := buildDecodedMirror(enumeratedPaths(web), t.TempDir(), newSignCache())
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("wrote %d decoded layer(s) for non-web content; the sign gate is not holding", n)
	}
}

// The mirror file carries the ORIGIN's language context, because the rule gate runs on the mirror
// path before the finding is rewritten back. For a name that claims nothing there IS no origin
// extension to carry, and the pre-008 fallback was a hardcoded `.php` -- harmless while unknown-named
// files never reached the mirror at all, and load-bearing the moment they do: it would make every
// jsp/asp/aspx-scoped rule ineligible on the decoded body of a renamed JSP or ASP.NET shell, so the
// widening would buy back PHP only.
//
// The sign already knows what the content is. The mirror must use it.
func TestMirrorLanguageFollowsTheSignWhenTheNameClaimsNothing(t *testing.T) {
	hexRun := `\x52\x75\x6e\x74\x69\x6d\x65\x2e\x67\x65\x74\x52\x75\x6e\x74\x69\x6d\x65`
	cases := []struct {
		name string
		body string
		want fileContext
	}{
		{"jsp", `<%@ page import="java.io.*" %><% String p = "` + hexRun + `"; %>`, ctxJSP},
		{"php", `<?php $p = "` + hexRun + `"; eval($p); ?>`, ctxPHP},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			web := t.TempDir()
			if err := os.WriteFile(filepath.Join(web, "renamed.txt"), []byte(c.body), 0o644); err != nil {
				t.Fatal(err)
			}
			mirror := t.TempDir()
			originOf, n, err := buildDecodedMirror(enumeratedPaths(web), mirror, newSignCache())
			if err != nil {
				t.Fatal(err)
			}
			if n == 0 {
				t.Fatalf("no decoded layer written for a renamed %s shell", c.name)
			}
			for mp := range originOf {
				if got := inferFileContext(mp); got != c.want {
					t.Errorf("mirror %s resolves to %q, want %q — %s-scoped rules cannot fire on the decoded body",
						filepath.Base(mp), got, c.want, c.want)
				}
			}
		})
	}
}

// The phptaint RESOLVED-layers mirror is the same gate again, one level down, and it was the last
// one still narrow: after the decode mirror above was widened, exactly one rule firing of the
// original nine was still lost on a renamed sample --
// `php_eval_concat_request_webshell` on curated/disk/php/obfuscated/o_a4e2cc8adc33e216, which fires
// only on a resolved layer. Resolved layers are PHP-only by construction, so the sign consulted here
// is PHP's, but the admission rule must be the one every other gate uses.
func TestResolvedLayerMirrorAdmitsAFileWhoseNameClaimsNothing(t *testing.T) {
	// Variable-function dispatch on a request superglobal: the shape ResolvedLayers rewrites to a
	// literal sink so the literal-anchored rules can see it.
	body := `<?php $f = "sys" . "tem"; $f($_GET["c"]); ?>`

	counts := map[string]int{}
	for _, name := range []string{"shell.php", "shell.txt"} {
		web := t.TempDir()
		if err := os.WriteFile(filepath.Join(web, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		_, n, err := buildDecodedMirror(enumeratedPaths(web), t.TempDir(), newSignCache())
		if err != nil {
			t.Fatal(err)
		}
		counts[name] = n
	}
	if counts["shell.php"] == 0 {
		t.Skip("fixture produced no resolved layer under its native name; nothing to compare")
	}
	if counts["shell.txt"] != counts["shell.php"] {
		t.Errorf("renamed copy got %d mirror layer(s), native name got %d — the resolved-layer gate is still narrow",
			counts["shell.txt"], counts["shell.php"])
	}
}

// The Java bytecode scanner is the fifth of the seven gates the spec enumerates, and FR-003 names it
// explicitly: "a widened rule layer over narrow taint and BYTECODE passes reports a file as examined
// by a detector that never read it."
//
// Measured 2026-08-26 on all 246 real samples in curated/disk/java/malicious, staged under their
// native name and again as `.txt`: 114 javadisk findings present under the native name were absent on
// the byte-identical renamed copy — 82 `javadisk:request-exec`, 17 `file-drop-on-request`,
// 8 `reverse-shell-literal`, 4 `dynamic-classload`, 2 `scriptengine-eval`, 1 `deserialization-jndi`.
func TestJavaScannerAdmitsARenamedJSPShell(t *testing.T) {
	body := `<%@ page import="java.io.*" %>` +
		`<% Runtime.getRuntime().exec(request.getParameter("c")); %>`

	count := func(name string) int {
		root := t.TempDir()
		if err := os.WriteFile(filepath.Join(root, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		scan := javadiskScan(context.Background(), []string{root}, "host",
			javadisk.DefaultOptions(), false, newSignCache())
		return len(scan.Findings)
	}

	native := count("shell.jsp")
	if native == 0 {
		t.Fatal("fixture produced no Java finding under its native name; the test proves nothing")
	}
	for _, name := range []string{"shell.txt", "config.bak", "shell"} {
		if got := count(name); got != native {
			t.Errorf("%s: %d Java finding(s), want %d — the bytecode gate is still narrow", name, got, native)
		}
	}
}

// The Java pass must not be handed files that are not Java at all. The sign is what separates a
// renamed JSP shell from every other unnamed file in a webroot.
func TestJavaScannerRefusesNonJavaContentUnderAnUnknownName(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "notes.dat"),
		[]byte("plain prose about a runtime exec of a process, with no code in it at all."), 0o644); err != nil {
		t.Fatal(err)
	}
	scan := javadiskScan(context.Background(), []string{root}, "host",
		javadisk.DefaultOptions(), false, newSignCache())
	if len(scan.Findings) != 0 {
		t.Errorf("%d Java finding(s) on non-Java content; the sign gate is not holding", len(scan.Findings))
	}
}

// The coverage reason must account for its own total. Measured 2026-08-26 on the T046 non-web
// population, the shipped text read:
//
//	"23367 entr(ies) not examined: 0 non-regular, 0 unreadable, 0 oversize"
//
// -- a total contradicted by every term it enumerates, because the reason was never extended when
// the fourth counter was added. A responder reading that cannot tell whether 23,367 files were
// skipped for a reason the report forgot to name or whether the total is simply wrong.
func TestCoverageReasonAccountsForItsOwnTotal(t *testing.T) {
	s := finding.ScanSkips{NonRegular: 1, Unreadable: 2, OversizeSkipped: 3, NoLanguageDetector: 23367}
	reason := skipReason(s)
	if !strings.Contains(reason, "23373") {
		t.Errorf("reason %q does not carry the total %d", reason, s.Total())
	}
	for _, want := range []string{"1 non-regular", "2 unreadable", "3 oversize", "23367 "} {
		if !strings.Contains(reason, want) {
			t.Errorf("reason %q omits %q", reason, want)
		}
	}
	if !strings.Contains(reason, "language") {
		t.Errorf("reason %q does not name the no-language-detector counter", reason)
	}
}

// FR-005 resolves a compound suffix, so `shell.jsp.bak` IS JSP to every gate in this package. It was
// not JSP to `internal/javadisk`, which keys on the literal path suffix (`isJSPPath`), so a
// compound-named JSP reached the Java analyser and was analysed as plain Java: no scriptlet
// stripping, no JSP analyzer state, and two finding rules gated off.
//
// Measured 2026-08-28 over all 246 real java/malicious samples staged under four alternative names
// (T042): the compound scheme dropped the confirmed band from 85/246 to 3/246 -- 82 samples losing a
// tier. The renamed-to-.txt and no-extension schemes did not, because those are ctxUnknown and
// already route through analyzeAsJSPSource's synthetic name.
//
// So the COMPOUND name was worse than no name at all, which is the opposite of what FR-005 intends.
func TestCompoundNamedJSPIsAnalysedAsJSPNotAsJava(t *testing.T) {
	body := `<%@ page import="java.io.*" %>` +
		`<% Runtime.getRuntime().exec(request.getParameter("c")); %>`
	count := func(name string) int {
		root := t.TempDir()
		if err := os.WriteFile(filepath.Join(root, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return len(javadiskScan(context.Background(), []string{root}, "host",
			javadisk.DefaultOptions(), false, newSignCache()).Findings)
	}
	native := count("shell.jsp")
	if native == 0 {
		t.Fatal("fixture produced no Java finding under its native name; the test proves nothing")
	}
	for _, name := range []string{"shell.jsp.bak", "shell.jspx.old", "config.jsp.txt"} {
		if got := count(name); got != native {
			t.Errorf("%s: %d Java finding(s), want %d — a compound-named JSP is not reaching the "+
				"analyser as JSP", name, got, native)
		}
	}
}

// The same defect one layer over: `mirrorExtFor` carries the ORIGIN's language onto the mirror file
// so the rule gate can scope correctly, and for a compound name it carried the literal trailing
// suffix -- `.bak` -- which names no language at all.
func TestMirrorExtCarriesTheResolvedLanguageNotTheTrailingSuffix(t *testing.T) {
	for _, c := range []struct {
		origin string
		want   fileContext
	}{
		{"shell.jsp.bak", ctxJSP},
		{"shell.php.bak", ctxPHP},
		{"shell.aspx.old", ctxASPX},
		{"shell.jsp", ctxJSP},
		{"shell.php", ctxPHP},
	} {
		got := inferFileContext("layer_0_base64" + mirrorExtFor(c.origin, nil))
		if got != c.want {
			t.Errorf("%s: mirror ext %q resolves to %q, want %q",
				c.origin, mirrorExtFor(c.origin, nil), got, c.want)
		}
	}
}
