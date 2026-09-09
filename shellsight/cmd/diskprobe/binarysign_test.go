package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"shellsight/internal/weblang"
)

// R10. The JSP sign's first alternative is the bare two-byte string `<%` and the PHP sign's is `<?`
// plus one word character. In compressed data those pairs occur by chance, so fonts and images were
// admitted as JSP and PHP and then put through AST parsing, the deobfuscation mirror and the Java
// analyser.
//
// Measured 2026-08-26 on the WordPress benign webroot: 123 of 315 .woff2, 54 of 85 .jpg, 35 of 56
// .webp and 25 of 161 .png admitted — 286 binaries costing 101 s of a 128.6 s run, and 3 of the 19
// new false positives in 03-fpr-nonweb.md.
func TestBinaryContentIsAdmittedToNoLanguage(t *testing.T) {
	cases := []struct {
		name string
		data []byte
	}{
		// A PNG header, then the two-byte coincidence past it.
		{"png with a chance <%", append([]byte("\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"),
			[]byte("\x00\x01<%\x00\x02rest of the compressed stream")...)},
		// woff2 carries its NUL bytes in the header, exactly like the real ones measured.
		{"woff2 with a chance <?p", append([]byte("wOF2\x00\x01\x00\x00\x00\x00"),
			[]byte("\xff<?ph\x00 one byte short of the php opener")...)},
		{"jpeg with both", append([]byte("\xff\xd8\xff\xe0\x00\x10JFIF\x00"),
			[]byte("<% <?x \xde\xad\xbe\xef")...)},
		// A NUL anywhere in the first 8000 bytes is enough, per git's buffer_is_binary.
		{"nul at the very end of the window",
			append(append([]byte("<?x system($_GET['c']); "), bytes.Repeat([]byte("A"), 7000)...),
				0x00)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := signsFor(c.data); len(got) != 0 {
				t.Errorf("binary content admitted to %v; it must be admitted to nothing", got)
			}
		})
	}
}

// The refusal must be bounded the way git bounds it, or the test itself becomes the cost it removes:
// a NUL past the first 8,000 bytes does not make a file binary.
func TestNulPastTheWindowDoesNotMakeAFileBinary(t *testing.T) {
	data := append([]byte("<?x system($_GET['c']); "), bytes.Repeat([]byte("A"), 9000)...)
	data = append(data, 0x00)
	got := signsFor(data)
	found := false
	for _, l := range got {
		if l == weblang.PHP {
			found = true
		}
	}
	if !found {
		t.Errorf("a text file with a NUL at offset >8000 was refused; got %v, want PHP admitted", got)
	}
}

// Real text must keep being admitted. This is the control that separates "refuses binary" from
// "refuses everything".
func TestTextContentIsStillAdmitted(t *testing.T) {
	cases := []struct {
		body string
		want weblang.Lang
	}{
		{`<?php system($_GET["c"]); ?>`, weblang.PHP},
		{`<% Runtime.getRuntime().exec(request.getParameter("c")); %>`, weblang.JSP},
		{`<%@ Page Language="C#" %><% Response.Write(Request["c"]); %>`, weblang.ASP},
		{"#!/usr/bin/perl\nuse strict;\nmy $x = 1;\n", weblang.Perl},
		{"#!/usr/bin/python\nimport os\ndef f():\n pass\n", weblang.Python},
		{`<!--#exec cmd="id" -->`, weblang.Shtml},
	}
	for _, c := range cases {
		got := signsFor([]byte(c.body))
		found := false
		for _, l := range got {
			if l == c.want {
				found = true
			}
		}
		if !found {
			t.Errorf("%q: want %s admitted, got %v", c.body[:min(28, len(c.body))], c.want, got)
		}
	}
}

// End to end through the cache, on a file, which is how every caller reaches it.
//
// These fixtures deliberately carry only CHANCE markers. Several originally used `<?php`, written
// before the polyglot exception existed; once that landed, `<?php` in a font became the very thing
// the exception is for, so the fixtures had to become what they always meant to be -- binary whose
// only resemblance to a language is a short coincidence. `<?x` still matches the PHP sign's `<\?\w`
// branch, so the refusal being tested is R10's and not a sign miss.
func TestSignCacheRefusesABinaryFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "logo.woff2")
	if err := os.WriteFile(p, append([]byte("wOF2\x00\x01\x00\x00"), []byte("<%<?x\x00")...), 0o644); err != nil {
		t.Fatal(err)
	}
	c := newSignCache()
	for _, l := range []weblang.Lang{weblang.PHP, weblang.JSP, weblang.ASP, weblang.ASPX} {
		if c.admits(p, l) {
			t.Errorf("binary file admitted to %s", l)
		}
	}
}

// The header must carry R10's citations, because this project's standing rule is that the method,
// not just the code, is what has to be justified.
func TestBinaryRefusalCarriesItsCitations(t *testing.T) {
	src, err := os.ReadFile("langsign.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"buffer_is_binary", "8000", "grep", "clamav"} {
		if !strings.Contains(strings.ToLower(string(src)), strings.ToLower(want)) {
			t.Errorf("langsign.go does not cite %q", want)
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// R10's binary refusal collides with A3 unless it makes an exception, and the collision is real.
//
// A3 established that the sign must sweep the WHOLE bounded file because "appending a shell to the
// tail of a legitimate file is a standard infection pattern". A flat NUL test contradicts that for
// the most common form of it: a webshell appended to a JPEG, GIF or PNG. The image header carries
// NULs, so a flat test refuses the file without ever looking at the shell.
//
// This is not hypothetical. Sweeping 41,797 corpus files on 2026-08-27 found **88** real malicious
// samples that are binary in their first 8 KB and carry an unambiguous language opener: 33 JPEG,
// 13 GIF, 6 PNG, 6 ZIP and 30 other binary containers.
//
// The exception is safe because the markers are LONG. `<%` is two bytes and appears by chance in
// roughly 78% of 100 KB compressed files; `<?php` is five, which is about one chance occurrence per
// 10^12 bytes. Measured: of the 7,504 binary files in the T046 benign population, **0** carry a
// strong marker, and of 1,533 unknown-extension files in the WordPress webroot, **0** do.
func TestBinaryPolyglotWithAStrongMarkerIsStillAdmitted(t *testing.T) {
	cases := []struct {
		name   string
		header []byte
		tail   string
		want   weblang.Lang
	}{
		{"php appended to a jpeg", []byte("\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x02\x03"),
			`<?php system($_GET["c"]); ?>`, weblang.PHP},
		{"php appended to a gif", []byte("GIF89a\x00\x01\x00\x01\x00\x00"),
			`<?php eval($_POST["x"]); ?>`, weblang.PHP},
		{"php appended to a png", []byte("\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00"),
			`<?php passthru($_REQUEST["c"]); ?>`, weblang.PHP},
		{"jsp appended to a jpeg", []byte("\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01"),
			`<%@page import="java.io.*"%><% Runtime.getRuntime().exec(request.getParameter("c")); %>`, weblang.JSP},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			data := append(append([]byte(nil), c.header...), []byte(c.tail)...)
			if !looksBinary(data) {
				t.Fatal("fixture is not binary in its first 8 KB; the test proves nothing")
			}
			got := signsFor(data)
			for _, l := range got {
				if l == c.want {
					return
				}
			}
			t.Errorf("polyglot refused: got %v, want %s admitted", got, c.want)
		})
	}
}

// The exception must not readmit what R10 exists to refuse: binary whose only "language" is a
// two-byte coincidence stays refused.
func TestBinaryWithOnlyAChanceMarkerStaysRefused(t *testing.T) {
	for _, c := range []struct{ name, tail string }{
		{"chance <%", "<% \xde\xad\xbe\xef more compressed bytes"},
		{"chance <?x", "<?x \xca\xfe\xba\xbe"},
		{"request. in a string table", "get_Request.Item \x01\x02"},
	} {
		data := append([]byte("wOF2\x00\x01\x00\x00\x00\x00"), []byte(c.tail)...)
		if got := signsFor(data); len(got) != 0 {
			t.Errorf("%s: binary readmitted to %v", c.name, got)
		}
	}
}

// FR-008: a rule or pass must never examine a file whose language is RECOGNISED and different. The
// three taint passes route through `passAdmits`, which asks for ctxUnknown before consulting a sign.
// perlpytaintFindings did not: it consulted the sign whenever `perlPyLang` returned "", and
// `perlPyLang` returns "" for every recognised non-Perl/Python context too -- php, static, jsp, aspx.
//
// So a .php file whose content happened to match the CGI sign was offered to the Perl/Python taint
// grammar, which is precisely the cross-language matching spec 008 measured and declined.
//
// It was also the wall-clock defect. `signs.admits` READS THE FILE, so every recognised file in a
// tree was read and swept: 3,650 files / 89.8 MB on the WordPress recognised half, ~30 s of a 65 s
// run, on a tree containing no unknown-extension file at all.
func TestPerlPythonPassRefusesARecognisedOtherLanguage(t *testing.T) {
	// Content that is unambiguously a Perl CGI shell, under names that claim other languages.
	body := "#!/usr/bin/perl\nuse strict;\nmy $q = $ENV{'QUERY_STRING'};\nsystem($q);\n"

	for _, name := range []string{"shell.php", "style.css", "app.js", "index.html", "page.jsp"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			p := filepath.Join(dir, name)
			if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}
			got := perlpytaintFindings([]string{p}, "T", newSignCache())
			if len(got) != 0 {
				t.Errorf("%s: %d Perl/Python finding(s) on a file whose name claims another language; "+
					"FR-008 refuses cross-language matching", name, len(got))
			}
		})
	}
}

// The control: the same content under a name that claims nothing must still be admitted, or the fix
// above would have closed the feature instead of a hole in it.
func TestPerlPythonPassStillAdmitsAnUnnamedFile(t *testing.T) {
	body := "#!/usr/bin/perl\nuse strict;\nmy $q = $ENV{'QUERY_STRING'};\nsystem($q);\n"
	for _, name := range []string{"shell.txt", "backup.bak", "shell"} {
		dir := t.TempDir()
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		if got := perlpytaintFindings([]string{p}, "T", newSignCache()); len(got) == 0 {
			t.Errorf("%s: a renamed Perl CGI shell produced no Perl/Python finding", name)
		}
	}
}
