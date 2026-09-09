package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"shellsight/internal/finding"
	"shellsight/internal/javadisk"
)

const compiledRequestExecClass = "yv66vgAAADQAIQoAAgADBwAEDAAFAAYBABBqYXZhL2xhbmcvT2JqZWN0AQAGPGluaXQ+AQADKClWCgAIAAkHAAoMAAsADAEAEWphdmEvbGFuZy9SdW50aW1lAQAKZ2V0UnVudGltZQEAFSgpTGphdmEvbGFuZy9SdW50aW1lOwgADgEAA2NtZAsAEAARBwASDAATABQBACVqYXZheC9zZXJ2bGV0L2h0dHAvSHR0cFNlcnZsZXRSZXF1ZXN0AQAMZ2V0UGFyYW1ldGVyAQAmKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL1N0cmluZzsKAAgAFgwAFwAYAQAEZXhlYwEAJyhMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9Qcm9jZXNzOwcAGgEABVNoZWxsAQAEQ29kZQEAA3J1bgEAKihMamF2YXgvc2VydmxldC9odHRwL0h0dHBTZXJ2bGV0UmVxdWVzdDspVgEACkV4Y2VwdGlvbnMHACABABNqYXZhL2xhbmcvRXhjZXB0aW9uACEAGQACAAAAAAACAAEABQAGAAEAGwAAABEAAQABAAAABSq3AAGxAAAAAAABABwAHQACABsAAAAcAAMAAgAAABC4AAcrEg25AA8CALYAFVexAAAAAAAeAAAABAABAB8AAA=="

func requestExecClass(t *testing.T) []byte {
	t.Helper()
	data, err := base64.StdEncoding.DecodeString(compiledRequestExecClass)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func writeZip(t *testing.T, path string, entries map[string][]byte) {
	t.Helper()
	var data bytes.Buffer
	zw := zip.NewWriter(&data)
	for name, content := range entries {
		entry, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write(content); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}

func findingForRule(findings []finding.Finding, rule string) *finding.Finding {
	for i := range findings {
		if findings[i].Detection.KnowledgeRef == rule {
			return &findings[i]
		}
	}
	return nil
}

func diagnosticCount(summaries []javaDiagnosticSummary, code string) int {
	for _, summary := range summaries {
		if summary.Code == code {
			return summary.Count
		}
	}
	return 0
}

// encodedShell returns a base64(eval(...)) PHP shell whose decoded layer is the given payload.
func encodedShell(payload string) string {
	return `<?php eval(base64_decode("` + base64.StdEncoding.EncodeToString([]byte(payload)) + `")); ?>`
}

func TestBuildDecodedMirrorMapsBackToOrigin(t *testing.T) {
	web := t.TempDir()
	origin := filepath.Join(web, "eviil.php")
	if err := os.WriteFile(origin, []byte(encodedShell(`<?php system($_GET["c"]); ?>`)), 0o644); err != nil {
		t.Fatal(err)
	}
	mirror := t.TempDir()
	originOf, n, err := buildDecodedMirror(enumeratedPaths(web), mirror, newSignCache())
	if err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Fatal("expected at least one decoded layer file written")
	}
	for mp, op := range originOf {
		if op != origin {
			t.Fatalf("mirror %s mapped to %s, want %s", mp, op, origin)
		}
	}
}

// A decoded layer must carry its ORIGIN's language context. The mirror is scanned as its own tree and
// the language rule-gate runs against the path yr reports (the mirror path) BEFORE the finding is
// rewritten back to the origin — so a mirror file named .php makes every jsp/aspx-gated rule
// ineligible on the decoded body of a JSP or ASPX shell. Encoding the origin extension in the mirror
// filename is what keeps inferFileContext honest.
func TestBuildDecodedMirrorPreservesOriginLanguageContext(t *testing.T) {
	web := t.TempDir()
	cases := []struct {
		name, file string
		want       fileContext
	}{
		{"jsp origin", "shell.jsp", ctxJSP},
		{"aspx origin", "shell.aspx", ctxASPX},
		{"asp origin", "shell.asp", ctxASP},
		{"php origin", "shell.php", ctxPHP},
	}
	for _, c := range cases {
		if err := os.WriteFile(filepath.Join(web, c.file),
			[]byte(encodedShell(`<% Runtime.getRuntime().exec(request.getParameter("c")); %>`)), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mirror := t.TempDir()
	originOf, n, err := buildDecodedMirror(enumeratedPaths(web), mirror, newSignCache())
	if err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Fatal("expected decoded layer files")
	}
	seen := map[string]bool{}
	for mp, op := range originOf {
		originExt := strings.ToLower(filepath.Ext(op))
		// phptaint resolved layers are PHP-only by construction and legitimately end in .php.
		if strings.HasPrefix(filepath.Base(mp), "res_") {
			continue
		}
		for _, c := range cases {
			if filepath.Base(op) != c.file {
				continue
			}
			seen[c.file] = true
			if got := inferFileContext(mp); got != c.want {
				t.Errorf("%s: decoded layer %s infers context %q, want %q (origin ext %s)",
					c.name, filepath.Base(mp), got, c.want, originExt)
			}
		}
	}
	for _, c := range cases {
		if !seen[c.file] {
			t.Errorf("%s: no decoded layer produced for %s", c.name, c.file)
		}
	}
}

func TestDeobfScanFlagsEncodedShellAtOrigin(t *testing.T) {
	yr := yrPath()
	if yr == "" {
		t.Skip("yr binary not found")
	}
	web := t.TempDir()
	origin := filepath.Join(web, "x.php")
	if err := os.WriteFile(origin, []byte(encodedShell(`<?php system($_GET["c"]); ?>`)), 0o644); err != nil {
		t.Fatal(err)
	}
	findings, scannedOK, failed, _ := scanWithDeobf(context.Background(), yr, rulesDir(), false, []string{web}, "T", javadisk.DefaultOptions())
	if scannedOK == 0 && len(failed) > 0 {
		t.Skip("yr scan blocked (AV/OS) on temp files — covered by cmd/measure")
	}
	for _, f := range findings {
		if f.Target.File != nil && f.Target.File.Path == origin &&
			strings.Contains(strings.ToLower(f.Detection.Evidence), "decoded layer") {
			return // a hit attributed to a decoded layer of the origin file
		}
	}
	t.Fatalf("expected a decoded-layer finding on %s; got %+v", origin, findings)
}

func TestJavaCompiledDispatchesClassJarAndWarWithPhysicalIdentity(t *testing.T) {
	classData := requestExecClass(t)
	for _, ext := range []string{".class", ".jar", ".war"} {
		t.Run(ext, func(t *testing.T) {
			root := t.TempDir()
			artifact := filepath.Join(root, "payload"+ext)
			if ext == ".class" {
				if err := os.WriteFile(artifact, classData, 0o600); err != nil {
					t.Fatal(err)
				}
			} else {
				member := "lib/Shell.class"
				if ext == ".war" {
					member = "WEB-INF/classes/Shell.class"
				}
				writeZip(t, artifact, map[string][]byte{
					member:            classData,
					"views/shell.jsp": []byte(`<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>`),
				})
			}

			findings, diagnostics := javadiskFindings(context.Background(), []string{root}, "host", javadisk.DefaultOptions())
			got := findingForRule(findings, "javadisk:class-request-exec")
			if got == nil || got.Target.File == nil {
				t.Fatalf("missing compiled Java finding: findings=%+v diagnostics=%+v", findings, diagnostics)
			}
			content, err := os.ReadFile(artifact)
			if err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(content)
			if got.Target.File.Path != artifact || got.Artifact.Location != artifact || got.Target.File.SHA256 != hex.EncodeToString(sum[:]) {
				t.Fatalf("finding must identify physical artifact %q: %+v", artifact, got)
			}
			if ext != ".class" {
				source := findingForRule(findings, "javadisk:request-exec")
				if source == nil || source.Target.File == nil || source.Target.File.Path != artifact ||
					source.Target.File.SHA256 != hex.EncodeToString(sum[:]) ||
					!strings.Contains(source.Detection.Evidence, "!/views/shell.jsp") {
					t.Fatalf("archive source finding must retain physical identity and logical member evidence: %+v", source)
				}
			}
		})
	}
}

func TestScanWithDeobfPreservesJavaArchiveMemberFindings(t *testing.T) {
	root := t.TempDir()
	artifact := filepath.Join(root, "payload.jar")
	writeZip(t, artifact, map[string][]byte{
		"views/first.jsp":  []byte(`<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>`),
		"views/second.jsp": []byte(`<% new ProcessBuilder(request.getParameter("command")).start(); %>`),
	})

	assertMembers := func(findings []finding.Finding) {
		t.Helper()
		var members []string
		for _, candidate := range findings {
			if candidate.Detection.KnowledgeRef != "javadisk:request-exec" {
				continue
			}
			if candidate.Target.File == nil || candidate.Target.File.Path != artifact {
				t.Fatalf("Java finding must retain archive physical path %q: %+v", artifact, candidate)
			}
			members = append(members, candidate.Detection.Evidence)
		}
		if len(members) != 2 || !strings.Contains(members[0]+members[1], "!/views/first.jsp") ||
			!strings.Contains(members[0]+members[1], "!/views/second.jsp") {
			t.Fatalf("expected two distinct archive-member findings, got %+v", members)
		}
	}

	yr := yrPath()
	if yr == "" {
		t.Skip("yr binary not found")
	}
	spec, err := json.Marshal(finding.TargetSpec{Host: "host", Webroots: []string{root}})
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := runDiskProbe(context.Background(), []string{"--yr", yr, "--rules", rulesDir(), "--deobf=false"}, bytes.NewReader(spec), &stdout, &stderr)
	if code != exitOK {
		if strings.Contains(stderr.String(), "yr on") {
			t.Skip("yr scan blocked (AV/OS) on temp files - covered by cmd/measure")
		}
		t.Fatalf("runDiskProbe exit=%d stderr=%s", code, stderr.String())
	}
	var output finding.ProbeOutput
	if err := json.Unmarshal(stdout.Bytes(), &output); err != nil {
		t.Fatal(err)
	}
	assertMembers(output.Findings)

	withDeobf, scannedOK, failed, _ := scanWithDeobf(context.Background(), yr, rulesDir(), false, []string{root}, "host", javadisk.DefaultOptions())
	if scannedOK == 0 && len(failed) > 0 {
		t.Skip("yr scan blocked (AV/OS) on temp files - covered by cmd/measure")
	}
	assertMembers(withDeobf)
}

func TestJavaDiagnosticMalformedSiblingDoesNotSuppressSourceOrYARA(t *testing.T) {
	yr := yrPath()
	if yr == "" {
		t.Skip("yr binary not found")
	}
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "bad.class"), []byte("not a class"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "semantic.jsp"), []byte(`<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "signature.php"), []byte(`<?php system($_GET["cmd"]); ?>`), 0o600); err != nil {
		t.Fatal(err)
	}

	findings, scannedOK, failed, diagnostics := scanWithDeobf(context.Background(), yr, rulesDir(), false, []string{root}, "host", javadisk.DefaultOptions())
	if scannedOK == 0 && len(failed) > 0 {
		t.Skip("yr scan blocked (AV/OS) on temp files - covered by cmd/measure")
	}
	if findingForRule(findings, "javadisk:request-exec") == nil || findingForRule(findings, "kb:yara/php_command_exec_webshell") == nil {
		t.Fatalf("parser failure suppressed source or YARA findings: %+v", findings)
	}
	if diagnosticCount(diagnostics, "java-class-malformed") != 1 {
		t.Fatalf("missing malformed-class diagnostic: %+v", diagnostics)
	}
}

func TestJavaDiagnosticAggregationIsDeterministicBoundedAndHonest(t *testing.T) {
	diagnostics := []javadisk.Diagnostic{
		{Artifact: "b", Code: "java-class-malformed", Detail: "same", Count: 1},
		{Artifact: "b", Code: "java-class-malformed", Detail: "same", Count: 4},
		{Artifact: "a", Code: "java-archive-budget-exhausted", Detail: "limit", Count: 0},
	}
	summaries := summarizeJavaDiagnostics(diagnostics)
	if len(summaries) != 2 || summaries[0].Code != "java-archive-budget-exhausted" || summaries[0].Count != 1 || summaries[1].Count != 4 {
		t.Fatalf("unexpected summaries: %+v", summaries)
	}
	cov := &finding.ProbeCoverage{Status: finding.CovRan, TargetsScanned: 1}
	applyJavaDiagnostics(cov, summaries)
	if cov.Status != finding.CovDegraded || cov.Reason != "java-archive-budget-exhausted=1; java-class-malformed=4" || len(cov.Reason) > 512 {
		t.Fatalf("unexpected degraded coverage: %+v", cov)
	}
	existing := &finding.ProbeCoverage{Status: finding.CovDegraded, Reason: "1 of 2 webroot(s) failed to scan: missing"}
	applyJavaDiagnostics(existing, summaries[:1])
	if existing.Reason != "1 of 2 webroot(s) failed to scan: missing; java-archive-budget-exhausted=1" {
		t.Fatalf("Java diagnostics replaced existing failed-root coverage: %+v", existing)
	}

	ran := &finding.ProbeCoverage{Status: finding.CovRan, TargetsScanned: 1}
	applyJavaDiagnostics(ran, nil)
	if ran.Status != finding.CovRan || ran.Reason != "" {
		t.Fatalf("diagnostic-free scan must remain ran: %+v", ran)
	}

	var many []javaDiagnosticSummary
	for i := 0; i < 100; i++ {
		many = append(many, javaDiagnosticSummary{Code: strings.Repeat("x", 20) + string(rune('a'+i%26)), Count: i + 1})
	}
	bounded := &finding.ProbeCoverage{Status: finding.CovRan}
	applyJavaDiagnostics(bounded, many)
	if len(bounded.Reason) > 512 {
		t.Fatalf("Java degradation reason is not bounded: %d bytes", len(bounded.Reason))
	}
}

func TestJavaDiagnosticMissingOrUnreadableArtifactOmitsFinding(t *testing.T) {
	result := javadisk.Result{Findings: []javadisk.Finding{
		{Rule: "missing-path", ArtifactPath: ""},
		{Rule: "unreadable", ArtifactPath: filepath.Join(t.TempDir(), "gone.class")},
	}}
	findings, diagnostics := javaResultFindings(result, "host", map[string]string{})
	if len(findings) != 0 {
		t.Fatalf("invalid Java findings must be omitted: %+v", findings)
	}
	summaries := summarizeJavaDiagnostics(diagnostics)
	if diagnosticCount(summaries, "java-class-malformed") != 1 || diagnosticCount(summaries, "java-artifact-read-failed") != 1 {
		t.Fatalf("missing integration diagnostics: %+v", summaries)
	}
}

func TestJavaDiagnosticOversizedJSPIsSkippedAndDegradesCoverage(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "oversized.jsp")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString(`<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>`); err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate((32 << 20) + 1); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	_, n, err := buildDecodedMirror(enumeratedPaths(root), t.TempDir(), newSignCache())
	if err != nil || n != 0 {
		t.Fatalf("oversized JSP must not produce decoded layers: n=%d err=%v", n, err)
	}
	findings, diagnostics := javadiskFindings(context.Background(), []string{root}, "host", javadisk.DefaultOptions())
	if len(findings) != 0 || diagnosticCount(diagnostics, "java-analysis-budget-exhausted") != 1 {
		t.Fatalf("oversized JSP coverage was not degraded: findings=%+v diagnostics=%+v", findings, diagnostics)
	}
}

// The decode-and-rescan mirror must cover every language the rule gate scopes rules to. Otherwise a
// base64-wrapped Perl or Python payload is never unwrapped and its sink is invisible.
func TestWebshellLikeExtCoversAllScopedLanguages(t *testing.T) {
	for _, p := range []string{
		"/v/a.php", "/v/a.jsp", "/v/a.aspx", "/v/a.asp",
		"/v/a.pl", "/v/a.pm", "/v/a.plx", "/v/a.pl6",
		"/v/a.py", "/v/a.pyw", "/v/a.py3", "/v/a.pyi", "/v/a.pyp", "/v/a.pyx",
		"/v/a.cgi", "/v/a.fcgi",
		"/v/a.shtml", "/v/a.shtm", "/v/a.stm",
	} {
		if !webshellLikeExt(p) {
			t.Errorf("webshellLikeExt(%q) = false, want true", p)
		}
	}
	// Still a pre-filter: non-web files must stay out so the mirror does not explode in size.
	for _, p := range []string{"/v/a.txt", "/v/a.png", "/v/a.go", "/v/a.md"} {
		if webshellLikeExt(p) {
			t.Errorf("webshellLikeExt(%q) = true, want false", p)
		}
	}
}

// --- the language a .cgi file is analysed as ------------------------------------------------
//
// T101 phase 2 asked CGI's own question -- "does the taint pass cover the CGI channel" -- and the
// answer turned up a routing defect on our side. `perlPyLang` decided the language from the
// EXTENSION, and .cgi/.fcgi routed to "perl" unconditionally, so a Python webshell served as
// foo.cgi was analysed with Perl's sink set.
//
// MEASURED before the fix, over the five real Python samples held, by transcribing perlSinks and
// pySinks and running both: THREE OF FIVE lose every sink. os.popen( -- present in four of the
// five and the commonest Python sink in that corpus -- matches no Perl sink at all. The two that
// survived did so for the wrong reason: Perl's \bsystem\s*\( matches os.system( by accident,
// because `.` is a non-word character.
//
// RFC 3875 is why the extension cannot decide it: section 1.4 makes a CGI script an executable the
// server invokes and fixes no language, so the suffix is a server configuration choice rather than
// a property of the code. The shebang is the only in-file evidence, and it is what the interpreter
// itself uses.

func TestPerlPyLangDecidesCgiFromTheShebangNotTheExtension(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	cases := []struct {
		name string
		file string
		body string
		want string
	}{
		{"python shebang under .cgi", "py.cgi", "#!/usr/bin/python\nimport os\n", "python"},
		{"python3 shebang under .cgi", "py3.cgi", "#!/usr/bin/env python3\nimport os\n", "python"},
		{"perl shebang under .cgi", "pl.cgi", "#!/usr/bin/perl\nuse CGI;\n", "perl"},
		{"no shebang under .cgi falls back to perl", "bare.cgi", "print \"hi\";\n", "perl"},
		{"python shebang under .fcgi", "py.fcgi", "#!/usr/bin/python\n", "python"},
		// A shebang NEVER overrides an unambiguous extension: a .py file is Python whatever its
		// first line says, and the fallback exists only where the extension carries no language.
		{"perl shebang under .py stays python", "x.py", "#!/usr/bin/perl\n", "python"},
		{"python shebang under .pl stays perl", "x.pl", "#!/usr/bin/python\n", "perl"},
		// The extensionless cgi-bin/ case: previously "" and therefore never analysed at all.
		// A shebang alone is NOT enough here, and the reason is measured -- accepting one cost
		// three confirmed-band false positives on `webmin/bin/language-manager`, a 2,282-line
		// maintainer CLI whose "request source" was an interactive `chomp(my $a = <STDIN>);`
		// prompt at lines 1743 and 1767. RFC 3875 section 4.1 says what a CGI program is: one
		// that obtains the request through the meta-variables. A program that never reads one
		// is not a CGI program, whatever its shebang.
		{"extensionless CGI program, perl", "cgibin-pl",
			"#!/usr/bin/perl\nmy $q = $ENV{'QUERY_STRING'};\n", "perl"},
		{"extensionless CGI program, python", "cgibin-py",
			"#!/usr/bin/python\nimport os\nq = os.environ['QUERY_STRING']\n", "python"},
		{"extensionless perl CLI tool is NOT ours", "language-manager",
			"#!/usr/bin/env perl\nchomp(my $a = <STDIN>);\nsystem(\"git add $a\");\n", ""},
		{"extensionless with no shebang is not ours", "notes", "hello\n", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := perlPyLang(write(tc.file, tc.body)); got != tc.want {
				t.Fatalf("perlPyLang(%s) = %q, want %q", tc.file, got, tc.want)
			}
		})
	}
}

func TestAPythonShellServedAsCgiKeepsItsSinks(t *testing.T) {
	// The end-to-end form of the same defect: identical bytes, two names, and before the fix the
	// .cgi copy produced no finding because os.popen is not a Perl sink.
	body := "#!/usr/bin/python\n" +
		"import os\n" +
		"def handle(environ):\n" +
		"    cmd = environ[\"QUERY_STRING\"]\n" +
		"    return os.popen(cmd).read()\n"
	dir := t.TempDir()
	var paths []string
	for _, name := range []string{"shell.py", "shell.cgi"} {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, p)
	}
	found := perlpytaintFindings(paths, "T", newSignCache())
	if len(found) != 2 {
		t.Fatalf("want a finding for BOTH names, got %d: %+v", len(found), found)
	}
}

// mkDedupFinding builds a finding for the dedup-ordering tests: one file, one rule, one score, so
// the only thing that can decide the winner is order.
func mkDedupFinding(sha, rule string, score int) finding.Finding {
	return finding.Finding{
		Target:    finding.Target{Kind: "file", File: &finding.File{Path: `C:\w\shell.php`, SHA256: sha}},
		Detection: finding.Detection{KnowledgeRef: rule},
		Score:     score,
	}
}

func TestDecodedOrderIsIndependentOfTheOrderYrEmitted(t *testing.T) {
	one := []finding.Finding{
		mkDedupFinding("cc", "kb:yara/R", 70),
		mkDedupFinding("aa", "kb:yara/R", 70),
		mkDedupFinding("bb", "kb:yara/Q", 70),
	}
	two := []finding.Finding{one[2], one[0], one[1]}
	sortDecodedForDedup(one)
	sortDecodedForDedup(two)
	for i := range one {
		if one[i].Detection.KnowledgeRef != two[i].Detection.KnowledgeRef ||
			one[i].Target.File.SHA256 != two[i].Target.File.SHA256 {
			t.Fatalf("index %d differs between input orders: %s/%s vs %s/%s", i,
				one[i].Detection.KnowledgeRef, one[i].Target.File.SHA256,
				two[i].Detection.KnowledgeRef, two[i].Target.File.SHA256)
		}
	}
}

func TestTheSameDecodedLayerWinsWhateverOrderYrEmitted(t *testing.T) {
	// yr emits matches in parallel COMPLETION order, not scan-list order. Measured 2026-09-04: four
	// runs over one identical 400-file scan list produced four different orderings and one identical
	// result SET. dedupByOriginRule keeps the first finding it sees for a (path, rule) and replaces
	// it only on a strictly higher score, so without a fixed order the surviving decoded LAYER
	// varied per run -- and with it Target.File.SHA256, which is the content key the console groups
	// triage by and part of the fingerprint.
	fwd := []finding.Finding{mkDedupFinding("bb", "kb:yara/R", 70), mkDedupFinding("aa", "kb:yara/R", 70)}
	rev := []finding.Finding{mkDedupFinding("aa", "kb:yara/R", 70), mkDedupFinding("bb", "kb:yara/R", 70)}
	sortDecodedForDedup(fwd)
	sortDecodedForDedup(rev)
	w1, w2 := dedupByOriginRule(fwd), dedupByOriginRule(rev)
	if len(w1) != 1 || len(w2) != 1 {
		t.Fatalf("dedup kept %d and %d findings, want 1 each", len(w1), len(w2))
	}
	if w1[0].Target.File.SHA256 != w2[0].Target.File.SHA256 {
		t.Fatalf("the surviving layer depends on emission order: %s vs %s",
			w1[0].Target.File.SHA256, w2[0].Target.File.SHA256)
	}
}

func TestARawFindingStillBeatsADecodedLayerOnATie(t *testing.T) {
	// The behaviour worth preserving. A raw finding's evidence points at bytes that exist on disk;
	// a decoded layer's points at a reconstruction. Only the DECODED slice is sorted, so raw stays
	// appended first and keeps winning ties -- the raw hash here sorts LAST on purpose, so a sort
	// applied to the merged slice would visibly steal the win.
	raw := mkDedupFinding("ff", "kb:yara/R", 70)
	decoded := []finding.Finding{mkDedupFinding("bb", "kb:yara/R", 70), mkDedupFinding("aa", "kb:yara/R", 70)}
	sortDecodedForDedup(decoded)
	out := dedupByOriginRule(append([]finding.Finding{raw}, decoded...))
	if len(out) != 1 {
		t.Fatalf("dedup kept %d findings, want 1", len(out))
	}
	if out[0].Target.File.SHA256 != "ff" {
		t.Fatalf("a decoded layer (%s) displaced the raw finding", out[0].Target.File.SHA256)
	}
}
