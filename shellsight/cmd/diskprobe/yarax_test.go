package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"shellsight/internal/finding"
)

// repoRoot walks up from cwd to the module root (directory containing go.mod).
func repoRoot() string {
	if r := os.Getenv("SHELLSIGHT_REPO_ROOT"); r != "" {
		return r
	}
	dir, _ := os.Getwd()
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "."
		}
		dir = parent
	}
}

// yrPath finds the bundled yr binary, or "" if unavailable.
func yrPath() string {
	if env := os.Getenv("SHELLSIGHT_YR"); env != "" {
		return env
	}
	p := filepath.Join(repoRoot(), "bin", "third_party", "yara-x", "yr.exe")
	if _, err := os.Stat(p); err == nil {
		return p
	}
	return ""
}

func rulesDir() string {
	if p := os.Getenv("SHELLSIGHT_RULES_PATH"); p != "" {
		return p
	}
	return filepath.Join(repoRoot(), "kb", "rules")
}

func TestParseNDJSON(t *testing.T) {
	in := []byte(`{"path":"C:\\web\\shell.php","rules":[{"identifier":"php_eval_request_webshell","namespace":"default"}]}
{"path":"C:\\web\\clean.php","rules":[]}

not json at all
{"path":"C:\\web\\b.jsp","rules":[{"identifier":"jsp_runtime_exec_webshell"}]}`)
	m := parseNDJSON(in)
	if len(m) != 2 {
		t.Fatalf("want 2 matched files, got %d", len(m))
	}
	if m[0].Rules[0].Identifier != "php_eval_request_webshell" {
		t.Fatalf("bad first match: %+v", m[0])
	}
	if m[1].Path != `C:\web\b.jsp` || m[1].Rules[0].Identifier != "jsp_runtime_exec_webshell" {
		t.Fatalf("bad second match: %+v", m[1])
	}
}

func TestParseNDJSONPreservesMetaField(t *testing.T) {
	// Object form (test format)
	ndjson := []byte(`{"path":"/tmp/shell.php","rules":[{"identifier":"test_rule","namespace":"default","meta":{"family":"TestFamily","score":"80"}}]}`)
	matches := parseNDJSON(ndjson)
	if len(matches) == 0 {
		t.Fatal("expected 1 file match")
	}
	if matches[0].Rules[0].Meta == nil {
		t.Error("Meta field not parsed; expected map with 'family' and 'score'")
	} else if matches[0].Rules[0].Meta["family"] != "TestFamily" {
		t.Errorf("expected family=TestFamily, got %q", matches[0].Rules[0].Meta["family"])
	}

	// Array-of-pairs form (actual yr --print-meta output)
	ndjson2 := []byte(`{"path":"/tmp/shell2.php","rules":[{"identifier":"php_rule","meta":[["family","GenericEval"],["score","70"]]}]}`)
	matches2 := parseNDJSON(ndjson2)
	if len(matches2) == 0 {
		t.Fatal("expected 1 file match for array-of-pairs meta")
	}
	if matches2[0].Rules[0].Meta["family"] != "GenericEval" {
		t.Errorf("array-of-pairs: expected family=GenericEval, got %q", matches2[0].Rules[0].Meta["family"])
	}
	if matches2[0].Rules[0].Meta["score"] != "70" {
		t.Errorf("array-of-pairs: expected score=70, got %q", matches2[0].Rules[0].Meta["score"])
	}
}

// Regression: yr emits THOR/signature-base meta with NUMBER (and bool) values — `score = 70`,
// `id = 12302`, `active = true`. A non-string meta value must NOT fail the record: the old
// [][]string decode failed the whole line, silently dropping EVERY rule match on that file
// (including our own string-meta rules). On the Java-disk corpus this hid 138/206 shells.
func TestParseNDJSONToleratesNonStringMeta(t *testing.T) {
	ndjson := []byte(`{"path":"C:\\web\\x.jsp","rules":[` +
		`{"identifier":"webshell_thor","meta":[["description","sig"],["score",70],["id",12302],["active",true]]},` +
		`{"identifier":"jsp_command_exec_webshell","meta":[["score","75"]]}` +
		`]}`)
	m := parseNDJSON(ndjson)
	if len(m) != 1 {
		t.Fatalf("a file matched by a number-meta rule must NOT be dropped; got %d files", len(m))
	}
	if len(m[0].Rules) != 2 {
		t.Fatalf("want both rule matches preserved, got %d", len(m[0].Rules))
	}
	if m[0].Rules[0].Meta["score"] != "70" {
		t.Errorf("number meta must stringify: want score=70, got %q", m[0].Rules[0].Meta["score"])
	}
	if m[0].Rules[0].Meta["id"] != "12302" {
		t.Errorf("number meta id must stringify: want 12302, got %q", m[0].Rules[0].Meta["id"])
	}
	if m[0].Rules[0].Meta["active"] != "true" {
		t.Errorf("bool meta must stringify: want active=true, got %q", m[0].Rules[0].Meta["active"])
	}
	if m[0].Rules[1].Meta["score"] != "75" {
		t.Errorf("string meta still works: want score=75, got %q", m[0].Rules[1].Meta["score"])
	}
}

func TestDiskProbeDetectsPlantedShell(t *testing.T) {
	yr := yrPath()
	if yr == "" {
		t.Skip("yr binary not found (set SHELLSIGHT_YR or place bin/third_party/yara-x/yr.exe)")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "shell.php"), []byte(`<?php eval($_REQUEST["x"]); ?>`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "index.php"), []byte(`<?php echo "hello"; ?>`), 0o644); err != nil {
		t.Fatal(err)
	}

	findings, scannedOK, failed := scanWebrootDirs(yr, rulesDir(), []string{dir}, "WEB01")
	if scannedOK == 0 && len(failed) > 0 {
		// Windows Defender blocks yr from opening freshly-written webshell test files (OS 225).
		// TestDiskEfficacy covers the same scanWebroots path via the pre-existing lab corpus.
		t.Skip("yr scan blocked by AV (OS 225) on temp files — skipping on this system")
	}
	if scannedOK != 1 || len(failed) != 0 {
		t.Fatalf("want 1 scanned, 0 failed; got scannedOK=%d failed=%v", scannedOK, failed)
	}
	if len(findings) == 0 {
		t.Fatalf("want at least 1 disk finding (the planted shell), got 0")
	}
	// The planted eval($_REQUEST) shell matches our php_eval_request_webshell rule — and, now
	// that PMF (php-malware-finder) is bundled, several PMF rules too — so find OUR rule among
	// the findings rather than assuming it is findings[0].
	var f *finding.Finding
	for i := range findings {
		if findings[i].Detection.KnowledgeRef == "kb:yara/php_eval_request_webshell" {
			f = &findings[i]
			break
		}
	}
	if f == nil {
		t.Fatalf("want a kb:yara/php_eval_request_webshell finding among %d findings", len(findings))
	}
	if f.View != "disk" || f.Detection.Basis != "signature" || f.Tier != finding.TierLikely {
		t.Fatalf("unexpected finding shape: %+v", *f)
	}
	if f.Target.File == nil || f.Target.File.SHA256 == "" {
		t.Fatalf("missing file sha256: %+v", f.Target)
	}
}

func TestRulesUsable(t *testing.T) {
	if err := rulesUsable(""); err == nil {
		t.Fatal("empty rules path must be unusable")
	}
	if err := rulesUsable(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Fatal("nonexistent rules path must be unusable")
	}
	if err := rulesUsable(t.TempDir()); err == nil {
		t.Fatal("empty rules dir (no .yar/.yara) must be unusable — it would compile to zero rules")
	}

	withRule := t.TempDir()
	if err := os.WriteFile(filepath.Join(withRule, "r.yar"), []byte("rule x { condition: true }"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := rulesUsable(withRule); err != nil {
		t.Fatalf("dir containing a .yar must be usable: %v", err)
	}

	single := filepath.Join(t.TempDir(), "rules.yara")
	if err := os.WriteFile(single, []byte("rule x { condition: true }"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := rulesUsable(single); err != nil {
		t.Fatalf("single rules file must be usable: %v", err)
	}
}

// A bogus rules path makes yr exit non-zero; the root must be reported as failed.
func TestScanWebrootsReportsFailedRootOnBadRules(t *testing.T) {
	yr := yrPath()
	if yr == "" {
		t.Skip("yr binary not found (set SHELLSIGHT_YR or place bin/third_party/yara-x/yr.exe)")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "x.php"), []byte(`<?php eval($_GET[0]); ?>`), 0o644); err != nil {
		t.Fatal(err)
	}
	bogusRules := filepath.Join(t.TempDir(), "no-such-rules.yar")
	findings, scannedOK, failed := scanWebrootDirs(yr, bogusRules, []string{dir}, "WEB01")
	if scannedOK != 0 {
		t.Fatalf("want 0 successful scans with bad rules, got %d", scannedOK)
	}
	if len(failed) != 1 {
		t.Fatalf("want the root reported as failed, got %v", failed)
	}
	if len(findings) != 0 {
		t.Fatalf("want 0 findings when the scan failed, got %d", len(findings))
	}
}

func TestYaraXArgsUseTheRulesDirectoryByDefault(t *testing.T) {
	got := yaraXArgs("C:\\rules", false, "list.txt")
	if !containsInOrder(got, "scan", "C:\\rules", "list.txt") {
		t.Fatalf("args = %v, want scan ... <rulesdir> <list>", got)
	}
	for _, a := range got {
		if a == "-C" {
			t.Fatal("-C passed for a rules DIRECTORY; yr would reject a directory as a compiled file")
		}
	}
}

func TestYaraXArgsPassCompiledRulesFlagForABlob(t *testing.T) {
	// yr's own help: "-C, --compiled-rules  Indicate that <RULES_PATH> is a file containing
	// compiled rules". Without it, yr tries to parse the blob as YARA source.
	got := yaraXArgs("C:\\set.yarc", true, "list.txt")
	if !containsInOrder(got, "-C", "C:\\set.yarc", "list.txt") {
		t.Fatalf("args = %v, want -C before the blob and the list last", got)
	}
}

func TestYaraXArgsKeepEveryOutputFlagOnBothPaths(t *testing.T) {
	// These four are not cosmetic. --print-meta carries shellsight_lang, which drives rule
	// admission in rulegate.go; --print-strings carries the matched text that becomes
	// Detection.Evidence and feeds the content fingerprint. Losing either on the compiled path
	// would change findings while every unit test about scanning still passed.
	for _, compiled := range []bool{false, true} {
		got := yaraXArgs("R", compiled, "L")
		for _, want := range []string{"--output-format", "ndjson", "--print-namespace", "--print-meta", "--scan-list"} {
			if !contains(got, want) {
				t.Errorf("compiled=%v: args %v are missing %q", compiled, got, want)
			}
		}
		var sawStrings bool
		for _, a := range got {
			if strings.HasPrefix(a, "--print-strings=") {
				sawStrings = true
			}
		}
		if !sawStrings {
			t.Errorf("compiled=%v: args %v are missing --print-strings=<n>", compiled, got)
		}
	}
}

func TestYaraXArgsPutTheListLast(t *testing.T) {
	// yr's usage is `<RULES_PATH>... <TARGET_PATH>`, so the list must be the final argument on
	// both paths or yr reads it as another rules path.
	for _, compiled := range []bool{false, true} {
		got := yaraXArgs("R", compiled, "THE-LIST")
		if got[len(got)-1] != "THE-LIST" {
			t.Errorf("compiled=%v: last arg is %q, want THE-LIST", compiled, got[len(got)-1])
		}
	}
}

// containsInOrder reports whether every needle appears, in this relative order.
func containsInOrder(hay []string, needles ...string) bool {
	i := 0
	for _, h := range hay {
		if i < len(needles) && h == needles[i] {
			i++
		}
	}
	return i == len(needles)
}
