package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// What the shebang fallback in perlPyLang costs on real benign code.
//
// The playbook's phase-6 rule: "Validate false positives on the benign pool at every step: a recall
// recovery that costs precision has spent the thing it exists to protect." The change widened the
// population perlpytaint analyses in two ways -- a `.cgi` file with a python shebang now gets
// Python's sinks, and an EXTENSIONLESS file with an interpreter shebang is analysed at all, where
// before it was skipped entirely. The second is the one with real false-positive exposure, because
// a web root is full of extensionless files.
//
// SKIPPED without the corpus, like the other corpus-dependent tests here: the pools are gitignored
// (3.8 GB) and a permanently-red test is one nobody reads.
func TestShebangFallbackCostsOnTheBenignPools(t *testing.T) {
	root := os.Getenv("SHELLSIGHT_CORPUS")
	if root == "" {
		root = filepath.Join("..", "..", "..", "shellsight-corpus")
	}
	// The staged trees are digest-named with an extension appended, so they cannot exercise the
	// extensionless case. The CLONED applications are the real filenames, and webmin alone is a
	// 44,303-file Perl CGI application -- exactly the shape of web root where an extensionless
	// cgi-bin/ population would live.
	clones := filepath.Join(root, "acquisition", "2026-08-23-groupA", "ben")
	pools := map[string]string{
		"benign-perl":   filepath.Join(root, "staging", "benign-perl"),
		"benign-python": filepath.Join(root, "staging", "benign-python"),
	}
	for _, app := range []string{"webmin__webmin", "bestpractical__rt", "saltstack__salt",
		"ansible__ansible", "certbot__certbot", "bugzilla__bugzilla", "eldy__AWStats"} {
		if _, err := os.Stat(filepath.Join(clones, app)); err == nil {
			pools["clone:"+app] = filepath.Join(clones, app)
		}
	}
	for _, p := range pools {
		if _, err := os.Stat(p); err != nil {
			t.Skip("benign pools not present on this machine")
		}
	}

	for name, pool := range pools {
		var extensionless, cgiPythonShebang []string
		err := filepath.Walk(pool, func(p string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil //nolint:nilerr // an unreadable entry is not this test's subject
			}
			switch strings.ToLower(filepath.Ext(p)) {
			case "":
				if perlPyLang(p) != "" {
					extensionless = append(extensionless, p)
				}
			case ".cgi", ".fcgi":
				if perlPyLang(p) == "python" {
					cgiPythonShebang = append(cgiPythonShebang, p)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		newly := append(append([]string{}, extensionless...), cgiPythonShebang...)
		findings := perlpytaintFindings(newly, "T", newSignCache())
		t.Logf("%s: %d extensionless with a shebang, %d .cgi re-routed to python, "+
			"%d newly-analysed files, %d finding(s)",
			name, len(extensionless), len(cgiPythonShebang), len(newly), len(findings))
		for _, f := range findings {
			t.Logf("    FP CANDIDATE %s -- %s", f.Artifact.Location, f.Detection.Evidence)
		}
		// The bar is not "zero new files analysed" -- widening the population is the point. It is
		// that widening it costs no false positive on real application code.
		if len(findings) != 0 {
			t.Errorf("%s: shebang fallback produced %d finding(s) on a benign pool; a recall "+
				"recovery that costs precision has spent what it exists to protect",
				name, len(findings))
		}
	}
}
