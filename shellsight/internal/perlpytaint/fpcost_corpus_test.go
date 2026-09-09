package perlpytaint

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// What the body-read change costs on real benign code, measured on the whole pool.
//
// The change is two-sided and both sides need measuring:
//   * ADDED  -- `read`/`sysread(STDIN, $x, ...)` now taints its out parameter, and
//               `sys.stdin.read` is a source. New exposure.
//   * REMOVED -- a STDIN source counts only in a file that is already framed as CGI. `<STDIN>`
//               used to be a source unconditionally, which is how `webmin/bin/language-manager`
//               reached score 85 off a y/n prompt.
//
// This reports the resulting finding count per pool. It is a REGRESSION FLOOR, not a claim of
// perfection: the pass is an escalator into the confirmed band, so any finding here is a
// confirmed-band false positive and the bar is low by construction.
func TestTaintFalsePositiveCostOnTheBenignPools(t *testing.T) {
	root := os.Getenv("SHELLSIGHT_CORPUS")
	if root == "" {
		root = filepath.Join("..", "..", "..", "shellsight-corpus")
	}
	pools := map[string][2]string{
		"benign-perl":   {filepath.Join(root, "staging", "benign-perl"), "perl"},
		"benign-python": {filepath.Join(root, "staging", "benign-python"), "python"},
	}
	// The acquisition round's benign applications, where the CGI shape actually lives: webmin is a
	// 44,303-file Perl CGI application and rt is another.
	clones := filepath.Join(root, "acquisition", "2026-08-23-groupA", "ben")
	for _, a := range []struct{ dir, lang string }{
		{"webmin__webmin", "perl"}, {"bestpractical__rt", "perl"}, {"bugzilla__bugzilla", "perl"},
		{"eldy__AWStats", "perl"}, {"saltstack__salt", "python"}, {"ansible__ansible", "python"},
		{"certbot__certbot", "python"},
	} {
		if _, err := os.Stat(filepath.Join(clones, a.dir)); err == nil {
			pools["clone:"+a.dir] = [2]string{filepath.Join(clones, a.dir), a.lang}
		}
	}
	if _, err := os.Stat(pools["benign-perl"][0]); err != nil {
		t.Skip("benign pools not present on this machine")
	}

	perlExt := map[string]bool{".pl": true, ".pm": true, ".cgi": true, ".fcgi": true, ".plx": true}
	pyExt := map[string]bool{".py": true, ".cgi": true, ".fcgi": true}

	total := 0
	for name, spec := range pools {
		pool, lang := spec[0], spec[1]
		want := perlExt
		if lang == "python" {
			want = pyExt
		}
		files, hits := 0, 0
		_ = filepath.Walk(pool, func(p string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() || !want[strings.ToLower(filepath.Ext(p))] {
				return nil //nolint:nilerr // an unreadable entry is not this test's subject
			}
			data, rerr := os.ReadFile(p)
			if rerr != nil {
				return nil
			}
			files++
			found := Analyze(data, lang)
			hits += len(found)
			for _, f := range found {
				t.Logf("    CONFIRMED-BAND FP %s -- %s", p, f.Evidence)
			}
			return nil
		})
		t.Logf("%-28s %s  %5d files, %d finding(s)", name, lang, files, hits)
		total += hits
	}
	t.Logf("TOTAL confirmed-band findings on benign code: %d", total)

	// A REGRESSION FLOOR AT THE MEASURED VALUE, not an aspiration of zero. The pass is a
	// confirmed-band escalator over real application code and it has always had a small
	// residue here; asserting 0 would leave a permanently-red test, which is how a guard stops
	// being read -- the same reasoning `langkit workspace` gives for being a refusal rather
	// than an assertion.
	//
	// MEASURED BOTH WAYS on 2026-08-23, same walk, only internal/perlpytaint/taint.go differing:
	//
	//   pool                     before  after
	//   benign-perl                   5      3
	//   benign-python                 1      1
	//   clone:webmin__webmin         13     10
	//   clone:bugzilla__bugzilla      3      2
	//   clone:eldy__AWStats           2      1
	//   rt / salt / ansible / certbot 0      0
	//   TOTAL                        24     17
	//
	// The change ADDS a source (the body read) and REMOVES one (a bare STDIN in a file with no
	// CGI framing). It is minus seven false positives and plus one real sample recovered
	// (`Perl_Web_Shell_by_RST-GHC.pl`, 0 findings -> 1) -- better on both axes, which is the
	// only justification the reuse-first rule accepts.
	const measuredFloor = 17
	if total > measuredFloor {
		t.Errorf("confirmed-band false positives on benign code rose to %d, floor is %d",
			total, measuredFloor)
	}
	if total < measuredFloor {
		t.Logf("IMPROVED to %d (floor %d) -- lower the floor and record why", total, measuredFloor)
	}
}
