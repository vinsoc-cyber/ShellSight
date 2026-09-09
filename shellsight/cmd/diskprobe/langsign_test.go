package main

import (
	"os"
	"path/filepath"
	"testing"

	"shellsight/internal/weblang"
)

// Each language's sign must admit that language's own real corpus samples when their names are
// stripped. This is the property the whole feature rests on: if a sign refuses a real shell, the
// widened admission never happens and the renamed file stays invisible.
func TestSignsAdmitRealSamplesWithNoName(t *testing.T) {
	cases := []struct {
		dir  string
		lang weblang.Lang
	}{
		{filepath.Join("php", "combined-mal"), weblang.PHP},
		{filepath.Join("java", "malicious"), weblang.JSP},
		{filepath.Join("dotnet", "malicious"), weblang.ASPX},
	}
	root := corpusDiskRoot(t)
	for _, c := range cases {
		dir := filepath.Join(root, c.dir)
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Logf("skipping %s: %v", c.dir, err)
			continue
		}
		checked, refused := 0, 0
		for _, e := range entries {
			if e.IsDir() || checked >= 200 {
				continue
			}
			data, rerr := readBoundedFile(filepath.Join(dir, e.Name()), maxScanFileBytes)
			if rerr != nil || len(data) == 0 {
				continue
			}
			checked++
			if !signMatches(c.lang, data) {
				refused++
				if refused <= 5 {
					t.Logf("%s sign refused %s", c.lang, e.Name())
				}
			}
		}
		if checked == 0 {
			continue
		}
		// A sign is a cheap prefilter, not a detector: it is allowed to be imperfect, but a sign
		// that refuses a large share of real samples would silently undo the feature. 10% is the
		// bound; the measured figure is logged either way so a regression is visible before it
		// crosses it.
		t.Logf("%s: %d/%d real samples refused by the sign", c.lang, refused, checked)
		if refused*10 > checked {
			t.Errorf("%s sign refused %d of %d real samples (>10%%) -- renamed copies of those "+
				"would not be admitted", c.lang, refused, checked)
		}
	}
}

// A file may be admitted by SEVERAL signs and must then be offered to every language that admitted
// it. Assigning it to one is the incumbent's measured failure: its Java sign contains `<%.*request.*%>`,
// a Classic ASP shape, so the two tokens overlap in both directions and a file can be claimed by
// either. Our answer is not to pick a winner.
func TestSignsAreNotExclusive(t *testing.T) {
	// A JSP scriptlet reading a request parameter: `<%` is a JSP marker AND `request(` is an ASP one.
	both := []byte(`<% out.print(request.getParameter("c")); %>`)
	got := signsFor(both)
	seen := map[weblang.Lang]bool{}
	for _, l := range got {
		seen[l] = true
	}
	if !seen[weblang.JSP] {
		t.Errorf("signsFor did not admit JSP for %q; got %v", both, got)
	}
	if !seen[weblang.ASP] && !seen[weblang.ASPX] {
		t.Errorf("signsFor did not admit any ASP-family language for %q; got %v", both, got)
	}
	if len(got) < 2 {
		t.Errorf("expected an ambiguous file to be admitted by several signs, got %v", got)
	}
}

// Content that is not any web language must be admitted by nothing. This is what keeps the widened
// behaviour from handing every image and archive to an AST parser.
func TestSignsRefuseNonWebContent(t *testing.T) {
	cases := map[string][]byte{
		"png header":  {0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 13},
		"zip header":  {'P', 'K', 3, 4, 20, 0, 0, 0, 8, 0},
		"elf header":  {0x7f, 'E', 'L', 'F', 2, 1, 1, 0},
		"plain prose": []byte("The quick brown fox jumps over the lazy dog. Nothing here.\n"),
		"csv data":    []byte("id,name,total\n1,alpha,42\n2,beta,17\n"),
		"empty":       {},
	}
	for name, data := range cases {
		if got := signsFor(data); len(got) != 0 {
			t.Errorf("%s: signsFor admitted %v, want none", name, got)
		}
	}
}

// An unreadable file admits nothing. The alternative -- admitting every language to a file whose
// content nobody has seen -- is a false-positive engine rather than a detector.
func TestSignCacheRefusesAnUnreadableFile(t *testing.T) {
	c := newSignCache()
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	for _, l := range []weblang.Lang{weblang.PHP, weblang.JSP, weblang.ASP} {
		if c.admits(missing, l) {
			t.Errorf("an unreadable file must admit nothing, but admitted %q", l)
		}
	}
}

// The cache must read a file once, however many rules ask about it.
func TestSignCacheReadsOnce(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "shell.txt")
	if err := os.WriteFile(p, []byte(`<?php eval($_POST["c"]); ?>`), 0o600); err != nil {
		t.Fatal(err)
	}
	c := newSignCache()
	if !c.admits(p, weblang.PHP) {
		t.Fatal("PHP content in a .txt must be admitted by the PHP sign")
	}
	// Remove the file: a second call must still answer from cache rather than re-reading.
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if !c.admits(p, weblang.PHP) {
		t.Error("second call re-read the file instead of using the cache")
	}
}

// The sign must see the WHOLE bounded file, not a leading window. Appending a shell to the tail of a
// legitimate file is a standard infection pattern, and a prefix-only sign is blind to exactly that.
func TestSignSeesAnAppendedShell(t *testing.T) {
	benign := make([]byte, 0, 200000)
	for len(benign) < 180000 {
		benign = append(benign, []byte("Lorem ipsum dolor sit amet, consectetur adipiscing elit. ")...)
	}
	appended := append(benign, []byte("\n<?php system($_GET['c']); ?>\n")...)
	if !signMatches(weblang.PHP, appended) {
		t.Error("a shell appended after 180 KB of prose was not seen; the sign must not read only a prefix")
	}
	if signMatches(weblang.PHP, benign) {
		t.Error("the prose alone matched the PHP sign")
	}
}

func corpusDiskRoot(t *testing.T) string {
	t.Helper()
	for _, rel := range []string{
		filepath.Join("..", "..", "..", "shellsight-corpus", "curated", "disk"),
		filepath.Join("..", "..", "shellsight-corpus", "curated", "disk"),
	} {
		if st, err := os.Stat(rel); err == nil && st.IsDir() {
			return rel
		}
	}
	t.Skip("corpus not present (gitignored)")
	return ""
}
