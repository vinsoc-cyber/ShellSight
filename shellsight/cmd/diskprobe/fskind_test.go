package main

// Cross-platform tests for the reader allowlist. The cases that need real Unix file kinds -- FIFO,
// socket, device -- live in fslinux_test.go, which only builds on Linux. What can be checked
// everywhere is checked everywhere, because the allowlist runs on both platforms and a Windows-only
// divergence would break detection parity (FR-019).

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"shellsight/internal/finding"
)

// scanWebrootDirs is the pre-enumeration signature the older tests were written against: hand it
// directories and it enumerates them exactly as the probe does. Keeping it as a helper rather than
// a second production entry point means those tests exercise the real gate instead of bypassing it.
func scanWebrootDirs(yr, rules string, roots []string, host string) ([]finding.Finding, int, []string) {
	enumerated, _ := enumerateScannable(roots)
	return scanWebroots(context.Background(), yr, rules, false, enumerated, host)
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// enumeratedNames is the base names the enumeration accepted, for readable assertions.
func enumeratedNames(t *testing.T, root string) []string {
	t.Helper()
	rs, _ := enumerateScannable([]string{root})
	var out []string
	for _, r := range rs {
		for _, p := range r.Paths {
			rel, err := filepath.Rel(root, p)
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, filepath.ToSlash(rel))
		}
	}
	return out
}

// enumeratedPaths is the vetted file list under root, for tests that used to hand a directory to a
// pass that now takes paths. Going through the real enumeration rather than a hand-built slice
// means those tests still cover the gate.
func enumeratedPaths(root string) []string {
	rs, _ := enumerateScannable([]string{root})
	return allPaths(rs)
}

func contains(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}

func TestEnumerateAcceptsOrdinaryFilesRegardlessOfExtension(t *testing.T) {
	// The engine scans every file it is given, extension or not; the per-language filters belong to
	// the individual passes. An extension filter here would silently shrink the engine's input.
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "a.php"), "<?php echo 1;")
	writeFile(t, filepath.Join(root, "noext"), "plain")
	writeFile(t, filepath.Join(root, "deep", "b.jsp"), "<% %>")

	got := enumeratedNames(t, root)
	for _, want := range []string{"a.php", "noext", "deep/b.jsp"} {
		if !contains(got, want) {
			t.Errorf("enumeration dropped %q; got %v", want, got)
		}
	}
}

func TestEnumerateReportsZeroSkipsOnAnOrdinaryTree(t *testing.T) {
	// "Nothing was skipped" must be an assertion the scan makes, so an ordinary tree has to produce
	// all-zero counters rather than incidental ones -- otherwise every real scan reads as degraded.
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "a.php"), "<?php echo 1;")
	writeFile(t, filepath.Join(root, "sub", "b.php"), "<?php echo 2;")

	_, skips := enumerateScannable([]string{root})
	if skips.Total() != 0 {
		t.Errorf("ordinary tree reported %d skip(s): nonRegular=%d unreadable=%d oversize=%d",
			skips.Total(), skips.NonRegular(), skips.Unreadable(), skips.Oversize())
	}
}

func TestEnumerateCountsAnOversizeFileButStillScansIt(t *testing.T) {
	// The engine memory-maps its targets, so an enormous file costs it nothing and dropping one
	// would lose a detection it makes today. Only the in-memory Go passes decline it, so the
	// counter is a disclosure and the path still goes to the engine.
	root := t.TempDir()
	big := filepath.Join(root, "big.php")
	if err := os.WriteFile(big, make([]byte, maxScanFileBytes+1), 0o644); err != nil {
		t.Fatal(err)
	}

	rs, skips := enumerateScannable([]string{root})
	if skips.Oversize() != 1 {
		t.Errorf("oversize count = %d, want 1", skips.Oversize())
	}
	if got := allPaths(rs); len(got) != 1 {
		t.Fatalf("engine target list = %v, want the oversize file still present", got)
	}
}

func TestAnOversizeNonSourceFileIsNotCountedAsAGap(t *testing.T) {
	// The in-memory passes filter by extension before reading, so a huge git pack or zip was never
	// going to be read at any size. Counting it would claim a hole that does not exist -- and
	// measured, all 13 corpus files over the bound are exactly that, several of them inside benign
	// populations, so an ordinary WordPress checkout would otherwise read as degraded forever.
	root := t.TempDir()
	big := filepath.Join(root, "pack-abc123.pack")
	if err := os.WriteFile(big, make([]byte, maxScanFileBytes+1), 0o644); err != nil {
		t.Fatal(err)
	}

	rs, skips := enumerateScannable([]string{root})
	if skips.Oversize() != 0 {
		t.Errorf("oversize = %d, want 0: a .pack is not something any pass would have read",
			skips.Oversize())
	}
	if got := allPaths(rs); len(got) != 1 {
		t.Errorf("engine target list = %v, want the file still present", got)
	}
}

func TestSkipsAreCountedByDistinctPathNotByOccurrence(t *testing.T) {
	// Several passes consider the same file. One unreadable entry is one file not examined, not
	// one per pass, or the disclosed number would be meaningless.
	var s scanSkips
	s.markNonRegular("/a/pipe")
	s.markNonRegular("/a/pipe")
	s.markNonRegular("/a/pipe")
	s.markUnreadable("/a/secret")
	if s.NonRegular() != 1 || s.Unreadable() != 1 || s.Total() != 2 {
		t.Errorf("nonRegular=%d unreadable=%d total=%d, want 1/1/2",
			s.NonRegular(), s.Unreadable(), s.Total())
	}
}

func TestPathWithinAnyRejectsASiblingWithASharedPrefix(t *testing.T) {
	// Prefix comparison would place /srv/www-backup inside /srv/www and let a link escape into it.
	base := t.TempDir()
	root := filepath.Join(base, "www")
	sibling := filepath.Join(base, "www-backup")
	writeFile(t, filepath.Join(root, "keep"), "x")
	writeFile(t, filepath.Join(sibling, "secret"), "x")

	if pathWithinAny(filepath.Join(sibling, "secret"), []string{root}) {
		t.Error("a sibling directory sharing a name prefix was treated as inside the root")
	}
	if !pathWithinAny(filepath.Join(root, "keep"), []string{root}) {
		t.Error("a file genuinely inside the root was treated as outside")
	}
}

func TestEnumerateSurvivesAMissingRoot(t *testing.T) {
	// A webroot that does not exist must not panic or abort the other roots (FR-014).
	real := t.TempDir()
	writeFile(t, filepath.Join(real, "a.php"), "<?php echo 1;")

	rs, _ := enumerateScannable([]string{filepath.Join(real, "does-not-exist"), real})
	if len(allPaths(rs)) != 1 {
		t.Errorf("a missing root cost the real root its files: %v", allPaths(rs))
	}
}

func TestWriteScanListDropsAPathContainingANewline(t *testing.T) {
	// A newline in a filename would inject a bogus entry into the list yr reads line by line. On
	// Linux that is a legal filename and the webroot is attacker-writable.
	list, cleanup, err := writeScanList([]string{"/a/good.php", "/a/ev\nil.php", "/a/also-good.php"})
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	data, err := os.ReadFile(list)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(data); got != filepath.Clean("/a/good.php")+"\n"+filepath.Clean("/a/also-good.php")+"\n" {
		t.Errorf("scan list = %q, want the newline-bearing path dropped", got)
	}
}

func TestWriteScanListCleansUpAfterItself(t *testing.T) {
	list, cleanup, err := writeScanList([]string{"/a/x.php"})
	if err != nil {
		t.Fatal(err)
	}
	cleanup()
	if _, err := os.Stat(list); !os.IsNotExist(err) {
		t.Errorf("scan list %s survived cleanup (err=%v)", list, err)
	}
}

func TestRunYaraXOnAnEmptyTargetListDoesNotInvokeTheEngine(t *testing.T) {
	// A root whose every entry was a device or a FIFO is a scanned root that found nothing, not a
	// failed one. Passing a bogus engine path proves the engine was never launched.
	out, err := runYaraX(context.Background(), filepath.Join(t.TempDir(), "no-such-yr"), "rules", false, nil)
	if err != nil {
		t.Errorf("empty target list reported an error: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("empty target list produced output: %q", out)
	}
}
