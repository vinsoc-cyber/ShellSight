//go:build linux

package main

// Spec 002 US3: survive a hostile or unusual webroot.
//
// These cases need real Unix file kinds, so they only build on Linux. They must also RUN on a real
// Linux filesystem: /mnt/c is v9fs and case-insensitive, and creating the fixture there would test
// nothing while appearing to pass (data-model E6). requireUnixFS asserts both properties rather
// than assuming them.
//
// Every case asserts that a known webshell placed BESIDE the offending entry is still reported.
// That is the whole point: the observed failure mode is loss of the entire scan, not of the one
// file. Measured 2026-08-20 before the fix, a directory holding a webshell and a FIFO produced zero
// findings and never terminated.

import (
	"net"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"
)

// netListenUnix creates a real unix socket file in the webroot. A socket is the one non-regular
// kind that appears in ordinary deployments -- php-fpm and gunicorn both leave one behind -- so it
// is a case the scanner meets without an attacker involved.
func netListenUnix(path string) (net.Listener, error) {
	return net.Listen("unix", path)
}

// budget is generous on purpose. The failure being guarded against is unbounded -- a FIFO open that
// never returns -- so any finite budget separates pass from fail, and a loose one keeps the test
// from flaking on a loaded machine.
const budget = 30 * time.Second

// phpShell is a request-to-sink flow the PHP taint pass reports.
const phpShell = `<?php $x = $_GET['x']; system($x);`

// perlShell and pyShell are the equivalent for the Perl/Python pass.
const perlShell = "#!/usr/bin/perl\nmy $CMD = $ENV{'QUERY_STRING'};\nsystem($CMD);\n"
const pyShell = "import cgi\ncmd = cgi.FieldStorage().getvalue(\"c\")\nimport os\nos.system(cmd)\n"

// encodedPHPShell is a base64 layer the deobfuscation mirror unwraps.
const encodedPHPShell = `<?php eval(base64_decode("PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOw==")); ?>`

// requireUnixFS refuses to run on a filesystem that cannot represent the conditions under test.
//
// t.TempDir() follows TMPDIR, so a caller that points it at the Windows mount would otherwise get a
// green run that proved nothing: v9fs is case-insensitive, so the extension-case cases collapse,
// and it may not support mkfifo at all.
func requireUnixFS(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()

	upper := filepath.Join(dir, "CaseProbe.PHP")
	if err := os.WriteFile(upper, []byte("x"), 0o644); err != nil {
		t.Fatalf("fixture dir is not writable: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "caseprobe.php")); err == nil {
		t.Fatalf("fixture dir %s is CASE-INSENSITIVE (v9fs?); set TMPDIR to a native Linux "+
			"filesystem or these cases test nothing", dir)
	}
	if err := os.Remove(upper); err != nil {
		t.Fatal(err)
	}

	fifo := filepath.Join(dir, "kindprobe")
	if err := syscall.Mkfifo(fifo, 0o644); err != nil {
		t.Fatalf("fixture dir %s does not support Unix file kinds: %v", dir, err)
	}
	if err := os.Remove(fifo); err != nil {
		t.Fatal(err)
	}
	return dir
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// mustFinish runs fn and fails if it has not returned within the budget.
//
// The goroutine is deliberately left running on failure: it is blocked in a syscall that will never
// return, which is exactly what is being reported, and Go exits the process regardless of it.
func mustFinish(t *testing.T, what string, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() { defer close(done); fn() }()
	select {
	case <-done:
	case <-time.After(budget):
		t.Fatalf("%s did not return within %s -- the whole scan is lost, not just the file", what, budget)
	}
}

// allocDelta is the bytes fn caused to be allocated. An unbounded read of an endless device shows
// up here as hundreds of megabytes; a bounded one, or a file never opened, as almost nothing.
func allocDelta(fn func()) uint64 {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	fn()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

// runAllPasses exercises every reader the probe has, short of the external engine, and reports
// which files each of them managed to flag.
func runAllPasses(t *testing.T, root string) (php, perlpy int, layers int) {
	t.Helper()
	paths := enumeratedPaths(root)
	php = len(phptaintFindings(paths, "T", newSignCache()))
	perlpy = len(perlpytaintFindings(paths, "T", newSignCache()))
	_, layers, _ = buildDecodedMirror(paths, t.TempDir(), newSignCache())
	return php, perlpy, layers
}

// seedShells writes one webshell per pass into root, so "the webshell is still reported" can be
// asserted for each reader independently.
func seedShells(t *testing.T, root string) {
	t.Helper()
	write(t, filepath.Join(root, "shell.php"), phpShell)
	write(t, filepath.Join(root, "shell.pl"), perlShell)
	write(t, filepath.Join(root, "shell.py"), pyShell)
	write(t, filepath.Join(root, "encoded.php"), encodedPHPShell)
}

// assertShellsStillFound is the US3 acceptance condition, checked identically in every case.
func assertShellsStillFound(t *testing.T, root, condition string) {
	t.Helper()
	var php, perlpy, layers int
	mustFinish(t, "scan of a webroot containing "+condition, func() {
		php, perlpy, layers = runAllPasses(t, root)
	})
	if php == 0 {
		t.Errorf("%s: the PHP taint pass reported nothing; the webshell beside it was lost", condition)
	}
	if perlpy == 0 {
		t.Errorf("%s: the Perl/Python taint pass reported nothing; the webshell beside it was lost", condition)
	}
	if layers == 0 {
		t.Errorf("%s: the deobfuscation mirror produced no layers; the encoded shell was lost", condition)
	}
}

// ---------------------------------------------------------------------------------------------
// T040 -- FIFO
// ---------------------------------------------------------------------------------------------

func TestAFIFODoesNotHangTheScan(t *testing.T) {
	// Before the fix this never terminated: os.Open on a FIFO blocks waiting for a writer, and the
	// block happens before any read bound can apply. Naming it .php guarantees every pass considers
	// it, which is what an attacker who can write to the webroot would do.
	root := requireUnixFS(t)
	seedShells(t, root)
	if err := syscall.Mkfifo(filepath.Join(root, "pipe.php"), 0o644); err != nil {
		t.Fatal(err)
	}
	assertShellsStillFound(t, root, "a FIFO")
}

func TestAFIFOIsCountedAsNotExamined(t *testing.T) {
	root := requireUnixFS(t)
	seedShells(t, root)
	if err := syscall.Mkfifo(filepath.Join(root, "pipe.php"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, skips := enumerateScannable([]string{root})
	if skips.NonRegular() != 1 {
		t.Errorf("nonRegular = %d, want 1: a skipped FIFO must be disclosed, not dropped silently",
			skips.NonRegular())
	}
}

// ---------------------------------------------------------------------------------------------
// T041 -- endless device
// ---------------------------------------------------------------------------------------------

func TestASymlinkToAnEndlessDeviceDoesNotExhaustMemory(t *testing.T) {
	// Before the fix perlpytaintFindings reached 466 MB RSS here and the process died with no
	// output. os.ReadFile on /dev/zero grows until it cannot.
	root := requireUnixFS(t)
	seedShells(t, root)
	if err := os.Symlink("/dev/zero", filepath.Join(root, "zero.php")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/dev/zero", filepath.Join(root, "zero.pl")); err != nil {
		t.Fatal(err)
	}

	var delta uint64
	mustFinish(t, "scan of a webroot containing a link to an endless device", func() {
		delta = allocDelta(func() { runAllPasses(t, root) })
	})
	// Two orders of magnitude below the measured failure, and far above what four small files cost.
	const ceiling = 64 << 20
	if delta > ceiling {
		t.Errorf("scan allocated %d MB, want under %d MB -- the device read is not bounded",
			delta>>20, ceiling>>20)
	}
	assertShellsStillFound(t, root, "a link to an endless device")
}

func TestADeviceLinkIsCountedAsNotExamined(t *testing.T) {
	root := requireUnixFS(t)
	seedShells(t, root)
	if err := os.Symlink("/dev/zero", filepath.Join(root, "zero.php")); err != nil {
		t.Fatal(err)
	}
	_, skips := enumerateScannable([]string{root})
	if skips.NonRegular() != 1 {
		t.Errorf("nonRegular = %d, want 1", skips.NonRegular())
	}
}

// ---------------------------------------------------------------------------------------------
// T042 -- unreadable file
// ---------------------------------------------------------------------------------------------

func TestAnUnreadableFileIsCountedAndDisclosed(t *testing.T) {
	// The defect: it was skipped silently while the run reported success, so an operator could not
	// tell a clean scan from an incomplete one.
	if os.Geteuid() == 0 {
		t.Skip("running as root, which ignores permission bits; the case cannot be constructed")
	}
	root := requireUnixFS(t)
	seedShells(t, root)
	secret := filepath.Join(root, "secret.php")
	write(t, secret, phpShell)
	if err := os.Chmod(secret, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(secret, 0o644) })

	_, skips := enumerateScannable([]string{root})
	if skips.Total() == 0 {
		t.Error("an unreadable file was skipped silently: the run would report success with a gap in it")
	}
	assertShellsStillFound(t, root, "an unreadable file")
}

func TestAnUnreadableDirectoryDoesNotAbortTheWalk(t *testing.T) {
	// FR-014: a directory the scanner cannot open must cost only its own contents.
	if os.Geteuid() == 0 {
		t.Skip("running as root, which ignores permission bits")
	}
	root := requireUnixFS(t)
	seedShells(t, root)
	locked := filepath.Join(root, "locked")
	write(t, filepath.Join(locked, "inner.php"), phpShell)
	if err := os.Chmod(locked, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })

	assertShellsStillFound(t, root, "an unreadable directory")
}

// ---------------------------------------------------------------------------------------------
// T043 -- unix socket (regression: handled today, must stay handled)
// ---------------------------------------------------------------------------------------------

func TestAUnixSocketDoesNotStopTheScan(t *testing.T) {
	root := requireUnixFS(t)
	seedShells(t, root)
	// Bound rather than dialled: an unconnected socket file is the artifact left behind by any
	// daemon with a socket in the webroot, which is the realistic case.
	sock := filepath.Join(root, "app.sock.php")
	l, err := netListenUnix(sock)
	if err != nil {
		t.Skipf("cannot create a unix socket here: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })

	_, skips := enumerateScannable([]string{root})
	if skips.NonRegular() != 1 {
		t.Errorf("nonRegular = %d, want 1", skips.NonRegular())
	}
	assertShellsStillFound(t, root, "a unix socket")
}

// ---------------------------------------------------------------------------------------------
// T044 -- regressions across the remaining E6 conditions
// ---------------------------------------------------------------------------------------------

func TestExtensionCaseVariantsAreEachEnumerated(t *testing.T) {
	// On a case-sensitive filesystem these are four distinct files and all four must be scanned;
	// the language filters lowercase the extension themselves.
	root := requireUnixFS(t)
	for _, name := range []string{"a.php", "b.PHP", "c.Php", "d.pHp"} {
		write(t, filepath.Join(root, name), phpShell)
	}
	if got := len(enumeratedPaths(root)); got != 4 {
		t.Errorf("enumerated %d files, want 4: %v", got, enumeratedPaths(root))
	}
	if n := len(phptaintFindings(enumeratedPaths(root), "T", newSignCache())); n < 4 {
		t.Errorf("PHP taint reported %d findings across 4 case variants, want at least 4", n)
	}
}

func TestASymlinkToARegularFileInsideTheRootIsNotCountedAsAGap(t *testing.T) {
	// Measured: the engine does not scan symlinks, so neither do we -- but the target IS enumerated
	// in its own right, so its content is examined and calling this a coverage gap would be a lie.
	root := requireUnixFS(t)
	write(t, filepath.Join(root, "real.php"), phpShell)
	if err := os.Symlink("real.php", filepath.Join(root, "link.php")); err != nil {
		t.Fatal(err)
	}
	paths, skips := enumerateScannable([]string{root})
	if got := len(allPaths(paths)); got != 1 {
		t.Errorf("enumerated %d files, want 1 (the target, not the link): %v", got, allPaths(paths))
	}
	if skips.Total() != 0 {
		t.Errorf("skips = %d, want 0: the link's content IS examined, via its target", skips.Total())
	}
}

func TestASymlinkEscapingTheRootIsNotExamined(t *testing.T) {
	// FR-018. Before the fix the taint passes reached the target through os.ReadFile, which follows
	// symlinks -- so a link in the webroot pointing anywhere on the host was read AND reported under
	// the in-webroot path. Both an escape and a misattribution.
	base := requireUnixFS(t)
	root := filepath.Join(base, "www")
	outside := filepath.Join(base, "outside")
	write(t, filepath.Join(root, "keep.php"), phpShell)
	write(t, filepath.Join(outside, "secret.php"), phpShell)
	if err := os.Symlink(filepath.Join(outside, "secret.php"), filepath.Join(root, "escape.php")); err != nil {
		t.Fatal(err)
	}

	paths, skips := enumerateScannable([]string{root})
	for _, p := range allPaths(paths) {
		if !pathWithinAny(p, []string{root}) {
			t.Errorf("enumerated %s, which is outside the scanned root", p)
		}
	}
	if skips.NonRegular() != 1 {
		t.Errorf("nonRegular = %d, want 1: a link out of scope is a real gap", skips.NonRegular())
	}
	for _, f := range phptaintFindings(allPaths(paths), "T", newSignCache()) {
		if f.Target.File != nil && filepath.Base(f.Target.File.Path) == "escape.php" {
			t.Error("reported a finding on the escaping link: content from outside the root, " +
				"attributed to a path inside it")
		}
	}
}

func TestACircularSymlinkTerminates(t *testing.T) {
	root := requireUnixFS(t)
	seedShells(t, root)
	if err := os.Symlink("loop.php", filepath.Join(root, "loop.php")); err != nil {
		t.Fatal(err)
	}
	// A second, two-hop cycle: a single self-link is the easy case.
	if err := os.Symlink("pong.php", filepath.Join(root, "ping.php")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("ping.php", filepath.Join(root, "pong.php")); err != nil {
		t.Fatal(err)
	}
	assertShellsStillFound(t, root, "circular symlinks")
}

func TestADirectorySymlinkIsNotDescended(t *testing.T) {
	// Matches both the engine and filepath.WalkDir; descending would double-scan at best and escape
	// the root at worst.
	base := requireUnixFS(t)
	root := filepath.Join(base, "www")
	outside := filepath.Join(base, "outside")
	write(t, filepath.Join(root, "keep.php"), phpShell)
	write(t, filepath.Join(outside, "secret.php"), phpShell)
	if err := os.Symlink(outside, filepath.Join(root, "escape")); err != nil {
		t.Fatal(err)
	}
	for _, p := range enumeratedPaths(root) {
		if filepath.Base(p) == "secret.php" {
			t.Errorf("descended a directory symlink out of the root: %s", p)
		}
	}
}

func TestAHardLinkIsScannedLikeAnyOtherFile(t *testing.T) {
	// A hard link is an ordinary directory entry, and the engine scans it; the allowlist must not
	// invent a distinction the filesystem does not make.
	root := requireUnixFS(t)
	write(t, filepath.Join(root, "real.php"), phpShell)
	if err := os.Link(filepath.Join(root, "real.php"), filepath.Join(root, "hard.php")); err != nil {
		t.Fatal(err)
	}
	if got := len(enumeratedPaths(root)); got != 2 {
		t.Errorf("enumerated %d files, want 2: %v", got, enumeratedPaths(root))
	}
}

func TestAFilenameWithABackslashAndASpaceIsHandled(t *testing.T) {
	// A backslash is an ordinary character in a Linux filename and a path separator on Windows, so
	// it is exactly the shape that corrupts a path passed through a text channel -- which the
	// engine's scan list now is.
	root := requireUnixFS(t)
	odd := `we ird\name.php`
	write(t, filepath.Join(root, odd), phpShell)

	paths := enumeratedPaths(root)
	if len(paths) != 1 {
		t.Fatalf("enumerated %d files, want 1: %v", len(paths), paths)
	}
	list, cleanup, err := writeScanList(paths)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	data, err := os.ReadFile(list)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(data); got != paths[0]+"\n" {
		t.Errorf("scan list = %q, want %q -- the name did not survive the text channel", got, paths[0]+"\n")
	}
	if n := len(phptaintFindings(paths, "T", newSignCache())); n == 0 {
		t.Error("the file was not analysed")
	}
}

func TestAFileWithNoExtensionIsEnumeratedForTheEngine(t *testing.T) {
	// The language passes skip it, but the engine must still see it: a webshell does not need an
	// extension to be served, and yr scans by content.
	root := requireUnixFS(t)
	write(t, filepath.Join(root, "noext"), phpShell)
	if got := enumeratedPaths(root); len(got) != 1 {
		t.Errorf("enumerated %v, want the extensionless file", got)
	}
}

func TestEveryConditionAtOnceStillReportsTheShells(t *testing.T) {
	// The conditions are cheap to survive one at a time and easy to get wrong together, and a real
	// hostile webroot would not be polite enough to contain only one.
	if os.Geteuid() == 0 {
		t.Skip("running as root, which ignores permission bits")
	}
	base := requireUnixFS(t)
	root := filepath.Join(base, "www")
	outside := filepath.Join(base, "outside")
	seedShells(t, root)
	write(t, filepath.Join(outside, "secret.php"), phpShell)

	if err := syscall.Mkfifo(filepath.Join(root, "pipe.php"), 0o644); err != nil {
		t.Fatal(err)
	}
	for target, name := range map[string]string{
		"/dev/zero":    "zero.php",
		"/dev/urandom": "rand.php",
		"/dev/null":    "null.php",
	} {
		if err := os.Symlink(target, filepath.Join(root, name)); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("loop.php", filepath.Join(root, "loop.php")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "escape")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "secret.php"), filepath.Join(root, "escapefile.php")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "missing.php"), filepath.Join(root, "dangling.php")); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(root, `we ird\name.php`), phpShell)
	write(t, filepath.Join(root, "noext"), phpShell)
	if err := os.Link(filepath.Join(root, "shell.php"), filepath.Join(root, "hard.php")); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(root, "unreadable.php")
	write(t, secret, phpShell)
	if err := os.Chmod(secret, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(secret, 0o644) })

	assertShellsStillFound(t, root, "every hostile condition at once")

	_, skips := enumerateScannable([]string{root})
	if skips.Total() == 0 {
		t.Error("nothing was disclosed as skipped, yet the webroot is full of entries that were not examined")
	}
	for _, p := range enumeratedPaths(root) {
		if !pathWithinAny(p, []string{root}) {
			t.Errorf("enumerated %s, outside the scanned root", p)
		}
	}
}
