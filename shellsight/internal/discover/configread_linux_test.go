package discover

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Discovery reads configuration with os.ReadFile. cmd/diskprobe/fskind.go exists because two file
// kinds break exactly that call, and both were release-blocking for this port:
//
//	a FIFO              os.Open blocks FOREVER, waiting for a writer
//	a symlink to /dev/zero  an unbounded read grows until the process dies (measured at 466 MB)
//
// The scanner is guarded. Discovery is the same process reading attacker-writable paths -- /etc/nginx/
// nginx.conf, /etc/apache2/apache2.conf, $CATALINA_BASE/conf/server.xml -- and an intruder who can
// replace one of those with a FIFO takes the whole scan down before a single file is examined.
//
// Linux-only: creating a FIFO needs a filesystem that has them, which is why scripts/linux/
// check-fixture-fs.sh refuses to let this run on /mnt/c.

// discoverWithin runs Discover and reports whether it returned inside the budget. A hang is the
// failure under test, so it must not become a hung test run.
func discoverWithin(t *testing.T, budget time.Duration) (Result, bool) {
	t.Helper()
	type outcome struct{ res Result }
	done := make(chan outcome, 1)
	go func() {
		// Leaks if Discover hangs. Acceptable: the test has already failed at that point and the
		// process is about to exit.
		// Isolated to nginx-config, the mechanism these fixtures actually stub. Coverage is
		// unchanged -- the FIFO is created at the nginx path -- and the host is kept out of it.
		done <- outcome{Discover(nil, onlyNginxConfig())}
	}()
	select {
	case o := <-done:
		return o.res, true
	case <-time.After(budget):
		return Result{}, false
	}
}

func pointConfigAt(t *testing.T, path string) {
	t.Helper()
	prior := nginxConfigPaths
	nginxConfigPaths = func() []string { return []string{path} }
	t.Cleanup(func() { nginxConfigPaths = prior })
}

func TestAFifoInPlaceOfAConfigFileDoesNotHangDiscovery(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "nginx.conf")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("cannot create a FIFO here: %v", err)
	}
	pointConfigAt(t, fifo)

	start := time.Now()
	res, returned := discoverWithin(t, 5*time.Second)
	if !returned {
		t.Fatal("discovery hung on a FIFO in place of a config file: an intruder who can replace " +
			"/etc/nginx/nginx.conf takes the whole scan down before a single file is examined")
	}
	t.Logf("returned in %v", time.Since(start))

	// Returning fast is half of it. Nothing benign turns nginx.conf into a FIFO, so on a compromised
	// host this is a LEAD -- and silently skipping it would leave the operator with a scan that found
	// no Nginx roots and no reason why.
	if note := nginxDetail(res); !strings.Contains(note, "not an ordinary file") {
		t.Errorf("the refusal must be reported, got detail %q", note)
	}
}

// nginxDetail is the nginx-config mechanism's reported detail, or "".
func nginxDetail(res Result) string {
	for _, o := range res.Outcomes {
		if o.Mechanism == MechNginxConfig {
			return o.Detail
		}
	}
	return ""
}

func TestAFifoNamedByTheApacheDumpDoesNotHangDiscovery(t *testing.T) {
	// The second door to the same defect. `-S` output is attacker-influenced twice over: an intruder
	// who can edit the Apache config chooses which paths appear in the dump, and can make one of them
	// a FIFO. Reading those unguarded would reopen the hang after the config path was closed.
	dir := t.TempDir()
	fifo := filepath.Join(dir, "hidden.conf")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("cannot create a FIFO here: %v", err)
	}
	dump := "VirtualHost configuration:\n*:8081  hidden.example (" + fifo + ":1)\n" +
		"ServerRoot: \"/etc/apache2\"\nMain DocumentRoot: \"/var/www/html\"\n"

	priorRun, priorLook := runCommand, lookPath
	runCommand = func(string, ...string) ([]byte, error) { return []byte(dump), nil }
	lookPath = func(name string) (string, error) { return "/usr/sbin/" + name, nil }
	t.Cleanup(func() { runCommand, lookPath = priorRun, priorLook })

	done := make(chan []Outcome, 1)
	go func() {
		_, out := apacheDumpRoots(Options{})
		done <- out
	}()
	select {
	case outcomes := <-done:
		// It must also SAY so: a vhost file that is a FIFO is not something a working server produces.
		if len(outcomes) == 0 || !strings.Contains(outcomes[0].Detail, "not an ordinary file") {
			t.Errorf("the refused vhost file must be reported, got %+v", outcomes)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("apacheDumpRoots hung on a FIFO named by -S: the config-read guard was applied to the " +
			"config paths and not to the paths the dump points at")
	}
}

func TestACharacterDeviceInPlaceOfAConfigFileDoesNotExhaustMemory(t *testing.T) {
	// /dev/zero yields bytes forever. An unbounded read of it is the second half of the same defect,
	// and it is why the scanner checks file KIND rather than trusting a name.
	if _, err := os.Stat("/dev/zero"); err != nil {
		t.Skip("no /dev/zero here")
	}
	pointConfigAt(t, "/dev/zero")

	start := time.Now()
	res, returned := discoverWithin(t, 5*time.Second)
	if !returned {
		t.Fatal("discovery did not return within 5s reading /dev/zero as a config file: an unbounded " +
			"read grows until the process dies")
	}
	t.Logf("returned in %v", time.Since(start))
	if note := nginxDetail(res); !strings.Contains(note, "not an ordinary file") {
		t.Errorf("a character device in place of a config must be reported, got detail %q", note)
	}
}

func TestAnOversizeConfigFileIsNotReadWhole(t *testing.T) {
	// A regular file is the case a kind check alone would miss: 512 MiB of valid-looking directives is
	// an ordinary file by every stat, and reading it whole is a memory spike an attacker chooses.
	dir := t.TempDir()
	conf := filepath.Join(dir, "nginx.conf")
	f, err := os.Create(conf)
	if err != nil {
		t.Fatal(err)
	}
	// Sparse where the filesystem allows it, so the fixture costs no real disk.
	const size = 512 << 20
	if err := f.Truncate(size); err != nil {
		f.Close()
		t.Skipf("cannot create a sparse fixture: %v", err)
	}
	// `root` must start its own line: nginxRootRe anchors there on purpose, so that it never
	// matches fastcgi_temp_path and friends.
	if _, err := f.WriteAt([]byte("http {\n  server {\n    root /srv/real-site;\n  }\n}\n"), 0); err != nil {
		f.Close()
		t.Fatal(err)
	}
	f.Close()
	pointConfigAt(t, conf)

	start := time.Now()
	res, returned := discoverWithin(t, 20*time.Second)
	if !returned {
		t.Fatal("discovery did not return within 20s on a 512 MiB config file")
	}
	t.Logf("returned in %v with %d root(s), %d rejection(s)", time.Since(start), len(res.Roots), res.RejectedTotal)

	// Truncating is the right trade -- refusing would fail toward missing a webroot -- but it has to
	// be disclosed, and the root at the start of the file must still be found.
	if note := nginxDetail(res); !strings.Contains(note, "exceeded") {
		t.Errorf("a truncated read must say so, got detail %q", note)
	}
	var sawReal bool
	for _, r := range res.Roots {
		if strings.Contains(r.Path, "real-site") {
			sawReal = true
		}
	}
	if !sawReal {
		// The directory does not exist, so it is a rejection rather than a root -- either way the
		// directive must have been PARSED out of the truncated read.
		if res.RejectedTotal == 0 {
			t.Error("the directive at the start of the oversize file must still be parsed")
		}
	}
}
