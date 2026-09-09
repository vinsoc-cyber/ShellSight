package discover

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// T092 / FR-034: the dead-box capability must survive the arrival of the exec-based sources.
//
// This is the axis the tool leads on. The incumbent's discovery is process-based and cannot do any of
// it: a mounted image, a snapshot, or a host whose web server is stopped. The risk when adding
// `nginx -T` and `apache2ctl -S` is that they quietly become the real implementation and config
// parsing rots into a fallback nobody tests -- at which point the lead is gone and nothing says so.
//
// Measured on the WSL host while building this: `apache2ctl -S` succeeded with ZERO apache2 processes
// running, because -S only parses configuration. So a stopped SERVICE is not the hard case. The hard
// case is a mounted image: the configuration is all there and none of the binaries are, so no dump
// can run at all.

// mountedImage builds a config tree that is not this host's, with no binaries available.
func mountedImage(t *testing.T) (apacheRoot, nginxRoot string) {
	t.Helper()
	img := t.TempDir()

	apacheRoot = filepath.Join(img, "srv", "apache-site")
	nginxRoot = filepath.Join(img, "srv", "nginx-site")
	for _, d := range []string{apacheRoot, nginxRoot} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	apacheConf := filepath.Join(img, "etc", "apache2", "apache2.conf")
	nginxConf := filepath.Join(img, "etc", "nginx", "nginx.conf")
	for _, f := range []string{apacheConf, nginxConf} {
		if err := os.MkdirAll(filepath.Dir(f), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write := func(path, body string) {
		if err := os.WriteFile(path, []byte(body), 0o400); err != nil { // read-only file
			t.Fatal(err)
		}
	}
	write(apacheConf, "ServerName image.example\nDocumentRoot "+filepath.ToSlash(apacheRoot)+"\n")
	write(nginxConf, "http {\n  server {\n    root "+filepath.ToSlash(nginxRoot)+";\n  }\n}\n")

	priorA, priorN := apacheConfigPaths, nginxConfigPaths
	apacheConfigPaths = func() []string { return []string{apacheConf} }
	nginxConfigPaths = func() []string { return []string{nginxConf} }

	// No binaries: an image carries the target host's filesystem, not runnable programs for it.
	priorLook, priorRun := lookPath, runCommand
	lookPath = func(string) (string, error) { return "", errors.New("no such file or directory") }
	runCommand = func(string, ...string) ([]byte, error) {
		t.Error("nothing may be executed against a mounted image")
		return nil, errors.New("unreachable")
	}

	t.Cleanup(func() {
		apacheConfigPaths, nginxConfigPaths = priorA, priorN
		lookPath, runCommand = priorLook, priorRun
	})
	return apacheRoot, nginxRoot
}

func TestAMountedImageIsStillDiscovered(t *testing.T) {
	apacheRoot, nginxRoot := mountedImage(t)
	res := Discover(nil, Options{})

	byPath := map[string]Root{}
	for _, r := range res.Roots {
		byPath[pathKey(r.Path)] = r
	}
	for _, want := range []string{apacheRoot, nginxRoot} {
		r, ok := byPath[pathKey(want)]
		if !ok {
			t.Fatalf("config parsing must still find %q with no binaries available, got %+v", want, res.Roots)
		}
		// The mechanism must be the config reader, not a dump. If a dump ever satisfied this test, the
		// primary method would have become the fallback without anyone noticing.
		if !strings.HasSuffix(string(r.Mechanism), "-config") {
			t.Errorf("root %q was attributed to %q; config parsing must be what found it", want, r.Mechanism)
		}
	}
}

func TestTheDumpsReportUnavailableOnAnImageRatherThanFailing(t *testing.T) {
	// An image has no binaries to run. That is a fact about the target, not an error in the scan, and
	// it must not degrade the verdict — the configuration was read and the roots were found.
	mountedImage(t)
	res := Discover(nil, Options{})
	seen := map[Mechanism]Outcome{}
	for _, o := range res.Outcomes {
		seen[o.Mechanism] = o
	}
	for _, m := range ExecMechanisms() {
		o, ok := seen[m]
		if !ok {
			t.Fatalf("mechanism %q must still account for itself", m)
		}
		if o.Status != StatusUnavailable {
			t.Errorf("%q on an image must be unavailable, got %+v", m, o)
		}
		if o.Detail == "" {
			t.Errorf("%q must say why it could not run", m)
		}
	}
}

func TestAReadOnlyConfigTreeIsEnoughToDiscover(t *testing.T) {
	// A mounted image is read-only, and so is a snapshot. Discovery must never need to write: the
	// config files above are mode 0400, and their directories are made read-only here too.
	apacheRoot, _ := mountedImage(t)
	if runtime.GOOS != "windows" {
		// chmod is meaningful on Linux; on Windows NTFS ACLs do not map onto it and the 0400 files
		// already carry the property this asserts.
		for _, d := range []string{filepath.Dir(apacheRoot)} {
			if err := os.Chmod(d, 0o555); err != nil {
				t.Skipf("cannot make the tree read-only: %v", err)
			}
			defer os.Chmod(d, 0o755) //nolint:errcheck // best effort so TempDir cleanup succeeds
		}
	}
	res := Discover(nil, Options{})
	if len(res.Roots) == 0 {
		t.Fatalf("a read-only config tree must still yield roots, rejected=%+v", res.Rejected)
	}
}

func TestRefusingEveryExecStillDiscoversFromConfig(t *testing.T) {
	// The operator-facing version of the same guarantee: someone who refuses every exec on a
	// compromised host must not thereby lose discovery. If they did, the safe choice would be the
	// one that finds nothing, and nobody would make it.
	apacheRoot, nginxRoot := mountedImage(t)
	refuse := map[Mechanism]bool{}
	for _, m := range ExecMechanisms() {
		refuse[m] = true
	}
	res := Discover(nil, Options{Refuse: refuse})
	found := map[string]bool{}
	for _, r := range res.Roots {
		found[pathKey(r.Path)] = true
	}
	if !found[pathKey(apacheRoot)] || !found[pathKey(nginxRoot)] {
		t.Fatalf("refusing every exec must not cost config-derived roots, got %+v", res.Roots)
	}
}
