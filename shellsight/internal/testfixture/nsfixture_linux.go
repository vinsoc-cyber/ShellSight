//go:build linux

// Package testfixture builds test fixtures that ordinary temp directories cannot express.
//
// The one it exists for is a filesystem that is visible ONLY through another process's root view,
// /proc/<pid>/root -- what a responder sees from a Kubernetes debug container that shares the pod's
// process namespace (spec 007, research R1/R7). No container runtime is available on the verification
// host, so the fixture is an unprivileged user+mount namespace: `unshare -Urm` mounts a tmpfs over
// existing directories and the files written there exist nowhere in the caller's own namespace.
//
// Measured 2026-08-26 on the WSL2 host (kernel 6.18, util-linux 2.41.3): `unshare -Urm` succeeds
// without privilege, and the caller can read /proc/<pid>/root/... of the child because the child's
// user namespace is owned by the same uid. Where either is refused the fixture SKIPS with the reason
// rather than failing: a host that cannot express the condition has not found a defect.
package testfixture

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// Namespace is a parked process whose root view holds the fixture.
type Namespace struct {
	// PID of the parked process. /proc/<PID>/root is the view; the path is what a responder types.
	PID int
	// Root is "/proc/<PID>/root".
	Root string
	cmd  *exec.Cmd
}

// Start creates the namespace. tmpfsAt lists directories that MUST already exist on this host; a
// tmpfs is mounted over each of them inside the child only. files maps in-namespace absolute paths
// to content; every path must lie under one of the tmpfs mounts, because anything else would be
// written to the host's real filesystem.
//
// The child is `unshare -Urm bash -c <script>` with no --fork, so the process unshare starts IS the
// namespaced process and cmd.Process.Pid is the PID whose root view carries the fixture.
func Start(t testing.TB, tmpfsAt []string, files map[string]string) *Namespace {
	t.Helper()
	if _, err := exec.LookPath("unshare"); err != nil {
		t.Skip("cross-namespace fixture: unshare(1) is not installed")
	}
	if len(tmpfsAt) == 0 {
		t.Fatal("cross-namespace fixture: at least one tmpfs mountpoint is required")
	}
	for _, m := range tmpfsAt {
		if !filepath.IsAbs(m) {
			t.Fatalf("cross-namespace fixture: mountpoint %q is not absolute", m)
		}
		if fi, err := os.Stat(m); err != nil || !fi.IsDir() {
			t.Fatalf("cross-namespace fixture: mountpoint %q must exist on this host as a directory", m)
		}
	}

	// Stage the files in the caller's namespace; the child copies each mount's subtree over its tmpfs.
	stage := t.TempDir()
	names := make([]string, 0, len(files))
	for p := range files {
		names = append(names, p)
	}
	sort.Strings(names)
	for _, p := range names {
		if !filepath.IsAbs(p) || !underAny(p, tmpfsAt) {
			t.Fatalf("cross-namespace fixture: %q is not under a tmpfs mountpoint %v", p, tmpfsAt)
		}
		dst := filepath.Join(stage, p)
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dst, []byte(files[p]), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	var sb strings.Builder
	sb.WriteString("set -e\n")
	for _, m := range tmpfsAt {
		fmt.Fprintf(&sb, "mount -t tmpfs none %q\n", m)
		fmt.Fprintf(&sb, "if [ -d %q ]; then cp -a %q %q; fi\n", filepath.Join(stage, m), filepath.Join(stage, m)+"/.", m+"/")
	}
	sb.WriteString("echo READY\nexec sleep 3600\n")

	cmd := exec.Command("unshare", "-Urm", "--", "bash", "-c", sb.String())
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Skipf("cross-namespace fixture: cannot start unshare: %v", err)
	}
	ns := &Namespace{PID: cmd.Process.Pid, Root: fmt.Sprintf("/proc/%d/root", cmd.Process.Pid), cmd: cmd}

	ready := make(chan error, 1)
	go func() {
		sc := bufio.NewScanner(stdout)
		for sc.Scan() {
			if strings.TrimSpace(sc.Text()) == "READY" {
				ready <- nil
				return
			}
		}
		ready <- errors.New("child exited before READY")
	}()
	select {
	case err := <-ready:
		if err != nil {
			ns.Stop()
			msg := strings.TrimSpace(stderr.String())
			if strings.Contains(msg, "Operation not permitted") || strings.Contains(msg, "not permitted") {
				t.Skipf("cross-namespace fixture: unprivileged user namespaces are refused here: %s", msg)
			}
			t.Fatalf("cross-namespace fixture: %v: %s", err, msg)
		}
	case <-time.After(15 * time.Second):
		ns.Stop()
		t.Fatalf("cross-namespace fixture: child did not become ready: %s", strings.TrimSpace(stderr.String()))
	}
	t.Cleanup(ns.Stop)
	return ns
}

// Path returns the caller-namespace path of an in-namespace absolute path: the form a responder types.
func (n *Namespace) Path(inNS string) string { return filepath.Join(n.Root, inNS) }

// Stop tears the namespace down. Idempotent.
func (n *Namespace) Stop() {
	if n == nil || n.cmd == nil || n.cmd.Process == nil {
		return
	}
	_ = n.cmd.Process.Kill()
	_ = n.cmd.Wait()
	n.cmd = nil
}

func underAny(p string, roots []string) bool {
	for _, r := range roots {
		rel, err := filepath.Rel(r, p)
		if err == nil && rel != ".." && !strings.HasPrefix(rel, "../") && !filepath.IsAbs(rel) {
			return true
		}
	}
	return false
}
