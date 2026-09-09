//go:build linux

package discover

// Spec 007 US1 / research R1: a webroot that is reachable only through another process's root view,
// /proc/<pid>/root/... -- what a responder sees from a Kubernetes debug container sharing the pod's
// process namespace. Measured 2026-08-26 on the v1.0.0-210 bundle: `--path /proc/512/root/mnt/srv/www`
// was refused with "none of the 1 requested webroot(s) exist" while `ls` listed 259 files, because
// validateRoot canonicalised the operator's path with EvalSymlinks and the magic link resolves to the
// scanner's own `/`. proc_pid_root(5): "this file is not merely a symbolic link. It provides the same
// view of the filesystem (including namespaces and the set of per-process mounts) as the process
// itself." These cases need a real second mount namespace, so they only build on Linux and skip
// where unprivileged namespaces are refused.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"shellsight/internal/testfixture"
)

// viewOnlyWebroot returns the caller-namespace path of a directory that exists only in a child
// namespace, skipping when this host happens to have the same path in its own namespace (the
// fixture would then not isolate the case: validation could pass on the wrong directory's existence,
// which is exactly the intermittency research R1 records).
func viewOnlyWebroot(t *testing.T) string {
	t.Helper()
	ns := testfixture.Start(t, []string{"/mnt"}, map[string]string{
		"/mnt/srv/www/index.php": "<?php echo 1;",
	})
	if _, err := os.Stat("/mnt/srv/www"); err == nil {
		t.Skip("/mnt/srv/www exists in this namespace too, so the fixture cannot isolate the case")
	}
	p := ns.Path("/mnt/srv/www")
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("fixture not visible through the process-root view: %v", err)
	}
	return p
}

func TestAnExplicitPathThroughAProcessRootViewIsAccepted(t *testing.T) {
	p := viewOnlyWebroot(t)
	res := assemble([]Root{{Path: p, Mechanism: MechExplicit}}, nil)
	if len(res.Roots) != 1 || res.Roots[0].Path != p {
		t.Fatalf("a directory the operator can list must be scanned as typed; got roots=%v rejected=%+v",
			res.Roots, res.Rejected)
	}
}

func TestADiscoveredPathThroughAProcessRootViewStillFailsClosed(t *testing.T) {
	// The relaxation is for the OPERATOR only. A path derived from attacker-writable input keeps the
	// resolve-then-contain gate, and a path that cannot be resolved stays refused (FR-003).
	p := viewOnlyWebroot(t)
	res := assemble([]Root{{Path: p, Mechanism: MechNginxConfig, Source: "/etc/nginx/nginx.conf"}}, nil)
	if len(res.Roots) != 0 {
		t.Fatalf("a discovered path that cannot be resolved must not be scanned, got %v", res.Roots)
	}
	if len(res.Rejected) != 1 || !strings.Contains(res.Rejected[0].Reason, "cannot be resolved") {
		t.Fatalf("want a 'cannot be resolved' rejection, got %+v", res.Rejected)
	}
}

func TestAnUnreadableExplicitPathIsRefusedWithTheReason(t *testing.T) {
	// The operator's path is exempt from canonicalisation, not from being readable: a directory the
	// scanner cannot open would otherwise reach the walk and report a clean scan of nothing.
	if os.Geteuid() == 0 {
		t.Skip("root ignores permission bits; the unreadable case cannot be built")
	}
	dir := filepath.Join(t.TempDir(), "locked")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
	res := assemble([]Root{{Path: dir, Mechanism: MechExplicit}}, nil)
	if len(res.Roots) != 0 {
		t.Fatalf("an unreadable directory must not be reported as scanned, got %v", res.Roots)
	}
	if len(res.Rejected) != 1 || !strings.HasPrefix(res.Rejected[0].Reason, "the directory cannot be read") {
		t.Fatalf("want 'the directory cannot be read: ...', got %+v", res.Rejected)
	}
}
