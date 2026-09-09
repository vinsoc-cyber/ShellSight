//go:build linux

package main

// Spec 007 US1, end to end: the disk probe pointed at a webroot that exists only in another process's
// root view (/proc/<pid>/root/...), the form a responder types from a Kubernetes debug container.
// Measured 2026-08-26 on the v1.0.0-210 bundle: the --path form was refused ("none of the 1 requested
// webroot(s) exist") while the --root form scanned the same files. Both must work and must agree.
//
// These cases need a second mount namespace and the bundled engine, so they only build on Linux and
// skip when either is unavailable (SHELLSIGHT_YR / SHELLSIGHT_RULES_PATH name the engine and rules).

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"shellsight/internal/finding"
	"shellsight/internal/testfixture"
)

// probeRun drives the probe in-process, exactly as the core does, and parses what it emitted.
func probeRun(t *testing.T, args []string, spec finding.TargetSpec) (int, finding.ProbeOutput, string) {
	t.Helper()
	specJSON, err := json.Marshal(spec)
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	rc := runDiskProbe(context.Background(), args, bytes.NewReader(specJSON), &stdout, &stderr)
	var out finding.ProbeOutput
	if rc == exitOK {
		if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
			t.Fatalf("probe output is not ProbeOutput JSON: %v\n%s", err, stdout.String())
		}
	}
	return rc, out, stderr.String()
}

func requireEngine(t *testing.T) (yr, rules string) {
	t.Helper()
	yr = yrPath()
	if yr == "" {
		t.Skip("yr binary not found (set SHELLSIGHT_YR)")
	}
	rules = rulesDir()
	if _, err := os.Stat(rules); err != nil {
		t.Skipf("rules tree not found at %s (set SHELLSIGHT_RULES_PATH): %v", rules, err)
	}
	return yr, rules
}

// startView builds the fixture: the same benign-inert webshell at a path no mechanism knows
// (/mnt/srv/www, reachable only by naming it) and at a conventional location (/srv/www, so --root
// discovery finds it unaided). Skips when this host has /mnt/srv/www itself, because validation
// could then pass on the wrong directory's existence and the case would prove nothing.
func startView(t *testing.T) *testfixture.Namespace {
	t.Helper()
	ns := testfixture.Start(t, []string{"/mnt", "/srv"}, map[string]string{
		"/mnt/srv/www/shell.php":  phpShell,
		"/mnt/srv/www/readme.txt": "plain text, nothing to see",
		"/srv/www/shell.php":      phpShell,
	})
	if _, err := os.Stat("/mnt/srv/www"); err == nil {
		t.Skip("/mnt/srv/www exists in this namespace too; the fixture cannot isolate the case")
	}
	return ns
}

// rulesFor collects the knowledge refs reported against a file, by base name.
func rulesFor(out finding.ProbeOutput, base string) map[string]bool {
	set := map[string]bool{}
	for _, f := range out.Findings {
		if f.Target.File != nil && filepath.Base(f.Target.File.Path) == base {
			set[f.Detection.KnowledgeRef] = true
		}
	}
	return set
}

func TestAnExplicitPathThroughAProcessRootViewIsScanned(t *testing.T) {
	yr, rules := requireEngine(t)
	ns := startView(t)
	target := ns.Path("/mnt/srv/www")

	rc, out, stderr := probeRun(t, []string{"-yr", yr, "-rules", rules},
		finding.TargetSpec{Host: "T", Webroots: []string{target}})
	if rc != exitOK {
		t.Fatalf("the probe refused a directory the operator can list: exit %d: %s", rc, stderr)
	}
	if len(rulesFor(out, "shell.php")) == 0 {
		t.Fatalf("the webshell under the view was not reported (findings=%d)", len(out.Findings))
	}
	if out.Coverage == nil || out.Coverage.Discovery == nil || len(out.Coverage.Discovery.Roots) != 1 {
		t.Fatalf("want exactly one discovered root, got %+v", out.Coverage)
	}
	if r := out.Coverage.Discovery.Roots[0]; r.Mechanism != "explicit" || r.Path != target {
		t.Fatalf("the root must be reported as the operator typed it, got %+v", r)
	}
}

func TestExplicitAndRootFormsReportTheSameFindings(t *testing.T) {
	// US1 scenario 2: naming the directory and letting discovery find it inside --root must agree.
	yr, rules := requireEngine(t)
	ns := startView(t)
	base := []string{"-yr", yr, "-rules", rules}

	rcA, a, errA := probeRun(t, base, finding.TargetSpec{Host: "T", Webroots: []string{ns.Path("/srv/www")}})
	if rcA != exitOK {
		t.Fatalf("--path form: exit %d: %s", rcA, errA)
	}
	rcB, b, errB := probeRun(t, append(base, "-root", ns.Root), finding.TargetSpec{Host: "T"})
	if rcB != exitOK {
		t.Fatalf("--root form: exit %d: %s", rcB, errB)
	}

	ra, rb := rulesFor(a, "shell.php"), rulesFor(b, "shell.php")
	if len(ra) == 0 || !reflect.DeepEqual(ra, rb) {
		t.Fatalf("the two forms must report the same rules for the same file: --path=%v --root=%v", ra, rb)
	}
	found := false
	if b.Coverage != nil && b.Coverage.Discovery != nil {
		for _, r := range b.Coverage.Discovery.Roots {
			if r.Path == ns.Path("/srv/www") && r.Mechanism == "convention" && r.InFilesystem == "/srv/www" {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("--root form must discover /srv/www by convention, served as /srv/www; got %+v", b.Coverage)
	}
}

func TestASymlinkEntryUnderAProcessRootViewIsCountedNotSilent(t *testing.T) {
	// Research R1's disclosed residual: classifySymlink resolves the entry through the magic link into
	// the scanner's own namespace and cannot see that the target is inside the same root, so the
	// entry is counted as not examined. Counted and degraded is the contract; silent would be a defect,
	// and the regular file beside it must still be reported.
	yr, rules := requireEngine(t)
	ns := startView(t)
	// Created THROUGH the view: a write via /proc/<pid>/root/... lands in the child's tmpfs.
	if err := os.Symlink("shell.php", ns.Path("/mnt/srv/www/link.php")); err != nil {
		t.Fatalf("cannot create a symlink through the view: %v", err)
	}
	rc, out, stderr := probeRun(t, []string{"-yr", yr, "-rules", rules},
		finding.TargetSpec{Host: "T", Webroots: []string{ns.Path("/mnt/srv/www")}})
	if rc != exitOK {
		t.Fatalf("exit %d: %s", rc, stderr)
	}
	if len(rulesFor(out, "shell.php")) == 0 {
		t.Fatalf("the regular file beside the symlink was lost")
	}
	if out.Coverage == nil || out.Coverage.Skipped == nil || out.Coverage.Skipped.NonRegular < 1 {
		t.Fatalf("the symlink entry was neither examined nor counted: %+v", out.Coverage)
	}
	if out.Coverage.Status != finding.CovDegraded {
		t.Fatalf("a counted gap must degrade coverage, got %q", out.Coverage.Status)
	}
}
