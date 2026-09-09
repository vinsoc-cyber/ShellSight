package main

// Spec 007 US3 / research R4: the disk view writes two temporary artifacts -- the yr scan list and the
// decoded-layer mirror -- and until this feature it could only write them to the default temporary
// location. In a container with a read-only root filesystem and no writable /tmp that failed the whole
// view: measured 2026-08-26, `TMPDIR=/proc/nonexistent` → "scan list: open /proc/nonexistent/
// ss-scanlist-…: no such file or directory", exit 5. The run directory is writable by construction
// (--out has to be), so it is the fallback -- and the report says when it was used.

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"shellsight/internal/finding"
)

// unwritableTemp points every temp-location variable Go consults (TMPDIR on Unix; TMP/TEMP on
// Windows) at a directory that does not exist, so os.CreateTemp("") and os.MkdirTemp("") fail.
func unwritableTemp(t *testing.T) string {
	t.Helper()
	gone := filepath.Join(t.TempDir(), "does-not-exist")
	t.Setenv("TMPDIR", gone)
	t.Setenv("TMP", gone)
	t.Setenv("TEMP", gone)
	return gone
}

func scratchProbeRun(t *testing.T, args []string, root string) (int, finding.ProbeOutput, string) {
	t.Helper()
	specJSON, _ := json.Marshal(finding.TargetSpec{Host: "T", Webroots: []string{root}})
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

// Benign-inert fixtures: a webshell by SHAPE (request input reaching an exec sink), which is what the
// detectors match. Duplicated from fslinux_test.go because that file only builds on Linux and these
// cases are platform-neutral.
const (
	scratchPHPShell     = `<?php $x = $_GET['x']; system($x);`
	scratchEncodedShell = `<?php eval(base64_decode("PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOw==")); ?>`
)

func smallWebroot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "shell.php"), []byte(scratchPHPShell), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "encoded.php"), []byte(scratchEncodedShell), 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}

func engineOrSkip(t *testing.T) (string, string) {
	t.Helper()
	yr := yrPath()
	if yr == "" {
		t.Skip("yr binary not found (set SHELLSIGHT_YR)")
	}
	rules := rulesDir()
	if _, err := os.Stat(rules); err != nil {
		t.Skipf("rules tree not found: %v", err)
	}
	return yr, rules
}

func TestAnUnwritableTempLocationFallsBackToTheScratchDirectory(t *testing.T) {
	yr, rules := engineOrSkip(t)
	root := smallWebroot(t)
	scratch := filepath.Join(t.TempDir(), "run_T_1", "scratch")
	unwritableTemp(t)

	rc, out, stderr := scratchProbeRun(t, []string{"-yr", yr, "-rules", rules, "-scratch", scratch}, root)
	if rc != exitOK {
		t.Fatalf("with a writable scratch directory the scan must complete; exit %d: %s", rc, stderr)
	}
	if out.Coverage == nil || out.Coverage.Scratch != scratch {
		t.Fatalf("the report must say where the workspace went; want %q, got %+v", scratch, out.Coverage)
	}
	if len(out.Findings) == 0 {
		t.Fatalf("the scan under the fallback must still report the fixture webshell")
	}
	entries, err := os.ReadDir(scratch)
	if err != nil {
		t.Fatalf("the scratch directory must exist after the run (the core removes it): %v", err)
	}
	if len(entries) != 0 {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("the probe must remove what it wrote into the scratch directory, left: %v", names)
	}
}

func TestNoWritableLocationFailsTheViewNamingBothAndTheRemedy(t *testing.T) {
	yr, rules := engineOrSkip(t)
	root := smallWebroot(t)
	gone := unwritableTemp(t)
	// A scratch path whose parent is a FILE cannot be created on any platform.
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	scratch := filepath.Join(blocker, "scratch")

	rc, _, stderr := scratchProbeRun(t, []string{"-yr", yr, "-rules", rules, "-scratch", scratch}, root)
	if rc != exitCoverage {
		t.Fatalf("with nothing writable the view must fail (exit %d), got %d: %s", exitCoverage, rc, stderr)
	}
	for _, want := range []string{"temporary workspace unavailable", gone, scratch,
		"set TMPDIR to a writable directory or pass a writable --out"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("the failure must name %q, got:\n%s", want, stderr)
		}
	}
}

func TestAWritableTempLocationLeavesTheReportUnchanged(t *testing.T) {
	// Byte-stability for every ordinary run: no scratch key unless the fallback was used.
	yr, rules := engineOrSkip(t)
	root := smallWebroot(t)
	scratch := filepath.Join(t.TempDir(), "scratch")

	rc, out, stderr := scratchProbeRun(t, []string{"-yr", yr, "-rules", rules, "-scratch", scratch}, root)
	if rc != exitOK {
		t.Fatalf("exit %d: %s", rc, stderr)
	}
	if out.Coverage == nil || out.Coverage.Scratch != "" {
		t.Fatalf("a run that never needed the fallback must not report a scratch workspace, got %+v", out.Coverage)
	}
	if _, err := os.Stat(scratch); err == nil {
		t.Fatalf("the scratch directory must not be created when it is not needed")
	}
	raw, _ := json.Marshal(out.Coverage)
	if bytes.Contains(raw, []byte(`"scratch"`)) {
		t.Fatalf("scratch must be omitempty, got %s", raw)
	}
}
