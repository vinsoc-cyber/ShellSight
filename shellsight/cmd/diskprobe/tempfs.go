package main

import (
	"fmt"
	"os"
)

// The probe's temporary workspace (spec 007 US3, research R4).
//
// Two artifacts are written during a scan: the engine's scan list (yarax.go) and the decoded-layer
// mirror (deobfscan.go). Both used the default temporary location, and in a container whose root
// filesystem is read-only with no writable /tmp that failed the whole view -- measured 2026-08-26,
// `TMPDIR=/proc/nonexistent`: "scan list: open /proc/nonexistent/ss-scanlist-…: no such file or
// directory", verdict unknown, exit 5. The run directory is writable by construction (--out has to
// be), so the core creates it before the probes run and hands its scratch subdirectory down as
// -scratch. The default location is still tried first: /tmp is usually a fast tmpfs, and an ordinary
// run must produce the same bytes it always did.
//
// The fallback is REPORTED (ProbeCoverage.Scratch) so a responder knows transient content briefly
// lived in the evidence folder, and everything written there is removed by the code that wrote it.

// scratchDir is the -scratch argument; empty means no fallback was offered.
var scratchDir string

// scratchUsed is set the first time the fallback is taken, and is what the coverage block reports.
var scratchUsed string

// remedy is the operator-facing fix, spelled once.
const remedy = "set TMPDIR to a writable directory or pass a writable --out"

// tempDir is os.MkdirTemp("", pattern) with the scratch fallback.
func tempDir(pattern string) (string, error) {
	d, err := os.MkdirTemp("", pattern)
	if err == nil {
		return d, nil
	}
	if scratchDir == "" {
		return "", fmt.Errorf("temporary workspace unavailable: %s: %v — %s", os.TempDir(), err, remedy)
	}
	if mkErr := os.MkdirAll(scratchDir, 0o755); mkErr != nil {
		return "", bothFailed(err, mkErr)
	}
	d, err2 := os.MkdirTemp(scratchDir, pattern)
	if err2 != nil {
		return "", bothFailed(err, err2)
	}
	scratchUsed = scratchDir
	return d, nil
}

// tempFile is os.CreateTemp("", pattern) with the scratch fallback.
func tempFile(pattern string) (*os.File, error) {
	f, err := os.CreateTemp("", pattern)
	if err == nil {
		return f, nil
	}
	if scratchDir == "" {
		return nil, fmt.Errorf("temporary workspace unavailable: %s: %v — %s", os.TempDir(), err, remedy)
	}
	if mkErr := os.MkdirAll(scratchDir, 0o755); mkErr != nil {
		return nil, bothFailed(err, mkErr)
	}
	f, err2 := os.CreateTemp(scratchDir, pattern)
	if err2 != nil {
		return nil, bothFailed(err, err2)
	}
	scratchUsed = scratchDir
	return f, nil
}

// bothFailed names both locations and the remedy: the operator has to choose which one to fix.
func bothFailed(defaultErr, scratchErr error) error {
	return fmt.Errorf("temporary workspace unavailable: %s: %v; %s: %v — %s",
		os.TempDir(), defaultErr, scratchDir, scratchErr, remedy)
}
