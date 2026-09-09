//go:build linux

package main

import (
	"os"
	"path/filepath"
	"testing"

	"shellsight/internal/jvmtriage"
)

// The attach-channel check is only meaningful BEFORE this scan attaches. It used to run after, so
// ShellSight observed the socket its own attach had just created and a clean, untouched Tomcat 9
// reported verdict=suspicious / exit 2 in the published archive. Caught by live validation, not by
// a unit test: jvmtriage.Channel was correct in isolation and its own tests passed throughout.
//
// These tests pin the two properties that made the bug possible, so it cannot come back quietly.

func writeStatus(t *testing.T, dir string, body string) string {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "status"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// The nspid must be resolved from /proc/<pid>/status, NOT from the attach result -- getting it from
// the attach is precisely what makes the observation too late.
func TestPreAttachChannelReportsASocketThatAlreadyExisted(t *testing.T) {
	base := t.TempDir()
	nsRoot := t.TempDir()
	writeStatus(t, base, "Uid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\nNStgid:\t4242\t7\n")
	if err := os.MkdirAll(filepath.Join(nsRoot, "tmp"), 0o755); err != nil {
		t.Fatal(err)
	}
	// Named with the INNERMOST nspid (7), which is the number HotSpot uses for itself.
	if err := os.WriteFile(filepath.Join(nsRoot, "tmp", ".java_pid7"), nil, 0o644); err != nil {
		t.Fatal(err)
	}

	got := preAttachChannel(base, nsRoot)
	if len(got) != 1 || got[0].Code != "attach-listener-already-started" {
		t.Fatalf("a pre-existing attach socket must be reported, got %+v", got)
	}
}

// The healthy default. A JVM nobody has attached to has no socket, and that must produce NOTHING --
// this is the case the ordering bug turned into a finding on every host.
func TestPreAttachChannelIsSilentOnAnUntouchedJVM(t *testing.T) {
	base := t.TempDir()
	nsRoot := t.TempDir()
	writeStatus(t, base, "Uid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\nNStgid:\t1\n")
	if err := os.MkdirAll(filepath.Join(nsRoot, "tmp"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := preAttachChannel(base, nsRoot); len(got) != 0 {
		t.Fatalf("an untouched JVM must produce no channel signal, got %+v", got)
	}
}

// Falling OPEN, not closed: with no NStgid there is no way to name the socket, and using the host
// pid would name a path that never appears -- indistinguishable from "nothing attached", but wrong
// for a containerised JVM. Dropping the signal is the honest outcome.
func TestPreAttachChannelDropsTheSignalRatherThanGuessingTheNSPID(t *testing.T) {
	base := t.TempDir()
	nsRoot := t.TempDir()
	writeStatus(t, base, "Uid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\n") // pre-4.1 kernel: no NStgid
	if err := os.MkdirAll(filepath.Join(nsRoot, "tmp"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nsRoot, "tmp", ".java_pid1"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if got := preAttachChannel(base, nsRoot); len(got) != 0 {
		t.Fatalf("with no NStgid the signal must be dropped, not guessed, got %+v", got)
	}
}

// And no attach result is consulted: preAttachChannel takes only proc paths, so it CANNOT depend on
// having attached. A signature change that reintroduced an attach result would fail to compile here.
func TestPreAttachChannelTakesNoAttachResult(t *testing.T) {
	var f func(string, string) []jvmtriage.Signal = preAttachChannel
	_ = f
}
