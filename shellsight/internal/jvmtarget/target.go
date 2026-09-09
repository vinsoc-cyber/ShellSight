// Package jvmtarget enumerates JVM processes from a /proc tree.
//
// The tree is a parameter, not a constant, for two reasons: tests must run on a machine with no
// JVM (and on Windows), and inspecting a container from the host reads through
// /proc/<hostpid>/root.
package jvmtarget

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Target is one JVM the sweep found.
type Target struct {
	PID    int
	Comm   string
	Argv   []string
	Server string // tomcat | spring-boot | jetty | jboss | unknown
	Found  string // how it was recognised, for the operator
}

// SweepResult is everything one pass over the process table saw.
//
// Unreadable is part of the answer, not a footnote: "no JVM found" means something very different
// when 4 of 400 entries were readable than when all 400 were. hidepid=2, a container namespace, or
// an unprivileged responder account each hide most of the table.
//
// Named SweepResult rather than Sweep because Go has one namespace for types and functions, and
// Sweep is the function.
type SweepResult struct {
	Targets    []Target
	Examined   int
	Unreadable int
}

// Sweep walks procRoot and returns every process that looks like a JVM.
func Sweep(procRoot string) SweepResult {
	var out SweepResult
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return out
	}
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue // "self", "sys", "net" — not processes
		}
		out.Examined++
		argv, ok := readCmdline(filepath.Join(procRoot, e.Name(), "cmdline"))
		if !ok {
			out.Unreadable++
			continue
		}
		comm := readComm(filepath.Join(procRoot, e.Name(), "comm"))
		if !isJVM(comm, argv) {
			continue
		}
		server, found := classify(argv)
		out.Targets = append(out.Targets, Target{
			PID: pid, Comm: comm, Argv: argv, Server: server, Found: found,
		})
	}
	return out
}

// SweepHost reads this host's own /proc.
func SweepHost() SweepResult { return Sweep("/proc") }

func readCmdline(path string) ([]string, bool) {
	b, err := os.ReadFile(path)
	if err != nil || len(bytes.TrimSpace(b)) == 0 {
		return nil, false
	}
	parts := bytes.Split(bytes.TrimRight(b, "\x00"), []byte{0})
	argv := make([]string, 0, len(parts))
	for _, p := range parts {
		argv = append(argv, string(p))
	}
	return argv, true
}

func readComm(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// isJVM keys on the EXECUTABLE, not on any argument. A process that merely mentions "java" in an
// argument — a grep, an editor, a build script, or an attacker's decoy — is not a JVM.
func isJVM(comm string, argv []string) bool {
	if comm == "java" || comm == "jsvc" {
		return true
	}
	if len(argv) == 0 {
		return false
	}
	base := filepath.Base(argv[0])
	return base == "java" || base == "jsvc"
}

// classify names the application server from argv.
//
// Reported as EVIDENCE, never as a gate: an unrecognised JVM is still scanned, it is just labelled
// "unknown". Gating on server recognition is how a scanner comes to ignore the one JVM that
// mattered because it was launched unusually.
func classify(argv []string) (server, found string) {
	joined := strings.Join(argv, " ")
	switch {
	case strings.Contains(joined, "org.apache.catalina.startup.Bootstrap"):
		return "tomcat", "catalina Bootstrap main class in argv"
	case strings.Contains(joined, "catalina.home") || strings.Contains(joined, "catalina.base"):
		return "tomcat", "catalina.home/base system property"
	case strings.Contains(joined, "org.eclipse.jetty"):
		return "jetty", "jetty main class in argv"
	case strings.Contains(joined, "jboss.home.dir") || strings.Contains(joined, "org.jboss."):
		return "jboss", "jboss system property or main class"
	}
	for i, a := range argv {
		if a == "-jar" && i+1 < len(argv) {
			return "spring-boot", "executable -jar launch"
		}
	}
	return "unknown", "java executable, server not identified"
}
