// Package jvmtriage reads evidence about a JVM process from OUTSIDE it.
//
// Everything here derives from the kernel's /proc view. Nothing asks the JVM a question, so
// nothing here can be answered dishonestly by code running inside that JVM. That is the entire
// point: the published memshell bypass set works by lying to an in-process inspector — deleting
// /tmp/.java_pid<pid>, blocking ClassFileTransformers, overriding findResource, claiming a
// borrowed CodeSource. None of those touch what the kernel reports.
//
// This layer never identifies a webshell on its own. It answers a narrower question — "is there
// something about this process worth looking at, and can we still say something useful when the
// in-JVM path is refused?" — which is what keeps a blocked attach from becoming a silent clean.
package jvmtriage

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Severity ranks how much one observation moves a verdict on its own.
type Severity int

const (
	// SevInfo is context worth recording that never alerts by itself — "this JVM has a
	// -javaagent, here is its path".
	SevInfo Severity = iota
	// SevWeak needs corroboration to matter.
	SevWeak
	// SevStrong stands alone as a lead.
	SevStrong
)

// Above reports whether s outranks other.
func (s Severity) Above(other Severity) bool { return s > other }

func (s Severity) String() string {
	switch s {
	case SevStrong:
		return "strong"
	case SevWeak:
		return "weak"
	default:
		return "info"
	}
}

// Signal is one external observation about one process.
//
// Code is a stable vocabulary term, never free text, so a SIEM can pivot on it. Detail carries the
// specific evidence and MAY contain attacker-influenced content (a file path), so consumers must
// treat it as data.
type Signal struct {
	Code     string
	Detail   string
	Severity Severity
}

// ID is a deterministic identity for deduplicating across repeated sweeps.
func (s Signal) ID() string {
	h := sha256.Sum256([]byte(s.Code + "\x00" + s.Detail))
	return hex.EncodeToString(h[:8])
}

// codeArtifact reports whether an unlinked path is executable code rather than data. A deleted
// jar/so/class the process still holds is the agent-dropped-and-removed pattern; a deleted log is
// logrotate.
func codeArtifact(p string) bool {
	return strings.HasSuffix(p, ".jar") || strings.HasSuffix(p, ".so") ||
		strings.HasSuffix(p, ".class") || strings.Contains(p, ".so.")
}

// Maps reads one /proc/<pid>/maps and reports what it implies.
//
// The trap this deliberately avoids: every HotSpot JVM carries megabytes of anonymous executable
// memory because that is where the JIT puts compiled code. Scoring rwx here would alert on every
// JVM in existence, so anonymous regions are not reported at all.
func Maps(path string) []Signal {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var out []Signal
	seen := map[string]bool{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for sc.Scan() {
		line := sc.Text()
		if !strings.HasSuffix(line, "(deleted)") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		// A path may contain spaces, so rejoin from field 5 and trim the marker.
		p := strings.TrimSpace(strings.TrimSuffix(strings.Join(fields[5:], " "), "(deleted)"))
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true

		if codeArtifact(p) {
			out = append(out, Signal{
				Code:     "deleted-mapping",
				Detail:   "unlinked code artifact still mapped by the JVM: " + p,
				Severity: SevStrong,
			})
			continue
		}
		out = append(out, Signal{
			Code:     "deleted-mapping",
			Detail:   "unlinked file still mapped: " + p,
			Severity: SevWeak,
		})
	}
	return out
}

// FDs inspects /proc/<pid>/fd for descriptors whose backing file has been unlinked.
//
// Complements Maps: a jar can be opened and read without being mmapped, so an agent that was
// dropped, read and deleted may leave a trace here and nowhere else.
//
// An unreadable directory returns nil, not an error signal. Not being root is a fact about the
// SCAN, not about the target; scan completeness is reported through the coverage record instead.
func FDs(fdDir string) []Signal {
	entries, err := os.ReadDir(fdDir)
	if err != nil {
		return nil
	}
	var out []Signal
	seen := map[string]bool{}
	for _, e := range entries {
		target, err := os.Readlink(filepath.Join(fdDir, e.Name()))
		if err != nil || !strings.HasSuffix(target, "(deleted)") {
			continue
		}
		p := strings.TrimSpace(strings.TrimSuffix(target, "(deleted)"))
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true

		if codeArtifact(p) {
			out = append(out, Signal{
				Code:     "deleted-fd",
				Detail:   "unlinked code artifact still open by the JVM: " + p,
				Severity: SevStrong,
			})
			continue
		}
		out = append(out, Signal{
			Code:     "deleted-fd",
			Detail:   "unlinked file still open: " + p,
			Severity: SevWeak,
		})
	}
	return out
}

// Cmdline extracts the JVM flags that change what a memory scan can see or mean.
//
// None of these is an alert. -javaagent is how every APM product works; DisableAttachMechanism is
// a legitimate hardening choice. They are recorded because they EXPLAIN a later result: an attach
// failure alongside attach-disabled is a configuration fact, while an attach failure with no such
// flag is unexplained and therefore interesting.
func Cmdline(argv []string) []Signal {
	var out []Signal
	for _, a := range argv {
		switch {
		case strings.HasPrefix(a, "-javaagent:"):
			out = append(out, Signal{
				Code:     "startup-javaagent",
				Detail:   "agent loaded at startup: " + strings.TrimPrefix(a, "-javaagent:"),
				Severity: SevInfo,
			})
		case a == "-XX:+DisableAttachMechanism":
			out = append(out, Signal{
				Code:     "attach-disabled",
				Detail:   "-XX:+DisableAttachMechanism: this JVM cannot be attached to; an in-JVM scan is impossible by configuration",
				Severity: SevInfo,
			})
		case a == "-XX:-EnableDynamicAgentLoading":
			out = append(out, Signal{
				Code:     "dynamic-agent-load-disabled",
				Detail:   "-XX:-EnableDynamicAgentLoading: dynamic agent attach is refused (JDK 21+)",
				Severity: SevInfo,
			})
		}
	}
	return out
}

// Channel inspects the HotSpot attach channel for one PID.
//
// CRITICAL: HotSpot starts its attach listener LAZILY. On a JVM nobody has attached to,
// /tmp/.java_pid<pid> does not exist. Absence is the healthy default and is reported as nothing at
// all — treating it as a signal would false-positive on every JVM alive. Only PRESENCE carries
// information: it means something attached during this JVM's lifetime, before we arrived.
//
// tmpDir is a parameter so a container target can be inspected through /proc/<hostpid>/root/tmp,
// and pid must be the pid IN THE TARGET'S NAMESPACE, because that is the number HotSpot used when
// it named the socket.
func Channel(tmpDir string, pid int) []Signal {
	var out []Signal
	p := strconv.Itoa(pid)

	if _, err := os.Stat(filepath.Join(tmpDir, ".java_pid"+p)); err == nil {
		out = append(out, Signal{
			Code:     "attach-listener-already-started",
			Detail:   "an attach listener socket exists for pid " + p + ": something attached to this JVM before this scan",
			Severity: SevWeak,
		})
	}
	if _, err := os.Stat(filepath.Join(tmpDir, ".attach_pid"+p)); err == nil {
		out = append(out, Signal{
			Code:     "attach-sentinel-present",
			Detail:   "a leftover attach sentinel exists for pid " + p + ": an attach was attempted against this JVM",
			Severity: SevWeak,
		})
	}
	return out
}
