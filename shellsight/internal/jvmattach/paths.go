package jvmattach

import (
	"bufio"
	"os"
	"path"
	"strconv"
	"strings"
)

// Status is what /proc/<pid>/status tells us that attach needs.
type Status struct {
	EUID  int // effective uid -- the JVM authorises the attach by comparing this
	EGID  int // effective gid
	NSPID int // pid inside the target's own namespace; 0 when the kernel does not report it
}

// ParseStatus reads one /proc/<pid>/status file.
//
// NStgid lists the process's pid in each namespace, outermost first. HotSpot names .java_pid<N>
// and .attach_pid<N> with the number it sees for ITSELF — the innermost, i.e. the last field.
// Using the host pid against a containerised JVM produces a socket path that never appears, which
// is indistinguishable from "attach timed out" unless you know to look for it.
//
// Kernels older than 4.1 do not export NStgid; NSPID is then 0 so the caller can fall back
// explicitly rather than silently using a wrong number.
func ParseStatus(p string) (Status, error) {
	f, err := os.Open(p)
	if err != nil {
		return Status{}, err
	}
	defer f.Close()

	var st Status
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "Uid:"):
			if v, ok := field(line, 2); ok { // real, EFFECTIVE, saved, fs
				st.EUID = v
			}
		case strings.HasPrefix(line, "Gid:"):
			if v, ok := field(line, 2); ok {
				st.EGID = v
			}
		case strings.HasPrefix(line, "NStgid:"):
			fs := strings.Fields(line)
			if len(fs) >= 2 {
				if v, err := strconv.Atoi(fs[len(fs)-1]); err == nil {
					st.NSPID = v
				}
			}
		}
	}
	return st, sc.Err()
}

// field returns the n-th whitespace-separated token of a "Key:\tv1\tv2..." line, so n==2 is the
// effective id.
func field(line string, n int) (int, bool) {
	f := strings.Fields(line)
	if len(f) <= n {
		return 0, false
	}
	v, err := strconv.Atoi(f[n])
	return v, err == nil
}

// Paths holds every filesystem location one attach needs, in both namespace views.
//
// THE RULE: fields prefixed Our* are paths THIS process opens. The second result of StagedJar is
// the path the TARGET JVM opens. They differ whenever the target is in another mount namespace,
// and confusing them is the defining bug of this protocol — the JVM reports "Agent JAR not found"
// for a jar that is demonstrably present.
//
// We reach the target's filesystem through /proc/<pid>/root rather than calling setns(), because
// setns(CLONE_NEWNS) is unavailable to a multithreaded process and the Go runtime is always
// multithreaded. Unix sockets resolve through ordinary path lookup, so connect() works through
// /proc/<pid>/root exactly as open() does.
type Paths struct {
	HostPID        int
	NSPID          int
	OurTmp         string // the target's /tmp, as we see it
	OurSocket      string // the attach socket, as we see it
	OurSentinelCwd string // primary sentinel location (the target's cwd)
	OurSentinelTmp string // fallback sentinel location
}

// PathsFor derives every path from the host pid and the target's namespace pid.
func PathsFor(hostPID, nsPID int) Paths {
	hp := strconv.Itoa(hostPID)
	np := strconv.Itoa(nsPID)
	ourTmp := path.Join("/proc", hp, "root", "tmp")
	return Paths{
		HostPID:        hostPID,
		NSPID:          nsPID,
		OurTmp:         ourTmp,
		OurSocket:      path.Join(ourTmp, ".java_pid"+np),
		OurSentinelCwd: path.Join("/proc", hp, "cwd", ".attach_pid"+np),
		OurSentinelTmp: path.Join(ourTmp, ".attach_pid"+np),
	}
}

// StagedJar returns where we write the agent jar and what path to hand the JVM.
func (p Paths) StagedJar(name string) (ourPath, targetPath string) {
	return path.Join(p.OurTmp, name), path.Join("/tmp", name)
}
