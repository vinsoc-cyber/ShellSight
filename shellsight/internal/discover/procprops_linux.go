package discover

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// procRoot is /proc, indirected so a test can present a fabricated process table. A test that needed
// a real running Tomcat would never run anywhere, and this mechanism exists precisely for the
// instances the environment does not mention.
var procRoot = "/proc"

// processTable is what one sweep of /proc saw: the command lines it could read, and how many it
// could not.
type processTable struct {
	ByPID      map[int][]string
	Unreadable int
	Err        error
}

// Examined describes the sweep for an operator. A negative result means something different
// depending on whether the whole table was visible or three entries of it, so the counts are part of
// the answer -- hidepid=2, a container namespace, or an unprivileged responder account all hide most
// of it.
func (t processTable) Examined() string {
	s := fmt.Sprintf("%d process(es) examined", len(t.ByPID))
	if t.Unreadable > 0 {
		s += fmt.Sprintf(", %d not readable", t.Unreadable)
	}
	return s
}

// readProcessTable reads every /proc/<pid>/cmdline it can.
//
// Shared by the Tomcat and application-server mechanisms: sweeping /proc twice for the same data
// would double the cost and let the two disagree about what was running.
func readProcessTable() processTable {
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return processTable{Err: err}
	}
	table := processTable{ByPID: map[int][]string{}}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue // /proc carries plenty of non-numeric entries
		}
		// os.ReadFile here on purpose, unlike every config read in this package: /proc/<pid>/cmdline
		// is kernel-provided, cannot be replaced with a FIFO, and is bounded by the kernel's own
		// argument-area limit. A hostile /proc is a far larger problem than this loop.
		data, err := os.ReadFile(filepath.Join(procRoot, e.Name(), "cmdline"))
		if err != nil {
			// A process that exited between the listing and the read, or one owned by another user
			// under hidepid. Counted, because "we could not see most of the table" changes what a
			// negative result means.
			table.Unreadable++
			continue
		}
		if argv := splitCmdline(data); len(argv) > 0 {
			table.ByPID[pid] = argv
		}
	}
	return table
}

// splitCmdline splits a NUL-separated /proc cmdline. The buffer carries a trailing NUL, which would
// otherwise produce an empty final argument.
func splitCmdline(data []byte) []string {
	parts := strings.Split(string(data), "\x00")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// unavailableProcessTable explains why the table could not be read at all. A mounted image has no
// /proc, and config-file discovery is the primary method precisely so that case stays covered
// (FR-034), so this must never read as an error.
func unavailableProcessTable(m Mechanism, err error) Outcome {
	return Outcome{
		Mechanism: m, Status: StatusUnavailable,
		Detail: fmt.Sprintf("%s is not readable: %v", procRoot, err),
	}
}
