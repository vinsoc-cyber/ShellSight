package output

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"shellsight/internal/finding"
)

// The runbook is the file an analyst follows at 3am, and it named a file that does not exist.
//
// It said `report.ndjson`; the code has always written `findings.ndjson`. So the documented SIEM
// ingestion path pointed at nothing, and an analyst looking for their findings found an absence. That
// is a documentation bug with the same consequence as a code bug, and it survived because nothing
// compared the two.

const ndjsonName = "findings.ndjson"

func runbook(t *testing.T) string {
	t.Helper()
	// ../../../docs/RUNBOOK.md: this package sits at shellsight/internal/output, and the runbook
	// moved to the repository-root docs/ when the analyst-facing document set was assembled.
	//
	// FATAL, NOT SKIP. These tests exist to stop the runbook drifting from the code, and a Skip on a
	// path error meant that moving the file DISARMED them while the package still reported ok --
	// which is precisely what would have happened during that move. If the runbook cannot be found,
	// that is the bug, not a reason to stand down.
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "docs", "RUNBOOK.md"))
	if err != nil {
		t.Fatalf("docs/RUNBOOK.md not readable: %v", err)
	}
	return string(b)
}

func TestTheRunbookNamesTheFileTheCodeActuallyWrites(t *testing.T) {
	text := runbook(t)
	if !strings.Contains(text, ndjsonName) {
		t.Errorf("the runbook must name %q, which is what Write produces", ndjsonName)
	}
	// The specific wrong name that shipped. Guarded by value so a revert is loud.
	//
	// Checked PER LINE, and a line that names BOTH files is exempt. The guard was written as a
	// whole-file substring search and then tripped on the one line that records the drift being
	// FIXED -- the verification-stamp row reading "the historical `report.ndjson` drift is gone and
	// a test now fails if it returns". So the test failed on its own changelog entry, the runbook
	// was correct the whole time, and the handoff that inherited the red test described it as a
	// documentation bug that no longer existed.
	//
	// The distinction is what the line DOES. An instruction pointing an analyst at the wrong file
	// names that file alone; a line naming both is comparing them, which is history rather than
	// direction. That keeps the revert loud -- reinstate `report.ndjson` as the documented SIEM
	// stream and the line naming only it fails here -- without making the fix unmentionable.
	for i, line := range strings.Split(text, "\n") {
		if !strings.Contains(line, "report.ndjson") {
			continue
		}
		if strings.Contains(line, ndjsonName) {
			continue // documents the drift; does not direct anyone to it
		}
		t.Errorf("RUNBOOK.md:%d names report.ndjson, which no run has ever produced: %q",
			i+1, strings.TrimSpace(line))
	}
}

func TestTheWrittenNdjsonFilenameIsTheOneDocumented(t *testing.T) {
	// The other half: if the code's filename changes, this fails rather than silently re-creating the
	// drift in the opposite direction.
	dir := t.TempDir()
	runDir, err := Write(finding.Report{
		Scan:    finding.Scan{Host: "h", RunID: "20260820_000000", ToolVersion: "v1"},
		Verdict: finding.Verdict{Tier: finding.TierClean},
	}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(runDir, ndjsonName)); err != nil {
		t.Fatalf("Write did not produce %q: %v", ndjsonName, err)
	}
}

func TestTheRunbookCoversTheLinuxRelease(t *testing.T) {
	// T066. A responder on an unfamiliar Linux host needs four things from the runbook, and the flat
	// unpack and the execute bit are the two that break a scan before it starts.
	// Whitespace-normalised: the runbook is hard-wrapped prose, and a phrase that happens to straddle
	// a line break is still present. A doc test that breaks on reflow gets deleted rather than fixed.
	text := strings.Join(strings.Fields(runbook(t)), " ")
	for _, want := range []struct{ topic, needle string }{
		{"the flat unpack", "flat"},
		{"the execute bit", "execute bit"},
		{"static linkage", "statically linked"},
		{"discovery provenance", "via convention"},
		{"the coverage statuses", "`n/a`"},
		{"deferred vs unsupported", "deferred"},
		{"scanning nothing is not clean", "not evidence of absence"},
		{"the low-priority flag", "--low-priority"},
		{"refusing exec discovery", "--discovery-refuse"},
	} {
		if !strings.Contains(text, want.needle) {
			t.Errorf("the runbook does not cover %s (looked for %q)", want.topic, want.needle)
		}
	}
}
