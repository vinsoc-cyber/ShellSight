package discover

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// procRoot is injectable because a test that needed a real running Tomcat would never run anywhere,
// and this mechanism exists precisely for the instances no environment variable mentions.
func fakeProc(t *testing.T, cmdlines map[string][]string) {
	t.Helper()
	root := t.TempDir()
	for name, argv := range cmdlines {
		dir := filepath.Join(root, name)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		// Real /proc cmdline is NUL-separated with a trailing NUL.
		body := strings.Join(argv, "\x00")
		if body != "" {
			body += "\x00"
		}
		if err := os.WriteFile(filepath.Join(dir, "cmdline"), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	prior := procRoot
	procRoot = root
	t.Cleanup(func() { procRoot = prior })
}

func TestATomcatIsFoundThroughTheProcessTable(t *testing.T) {
	fakeProc(t, map[string][]string{
		"1":    {"/sbin/init"},
		"2417": {"/usr/lib/jvm/java-17/bin/java", "-Dcatalina.base=/opt/tomcat/instance-a", "org.apache.catalina.startup.Bootstrap", "start"},
		// Non-numeric /proc entries are plentiful and must be skipped without error.
		"self":     {"/usr/lib/jvm/java-17/bin/java", "-Dcatalina.base=/should-not-be-read"},
		"sys":      {},
		"cpuinfo":  {},
		"acpi":     {},
		"pressure": {},
	})
	bases, outcome := catalinaBasesFromProcesses(Options{})
	if outcome.Status != StatusSucceeded {
		t.Fatalf("want succeeded, got %+v", outcome)
	}
	if len(bases) != 1 {
		t.Fatalf("want exactly the one real instance, got %+v", bases)
	}
	if bases[0].Path != "/opt/tomcat/instance-a" {
		t.Fatalf("wrong base: %+v", bases[0])
	}
	// /proc/self is a symlink to the reading process on a real host; here it proves that a
	// non-numeric entry is skipped rather than parsed, which would double-count every instance.
	if strings.Contains(bases[0].Path, "should-not-be-read") {
		t.Fatal("/proc/self must not be walked as a pid")
	}
	if !strings.Contains(bases[0].Source, "2417") {
		t.Fatalf("the source must name the pid, got %q", bases[0].Source)
	}
}

func TestAProcessTableWithNoTomcatSaysHowManyItLookedAt(t *testing.T) {
	// "Discovery must degrade, not fail." A negative result means something different depending on
	// whether we saw the whole table or three entries of it, so the count is part of the answer.
	fakeProc(t, map[string][]string{
		"1":   {"/sbin/init"},
		"421": {"/usr/sbin/nginx", "-g", "daemon off;"},
	})
	bases, outcome := catalinaBasesFromProcesses(Options{})
	if len(bases) != 0 {
		t.Fatalf("want none, got %+v", bases)
	}
	if outcome.Status != StatusAttempted {
		t.Fatalf("a table we could read but found nothing in is attempted, got %+v", outcome)
	}
	if !strings.Contains(outcome.Detail, "2 process") {
		t.Fatalf("the detail must state how much of the table was examined, got %q", outcome.Detail)
	}
}

func TestAnUnreadableProcessIsCountedNotIgnored(t *testing.T) {
	// hidepid=2, a container namespace, or an unprivileged responder account can hide most of the
	// table. "We looked at 2 of 40" and "we looked at 40" support very different conclusions from
	// the same empty result.
	fakeProc(t, map[string][]string{"1": {"/sbin/init"}})
	// A pid directory with no cmdline at all: the process exited between the listing and the read.
	if err := os.MkdirAll(filepath.Join(procRoot, "9999"), 0o755); err != nil {
		t.Fatal(err)
	}
	_, outcome := catalinaBasesFromProcesses(Options{})
	if !strings.Contains(outcome.Detail, "not readable") {
		t.Fatalf("an unreadable process must be disclosed, got %q", outcome.Detail)
	}
}

func TestAnAbsentProcFilesystemIsUnavailableNotAFailure(t *testing.T) {
	// A mounted image has no /proc. Config-file discovery is the primary method precisely so that
	// this case stays covered, so it must not read as an error.
	prior := procRoot
	procRoot = filepath.Join(t.TempDir(), "no-proc-here")
	t.Cleanup(func() { procRoot = prior })
	bases, outcome := catalinaBasesFromProcesses(Options{})
	if len(bases) != 0 {
		t.Fatalf("got %+v", bases)
	}
	if outcome.Status != StatusUnavailable {
		t.Fatalf("want unavailable, got %+v", outcome)
	}
}

func TestRefusingProcessInspectionReadsNothing(t *testing.T) {
	// FR-039: on a compromised host the process table is attacker-influenced too — an intruder
	// controls the command line of anything they start.
	fakeProc(t, map[string][]string{
		"2417": {"java", "-Dcatalina.base=/opt/tomcat"},
	})
	bases, outcome := catalinaBasesFromProcesses(Options{Refuse: map[Mechanism]bool{MechTomcatProcess: true}})
	if len(bases) != 0 || outcome.Status != StatusRefused {
		t.Fatalf("a refused mechanism must read nothing and say so, got %+v / %+v", bases, outcome)
	}
}
