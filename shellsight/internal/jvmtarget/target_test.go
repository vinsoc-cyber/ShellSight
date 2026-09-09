package jvmtarget

import (
	"os"
	"path/filepath"
	"testing"
)

// writeProc fabricates /proc/<pid>/{cmdline,comm}. argv entries are NUL-separated exactly as the
// kernel presents them, so the parser is exercised on the real format.
func writeProc(t *testing.T, root, pid, comm string, argv ...string) {
	t.Helper()
	dir := filepath.Join(root, pid)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	var buf []byte
	for _, a := range argv {
		buf = append(buf, []byte(a)...)
		buf = append(buf, 0)
	}
	if err := os.WriteFile(filepath.Join(dir, "cmdline"), buf, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "comm"), []byte(comm+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestFindsTomcatJVM(t *testing.T) {
	root := t.TempDir()
	writeProc(t, root, "101", "java", "/usr/bin/java", "-Xmx1g",
		"org.apache.catalina.startup.Bootstrap", "start")
	writeProc(t, root, "102", "nginx", "nginx: master process")

	got := Sweep(root)
	if len(got.Targets) != 1 {
		t.Fatalf("want 1 JVM, got %d: %+v", len(got.Targets), got.Targets)
	}
	if got.Targets[0].PID != 101 || got.Targets[0].Server != "tomcat" {
		t.Errorf("want pid 101 / tomcat, got %d / %q", got.Targets[0].PID, got.Targets[0].Server)
	}
	if got.Targets[0].Found == "" {
		t.Error("every target must record HOW it was recognised")
	}
}

func TestRecognisesSpringBootFatJar(t *testing.T) {
	root := t.TempDir()
	writeProc(t, root, "201", "java", "/usr/bin/java", "-jar", "/opt/app/petclinic.jar")
	got := Sweep(root)
	if len(got.Targets) != 1 || got.Targets[0].Server != "spring-boot" {
		t.Fatalf("want spring-boot, got %+v", got.Targets)
	}
}

// An unrecognised JVM must still be scanned. Gating on server recognition is how a scanner comes
// to ignore the one JVM that mattered because it was launched unusually.
func TestUnrecognisedJVMIsStillATarget(t *testing.T) {
	root := t.TempDir()
	writeProc(t, root, "301", "java", "/usr/bin/java", "-cp", "/opt/x", "com.acme.Main")
	got := Sweep(root)
	if len(got.Targets) != 1 {
		t.Fatalf("an unrecognised JVM must still be a target, got %+v", got.Targets)
	}
	if got.Targets[0].Server != "unknown" {
		t.Errorf("want server=unknown, got %q", got.Targets[0].Server)
	}
}

// isJVM must key on the executable. A process merely MENTIONING java is not a JVM — that is an
// attacker's cheapest decoy and a grep's ordinary command line.
func TestProcessMerelyMentioningJavaIsNotAJVM(t *testing.T) {
	root := t.TempDir()
	writeProc(t, root, "401", "grep", "grep", "-r", "java", "/opt")
	writeProc(t, root, "402", "bash", "/bin/bash", "-c", "java -jar evil.jar")
	if got := Sweep(root); len(got.Targets) != 0 {
		t.Errorf("only the java/jsvc executable counts, got %+v", got.Targets)
	}
}

func TestCountsUnreadableEntries(t *testing.T) {
	root := t.TempDir()
	writeProc(t, root, "501", "java", "/usr/bin/java", "-jar", "x.jar")
	// A pid dir with no cmdline models a process that exited mid-sweep, or hidepid.
	if err := os.MkdirAll(filepath.Join(root, "502"), 0o755); err != nil {
		t.Fatal(err)
	}
	got := Sweep(root)
	if got.Unreadable != 1 {
		t.Errorf("want 1 unreadable, got %d", got.Unreadable)
	}
	if len(got.Targets) != 1 {
		t.Errorf("the readable JVM must still be reported, got %d", len(got.Targets))
	}
	if got.Examined != 2 {
		t.Errorf("want 2 examined, got %d", got.Examined)
	}
}

func TestNonPidDirectoriesIgnored(t *testing.T) {
	root := t.TempDir()
	for _, d := range []string{"self", "sys", "net"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	got := Sweep(root)
	if got.Examined != 0 || got.Unreadable != 0 {
		t.Errorf("non-pid dirs must not be counted, got examined=%d unreadable=%d",
			got.Examined, got.Unreadable)
	}
}

func TestMissingProcRootIsEmptyNotPanic(t *testing.T) {
	got := Sweep(filepath.Join(t.TempDir(), "absent"))
	if len(got.Targets) != 0 || got.Examined != 0 {
		t.Errorf("a missing proc root yields an empty sweep, got %+v", got)
	}
}
