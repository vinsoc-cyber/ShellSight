package jvmtriage

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func codes(sigs []Signal) map[string]string {
	m := map[string]string{}
	for _, s := range sigs {
		m[s.Code] = s.Detail
	}
	return m
}

func writeMaps(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "maps")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// ---------------------------------------------------------------- Signal

func TestSeverityOrdering(t *testing.T) {
	if !SevStrong.Above(SevWeak) || !SevWeak.Above(SevInfo) {
		t.Error("severity must order info < weak < strong")
	}
	if SevWeak.Above(SevStrong) {
		t.Error("weak must not outrank strong")
	}
}

func TestSignalIDIsStableAndDiscriminating(t *testing.T) {
	a := Signal{Code: "deleted-mapping", Detail: "/tmp/x.jar", Severity: SevStrong}
	b := Signal{Code: "deleted-mapping", Detail: "/tmp/x.jar", Severity: SevStrong}
	c := Signal{Code: "deleted-mapping", Detail: "/tmp/y.jar", Severity: SevStrong}
	if a.ID() != b.ID() {
		t.Error("identical signals must share an id")
	}
	if a.ID() == c.ID() {
		t.Error("different detail must change the id")
	}
}

// ---------------------------------------------------------------- Maps

func TestDeletedJarMappingIsStrong(t *testing.T) {
	p := writeMaps(t, ""+
		"7f000000-7f001000 r--s 00000000 08:01 111  /opt/tomcat/lib/catalina.jar\n"+
		"7f002000-7f003000 r--s 00000000 08:01 222  /tmp/agent9182.jar (deleted)\n")
	sigs := Maps(p)
	if _, ok := codes(sigs)["deleted-mapping"]; !ok {
		t.Fatalf("want deleted-mapping, got %+v", sigs)
	}
	for _, s := range sigs {
		if s.Code == "deleted-mapping" && s.Severity != SevStrong {
			t.Errorf("an unlinked jar the JVM still maps is strong, got %v", s.Severity)
		}
	}
}

func TestOrdinaryMappingsAreSilent(t *testing.T) {
	p := writeMaps(t, ""+
		"7f000000-7f001000 r-xp 00000000 08:01 111  /usr/lib/jvm/lib/libjvm.so\n"+
		"7f002000-7f003000 r--s 00000000 08:01 222  /opt/tomcat/lib/catalina.jar\n")
	if sigs := Maps(p); len(sigs) != 0 {
		t.Errorf("an ordinary JVM must produce no maps signals, got %+v", sigs)
	}
}

// The JIT fills a JVM with anonymous rwx memory. Reporting it would alert on every JVM alive.
func TestAnonymousExecMemoryIsNeverReported(t *testing.T) {
	p := writeMaps(t, "7f004000-7f005000 rwxp 00000000 00:00 0 \n")
	if sigs := Maps(p); len(sigs) != 0 {
		t.Errorf("anonymous exec memory is normal in a JVM (JIT) and must not be reported: %+v", sigs)
	}
}

func TestDeletedNonCodeFileIsWeak(t *testing.T) {
	p := writeMaps(t, "7f002000-7f003000 r--p 00000000 08:01 222  /var/log/app.log (deleted)\n")
	for _, s := range Maps(p) {
		if s.Severity == SevStrong {
			t.Errorf("a deleted log is routine (logrotate) and must not be strong: %+v", s)
		}
	}
}

func TestMapsPathWithSpacesIsParsed(t *testing.T) {
	p := writeMaps(t, "7f002000-7f003000 r--s 00000000 08:01 222  /tmp/my agent.jar (deleted)\n")
	d := codes(Maps(p))["deleted-mapping"]
	if !strings.Contains(d, "my agent.jar") {
		t.Errorf("a path containing spaces must survive parsing, got %q", d)
	}
}

func TestMapsMissingFileIsSilent(t *testing.T) {
	if sigs := Maps(filepath.Join(t.TempDir(), "nope")); sigs != nil {
		t.Errorf("an unreadable maps file is a permissions fact, not a finding: %+v", sigs)
	}
}

// ---------------------------------------------------------------- FDs

func fdDir(t *testing.T, targets ...string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "fd")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for i, tgt := range targets {
		if err := os.Symlink(tgt, filepath.Join(dir, strconv.Itoa(i+3))); err != nil {
			t.Skipf("symlinks unavailable on this host: %v", err)
		}
	}
	return dir
}

func TestDeletedJarFDIsStrong(t *testing.T) {
	dir := fdDir(t, "/opt/tomcat/lib/catalina.jar", "/tmp/injected1234.jar (deleted)")
	d, ok := codes(FDs(dir))["deleted-fd"]
	if !ok {
		t.Fatalf("want deleted-fd, got %+v", FDs(dir))
	}
	if !strings.Contains(d, "injected1234.jar") {
		t.Errorf("the unlinked path is the evidence, got %q", d)
	}
}

func TestOrdinaryFDsAreSilent(t *testing.T) {
	dir := fdDir(t, "/opt/tomcat/lib/catalina.jar", "/dev/urandom")
	if sigs := FDs(dir); len(sigs) != 0 {
		t.Errorf("ordinary fds must be silent, got %+v", sigs)
	}
}

func TestUnreadableFDDirIsSilentNotFatal(t *testing.T) {
	if sigs := FDs(filepath.Join(t.TempDir(), "none")); sigs != nil {
		t.Errorf("an unreadable fd dir is a permissions fact, not a finding: %+v", sigs)
	}
}

// ---------------------------------------------------------------- Cmdline

func TestJavaagentIsReportedAsInfo(t *testing.T) {
	sigs := Cmdline([]string{"/usr/bin/java", "-javaagent:/opt/otel/agent.jar", "-jar", "app.jar"})
	d, ok := codes(sigs)["startup-javaagent"]
	if !ok {
		t.Fatalf("want startup-javaagent, got %+v", sigs)
	}
	if !strings.Contains(d, "/opt/otel/agent.jar") {
		t.Errorf("the agent path is the evidence, got %q", d)
	}
	for _, s := range sigs {
		if s.Code == "startup-javaagent" && s.Severity != SevInfo {
			t.Errorf("a -javaagent is normal on an APM host and must be info, got %v", s.Severity)
		}
	}
}

func TestAttachHardeningFlagsReported(t *testing.T) {
	if _, ok := codes(Cmdline([]string{"java", "-XX:+DisableAttachMechanism"}))["attach-disabled"]; !ok {
		t.Error("want attach-disabled")
	}
	if _, ok := codes(Cmdline([]string{"java", "-XX:-EnableDynamicAgentLoading"}))["dynamic-agent-load-disabled"]; !ok {
		t.Error("want dynamic-agent-load-disabled")
	}
}

func TestOrdinaryCmdlineIsSilent(t *testing.T) {
	if sigs := Cmdline([]string{"/usr/bin/java", "-Xmx2g", "-jar", "app.jar"}); len(sigs) != 0 {
		t.Errorf("an ordinary launch must be silent, got %+v", sigs)
	}
}

// ---------------------------------------------------------------- Channel

// The single most important false-positive guard in the package: HotSpot creates the attach socket
// lazily, so its absence is the state of every healthy un-attached JVM.
func TestMissingAttachSocketIsSilent(t *testing.T) {
	if sigs := Channel(t.TempDir(), 1234); len(sigs) != 0 {
		t.Errorf("absence of the attach socket is the NORMAL state and must be silent, got %+v", sigs)
	}
}

func TestExistingAttachSocketIsReported(t *testing.T) {
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, ".java_pid1234"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok := codes(Channel(tmp, 1234))["attach-listener-already-started"]; !ok {
		t.Error("an existing socket means something already attached")
	}
}

func TestStaleSentinelIsReported(t *testing.T) {
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, ".attach_pid1234"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok := codes(Channel(tmp, 1234))["attach-sentinel-present"]; !ok {
		t.Error("a leftover sentinel means an attach was attempted")
	}
}

func TestAnotherPidsSocketIsNotEvidence(t *testing.T) {
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, ".java_pid9999"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if sigs := Channel(tmp, 1234); len(sigs) != 0 {
		t.Errorf("another process's socket says nothing about this one, got %+v", sigs)
	}
}
