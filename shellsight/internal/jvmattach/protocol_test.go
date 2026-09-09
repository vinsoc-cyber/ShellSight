package jvmattach

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// ---------------------------------------------------------------- wire format

func TestEncodeRequestShape(t *testing.T) {
	got := EncodeRequest("load", "instrument", "false", "/tmp/a.jar=cfg")
	want := []byte("1\x00load\x00instrument\x00false\x00/tmp/a.jar=cfg\x00")
	if !bytes.Equal(got, want) {
		t.Fatalf("wire mismatch\n got %q\nwant %q", got, want)
	}
}

// The JVM blocks until it has read four slots. A short frame hangs the attach instead of failing
// it, which is why padding matters.
func TestEncodeRequestPadsToFourSlots(t *testing.T) {
	got := EncodeRequest("properties")
	want := []byte("1\x00properties\x00\x00\x00\x00")
	if !bytes.Equal(got, want) {
		t.Fatalf("short command must pad to four slots\n got %q\nwant %q", got, want)
	}
}

func TestEncodeRequestMergesExcessArgs(t *testing.T) {
	got := EncodeRequest("load", "a", "b", "c", "d", "e")
	want := []byte("1\x00load\x00a\x00b\x00c d e\x00")
	if !bytes.Equal(got, want) {
		t.Fatalf("excess args merge into the last slot\n got %q\nwant %q", got, want)
	}
}

// ---------------------------------------------------------------- response decoding

func TestDecodeLoadJDK9PlusSuccess(t *testing.T) {
	code, _, err := DecodeLoadResponse([]byte("0\nreturn code: 0\n"))
	if err != nil || code != 0 {
		t.Fatalf("want 0/nil, got %d/%v", code, err)
	}
}

func TestDecodeLoadJDK9PlusFailure(t *testing.T) {
	code, _, err := DecodeLoadResponse([]byte("0\nreturn code: -1\n"))
	if err != nil || code != -1 {
		t.Fatalf("want -1, got %d/%v", code, err)
	}
}

func TestDecodeLoadJDK8(t *testing.T) {
	code, _, err := DecodeLoadResponse([]byte("0\n0\n"))
	if err != nil || code != 0 {
		t.Fatalf("want 0, got %d/%v", code, err)
	}
}

// THE trap. On JDK 21+ the load command's first line is ALWAYS 0 and failure is prose in the body.
// Reading only the first line reports every failed attach as a success.
func TestDecodeLoadJDK21ProseErrorIsNotSuccess(t *testing.T) {
	code, msg, err := DecodeLoadResponse([]byte("0\nAgent JAR not found or no Agent-Class attribute\n"))
	if err != nil {
		t.Fatal(err)
	}
	if code == 0 {
		t.Fatal("a JDK21+ prose error body must NOT decode as success")
	}
	if msg == "" {
		t.Error("the JVM's error message must be preserved for the operator")
	}
}

func TestDecodeLoadNonZeroFirstLine(t *testing.T) {
	code, msg, err := DecodeLoadResponse([]byte("101\nsomething went wrong\n"))
	if err != nil || code == 0 {
		t.Fatalf("a non-zero command result must not decode as success, got %d/%v", code, err)
	}
	if msg == "" {
		t.Error("message must be preserved")
	}
}

func TestDecodeLoadNoSecondLineIsSuccess(t *testing.T) {
	if code, _, err := DecodeLoadResponse([]byte("0\n")); err != nil || code != 0 {
		t.Fatalf("nothing contradicts success, got %d/%v", code, err)
	}
}

func TestDecodeLoadEmptyIsError(t *testing.T) {
	if _, _, err := DecodeLoadResponse(nil); err == nil {
		t.Error("an empty response is an error, not a success")
	}
}

// ---------------------------------------------------------------- /proc status

func statusFile(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "status")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestParseStatusEffectiveIdsAndInnermostNSPID(t *testing.T) {
	got, err := ParseStatus(statusFile(t,
		"Name:\tjava\nUid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\nNStgid:\t4242\t7\n"))
	if err != nil {
		t.Fatal(err)
	}
	// Column 2 is the EFFECTIVE id, which is what the JVM compares against.
	if got.EUID != 1000 || got.EGID != 1000 {
		t.Errorf("want euid/egid 1000/1000, got %d/%d", got.EUID, got.EGID)
	}
	// NStgid is outermost-first; HotSpot names its socket with the INNERMOST value.
	if got.NSPID != 7 {
		t.Errorf("want nspid 7 (innermost), got %d", got.NSPID)
	}
}

func TestParseStatusUnNamespaced(t *testing.T) {
	got, _ := ParseStatus(statusFile(t, "Uid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\nNStgid:\t4242\n"))
	if got.NSPID != 4242 {
		t.Errorf("un-namespaced: nspid == pid, got %d", got.NSPID)
	}
}

// Kernels < 4.1 omit NStgid. Reporting 0 lets the caller fall back explicitly instead of silently
// using a wrong number.
func TestParseStatusMissingNStgidReportsZero(t *testing.T) {
	got, _ := ParseStatus(statusFile(t, "Uid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\n"))
	if got.NSPID != 0 {
		t.Errorf("absent NStgid must report 0, got %d", got.NSPID)
	}
}

func TestParseStatusUnreadableIsError(t *testing.T) {
	if _, err := ParseStatus(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Error("an unreadable status file must be an error, not a zero value")
	}
}

// ---------------------------------------------------------------- path derivation

func TestOurPathsGoThroughProcRoot(t *testing.T) {
	p := PathsFor(4242, 7)
	if p.OurTmp != "/proc/4242/root/tmp" {
		t.Errorf("we reach the target's /tmp through its proc root, got %q", p.OurTmp)
	}
	if p.OurSocket != "/proc/4242/root/tmp/.java_pid7" {
		t.Errorf("the socket path must use the NAMESPACE pid, got %q", p.OurSocket)
	}
	if p.OurSentinelCwd != "/proc/4242/cwd/.attach_pid7" {
		t.Errorf("primary sentinel lives in the target's cwd, got %q", p.OurSentinelCwd)
	}
	if p.OurSentinelTmp != "/proc/4242/root/tmp/.attach_pid7" {
		t.Errorf("fallback sentinel, got %q", p.OurSentinelTmp)
	}
}

// The JVM opens the agent jar in ITS OWN namespace, so the path handed to it must be the target's
// view. Getting this backwards yields "Agent JAR not found" for a jar that is right there.
func TestStagedJarHasBothViews(t *testing.T) {
	our, theirs := PathsFor(4242, 7).StagedJar("ss-agent-abc.jar")
	if our != "/proc/4242/root/tmp/ss-agent-abc.jar" {
		t.Errorf("our write path, got %q", our)
	}
	if theirs != "/tmp/ss-agent-abc.jar" {
		t.Errorf("the JVM's view, got %q", theirs)
	}
}

// A non-namespaced target has nspid == pid and /proc/<pid>/root symlinks to /, so one construction
// is correct in both cases and needs no branch.
func TestUnNamespacedUsesSameConstruction(t *testing.T) {
	if got := PathsFor(4242, 4242).OurSocket; got != "/proc/4242/root/tmp/.java_pid4242" {
		t.Errorf("got %q", got)
	}
}

// sun_path is 108 bytes including the NUL; a Linux pid is at most 7 digits.
func TestSocketPathFitsSunPath(t *testing.T) {
	p := PathsFor(4194304, 4194304)
	if len(p.OurSocket) >= 108 {
		t.Fatalf("socket path %q is %d bytes, sun_path allows 107", p.OurSocket, len(p.OurSocket))
	}
}

func TestAgentJarIsEmbedded(t *testing.T) {
	b := AgentJar()
	if len(b) < 1000 {
		t.Fatalf("embedded agent jar is %d bytes -- the embed did not pick up the file", len(b))
	}
	// A jar is a zip: it must start with the local file header magic.
	if b[0] != 'P' || b[1] != 'K' {
		t.Errorf("embedded agent is not a zip/jar (magic %q)", b[:2])
	}
	if AgentDigest() == "" {
		t.Error("agent digest must not be empty")
	}
}
