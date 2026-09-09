package jvmprov

import (
	"archive/zip"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---------------------------------------------------------------- claim parsing

func factsFile(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "0.facts")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestParsesClaim(t *testing.T) {
	c, err := ParseClaim(factsFile(t, ""+
		"name\torg.apache.Evil\n"+
		"codesource\tfile:/opt/tomcat/lib/catalina.jar\n"+
		"loader_read_ok\ttrue\n"+
		"suspicion\t85\n"+
		"verified_generated\tfalse\n"+
		"iface\tjavax.servlet.Filter\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.ClassName != "org.apache.Evil" {
		t.Errorf("class name, got %q", c.ClassName)
	}
	if c.CodeSourceJar != "/opt/tomcat/lib/catalina.jar" {
		t.Errorf("the file: URL must reduce to a filesystem path, got %q", c.CodeSourceJar)
	}
	if !c.LoaderReadOK || c.Suspicion != 85 {
		t.Errorf("loader_read_ok/suspicion, got %v/%d", c.LoaderReadOK, c.Suspicion)
	}
	if len(c.Contracts) != 1 {
		t.Errorf("contracts, got %v", c.Contracts)
	}
}

func TestNullCodeSourceIsDiskAbsent(t *testing.T) {
	c, _ := ParseClaim(factsFile(t, "name\tcom.x.Y\ncodesource\tnull\n"))
	if c.CodeSourceJar != "" || !c.DiskAbsent() {
		t.Errorf("a null codesource means disk-absent, got %q", c.CodeSourceJar)
	}
}

// Spring Boot nested fat jars name an archive member inside another archive. Go cannot open that
// through one call, so it must be reported unverifiable rather than mistaken for a fabrication.
func TestNestedJarURLIsFlagged(t *testing.T) {
	c, _ := ParseClaim(factsFile(t,
		"name\tcom.x.Y\ncodesource\tjar:nested:/opt/app.jar!/BOOT-INF/lib/dep.jar!/\n"))
	if !c.NestedCodeSource {
		t.Error("a jar:nested: URL must be flagged so verification reports unverifiable")
	}
	if c.DiskAbsent() {
		t.Error("nested is not the same as absent")
	}
}

func TestUnreadableFactsIsError(t *testing.T) {
	if _, err := ParseClaim(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Error("want an error for a missing facts file")
	}
}

// ---------------------------------------------------------------- verification

func makeJar(t *testing.T, dir string, entries ...string) string {
	t.Helper()
	p := filepath.Join(dir, "lib.jar")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zw := zip.NewWriter(f)
	for _, e := range entries {
		w, err := zw.Create(e)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte{0xCA, 0xFE, 0xBA, 0xBE}); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestEntryPresentIsCorroborated(t *testing.T) {
	jar := makeJar(t, t.TempDir(), "org/apache/Real.class")
	if v := Verify(Claim{ClassName: "org.apache.Real", CodeSourceJar: jar}, ""); v.Status != Corroborated {
		t.Fatalf("want corroborated, got %v (%s)", v.Status, v.Detail)
	}
}

// THE attack: define the class with ProtectionDomain(CodeSource=catalina.jar). The jar is real; the
// class is not in it.
func TestBorrowedCodeSourceIsSpoofed(t *testing.T) {
	jar := makeJar(t, t.TempDir(), "org/apache/catalina/Something.class")
	if v := Verify(Claim{ClassName: "org.apache.Evil", CodeSourceJar: jar}, ""); v.Status != Spoofed {
		t.Fatalf("a class absent from the jar it claims must be spoofed, got %v", v.Status)
	}
}

func TestFabricatedJarPathIsSpoofed(t *testing.T) {
	if v := Verify(Claim{ClassName: "org.apache.Evil", CodeSourceJar: "/opt/nope.jar"}, ""); v.Status != Spoofed {
		t.Fatalf("a CodeSource naming a nonexistent jar must be spoofed, got %v", v.Status)
	}
}

// THE asymmetry. The loader answered; the filesystem did not. That is a loader manufacturing bytes
// — the findResource bypass — and it is only visible because we did not ask the loader.
func TestLoaderAnsweredButJarDidNotIsFlagged(t *testing.T) {
	jar := makeJar(t, t.TempDir(), "org/apache/catalina/Other.class")
	v := Verify(Claim{ClassName: "org.apache.Evil", CodeSourceJar: jar, LoaderReadOK: true}, "")
	if v.Status != Spoofed {
		t.Fatalf("want spoofed, got %v", v.Status)
	}
	if !v.LoaderContradiction {
		t.Error("the loader answering where the filesystem did not must be flagged explicitly")
	}
}

// Claiming nothing is HONEST. It is suspicious for other reasons, but conflating it with a false
// claim would put every JDK proxy in the spoofed bucket.
func TestDiskAbsentClaimIsNotSpoofed(t *testing.T) {
	if v := Verify(Claim{ClassName: "com.x.Y"}, ""); v.Status != DiskAbsentClaim {
		t.Fatalf("want disk-absent-claim, got %v", v.Status)
	}
}

func TestNestedIsUnverifiable(t *testing.T) {
	if v := Verify(Claim{ClassName: "com.x.Y", NestedCodeSource: true}, ""); v.Status != Unverifiable {
		t.Fatalf("want unverifiable, got %v", v.Status)
	}
}

// A container target's jar lives under /proc/<pid>/root. Without applying the namespace root every
// containerised JVM reports every class as spoofed.
func TestNamespaceRootIsApplied(t *testing.T) {
	root := t.TempDir()
	inner := filepath.Join(root, "opt", "tomcat", "lib")
	if err := os.MkdirAll(inner, 0o755); err != nil {
		t.Fatal(err)
	}
	src := makeJar(t, t.TempDir(), "org/apache/Real.class")
	b, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(inner, "catalina.jar"), b, 0o644); err != nil {
		t.Fatal(err)
	}
	v := Verify(Claim{ClassName: "org.apache.Real", CodeSourceJar: "/opt/tomcat/lib/catalina.jar"}, root)
	if v.Status != Corroborated {
		t.Fatalf("the jar must resolve through the namespace root, got %v (%s)", v.Status, v.Detail)
	}
}

func TestExplodedDirectoryIsSupported(t *testing.T) {
	dir := t.TempDir()
	cls := filepath.Join(dir, "org", "apache")
	if err := os.MkdirAll(cls, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cls, "Real.class"), []byte{0xCA}, 0o644); err != nil {
		t.Fatal(err)
	}
	if v := Verify(Claim{ClassName: "org.apache.Real", CodeSourceJar: dir}, ""); v.Status != Corroborated {
		t.Fatalf("an exploded classes dir must corroborate, got %v (%s)", v.Status, v.Detail)
	}
}

// ---------------------------------------------------------------- attribution

// classWithLiterals builds a minimal class file whose constant pool contains the given genuine
// string literals (Utf8 + CONSTANT_String pairs), so the pool parser is exercised on real structure
// rather than a raw byte match.
func classWithLiterals(lits ...string) []byte {
	b := []byte{0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 52}
	count := 1 + 2*len(lits)
	pool := []byte{}
	for i, s := range lits {
		pool = append(pool, 1)
		var n [2]byte
		binary.BigEndian.PutUint16(n[:], uint16(len(s)))
		pool = append(pool, n[:]...)
		pool = append(pool, []byte(s)...)
		pool = append(pool, 8)
		var ref [2]byte
		binary.BigEndian.PutUint16(ref[:], uint16(1+2*i)) // the Utf8 slot just written
		pool = append(pool, ref[:]...)
	}
	var c [2]byte
	binary.BigEndian.PutUint16(c[:], uint16(count+1))
	return append(append(b, c[:]...), pool...)
}

func TestBehinderKeyAttributes(t *testing.T) {
	f, _ := Attribute(classWithLiterals("e45e329feb5d925b", "AES"))
	if f.Name != "behinder" {
		t.Fatalf("want behinder, got %q", f.Name)
	}
	if f.Evidence == "" || f.Confidence == 0 {
		t.Error("attribution must carry evidence and confidence")
	}
}

func TestGodzillaKeyAttributes(t *testing.T) {
	f, _ := Attribute(classWithLiterals("3c6e0b8a9c15224a"))
	if f.Name != "godzilla" {
		t.Fatalf("want godzilla, got %q", f.Name)
	}
}

// A marker must survive compilation. A constant pool holds `getClass` and `getClassLoader` as
// separate method refs, never the source text — a marker built on that could never fire.
func TestSourceLevelExpressionIsNotAMarker(t *testing.T) {
	if f, _ := Attribute(classWithLiterals("getClass().getClassLoader()")); f.Name != "" {
		t.Errorf("a source-level expression must not attribute, got %q", f.Name)
	}
}

func TestUnattributedIsNotAnError(t *testing.T) {
	if f, _ := Attribute(classWithLiterals("hello", "world")); f.Name != "" {
		t.Errorf("want no family, got %q", f.Name)
	}
}

func TestNilBytesSafe(t *testing.T) {
	if f, caps := Attribute(nil); f.Name != "" || caps != nil {
		t.Error("nil bytes must not attribute")
	}
}

func TestCapabilitiesAreSortedAndDeduped(t *testing.T) {
	_, caps := Attribute(classWithLiterals("java/lang/Runtime", "java/lang/ProcessBuilder", "javax/crypto/Cipher"))
	if len(caps) < 2 {
		t.Fatalf("want exec and crypto, got %v", caps)
	}
	for i := 1; i < len(caps); i++ {
		if caps[i-1] >= caps[i] {
			t.Fatalf("capabilities must be sorted and unique, got %v", caps)
		}
	}
	joined := strings.Join(caps, ",")
	if !strings.Contains(joined, "exec") || !strings.Contains(joined, "crypto") {
		t.Errorf("want exec+crypto, got %v", caps)
	}
}

func TestMalformedClassDoesNotPanic(t *testing.T) {
	for _, b := range [][]byte{{0xCA}, {0xCA, 0xFE, 0xBA, 0xBE}, {0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 52, 0xFF, 0xFF}} {
		if _, _, err := func() (f Family, c []string, err any) {
			defer func() { err = recover() }()
			f, c = Attribute(b)
			return
		}(); err != nil {
			t.Fatalf("Attribute panicked on malformed input: %v", err)
		}
	}
}

// ---------------------------------------------------------------- tunnel capability (Suo5)

// Suo5 is a TCP-over-HTTP tunnel, not a command shell: it never executes anything, so an
// exec-only capability vocabulary scored it a full tier below every command shell on the identical
// mechanism. The header it sets to stop nginx buffering its chunked stream is the discriminator the
// field already uses, and it is a constant-pool literal, so it can be read out of recovered
// bytecode BEFORE the shell is ever used -- which traffic-layer detection cannot do.
// Evidence: docs/measurements/2026-08-30-memshell-detection-landscape/02-tunnel-capability.md
func TestAntiBufferingHeaderIsTunnelCapability(t *testing.T) {
	_, caps := Attribute(classWithLiterals("X-Accel-Buffering", "no"))
	var got bool
	for _, c := range caps {
		if c == "tunnel" {
			got = true
		}
	}
	if !got {
		t.Fatalf("X-Accel-Buffering must yield the tunnel capability, got %v", caps)
	}
}

func TestAntiBufferingHeaderAttributesSuo5(t *testing.T) {
	f, _ := Attribute(classWithLiterals("X-Accel-Buffering"))
	if f.Name != "suo5" {
		t.Fatalf("want suo5, got %q", f.Name)
	}
	if f.Evidence == "" || f.Confidence == 0 {
		t.Error("attribution must carry evidence and confidence")
	}
}

// The load-bearing negative. java/net/Socket and friends are what Suo5 actually uses, and adding
// them would have been the obvious move -- but 45 of 4,016 classes in a stock Tomcat 9 reference
// java/net/Socket, because it is a web server. Counting relay APIs as capability would re-import
// exactly the weakness the exec gate was added to remove, so they must stay out of the vocabulary.
func TestRelayApisAreNotACapability(t *testing.T) {
	for _, needle := range []string{
		"java/net/Socket", "java/nio/channels/SocketChannel", "java/net/InetSocketAddress",
		"setTcpNoDelay", "java/util/concurrent/LinkedBlockingQueue",
	} {
		f, caps := Attribute(classWithLiterals(needle))
		for _, c := range caps {
			if c == "tunnel" || c == "exec" {
				t.Errorf("%s must not yield an action-grade capability, got %v", needle, caps)
			}
		}
		if f.Name != "" {
			t.Errorf("%s must not attribute a family, got %q", needle, f.Name)
		}
	}
}

// Neo-reGeorg is the other tunnel family in the corpus. Its classes carry neither the header nor
// java/net/Socket, so this marker cannot silently relabel one tunnel family as the other -- the
// failure mode the marker table's own comment warns about: a confident wrong answer in a report.
func TestTunnelMarkerDoesNotFireOnGenericProxyStrings(t *testing.T) {
	for _, s := range []string{"X-Forwarded-For", "Transfer-Encoding", "chunked", "Connection",
		"X-Powered-By", "Content-Length"} {
		if f, caps := Attribute(classWithLiterals(s)); f.Name != "" || len(caps) != 0 {
			t.Errorf("%q must not attribute or capability-match, got family=%q caps=%v", s, f.Name, caps)
		}
	}
}

// AN AGENT-ISOLATED LAYOUT IS NOT A SPOOFED ORIGIN. OpenTelemetry's javaagent stores its classes as
// inst/<path>.classdata so the application's classloaders cannot pick them up -- its own
// javaagent-structure.md says the extension exists for exactly that reason. Looking only for the
// plain entry reported four benign OTel classes as likely-malicious at score 100 with
// LoaderContradiction set, i.e. "a loader fabricating bytes", when the jar genuinely held them.
func TestAgentIsolatedLayoutIsCorroborated(t *testing.T) {
	jar := makeJar(t, t.TempDir(),
		"inst/io/opentelemetry/javaagent/tooling/AgentStarterImpl$X.classdata")
	v := Verify(Claim{
		ClassName:     "io.opentelemetry.javaagent.tooling.AgentStarterImpl$X",
		CodeSourceJar: jar,
		LoaderReadOK:  true,
	}, "")
	if v.Status != Corroborated {
		t.Fatalf("want corroborated, got %v (%s)", v.Status, v.Detail)
	}
	if v.LoaderContradiction {
		t.Error("the loader did not contradict anything: the class IS in the jar it claims")
	}
	if !strings.Contains(v.Detail, "agent-isolated layout") {
		t.Errorf("the detail must say the match was not a plain one, got %q", v.Detail)
	}
}

// THE OTHER DIRECTION. The fallback must not become a wildcard: a jar that contains NEITHER form is
// still a spoofed origin, and the detail must name both paths that were looked for.
func TestNeitherPlainNorRelocatedEntryIsStillSpoofed(t *testing.T) {
	jar := makeJar(t, t.TempDir(), "some/other/Thing.class")
	v := Verify(Claim{ClassName: "com.evil.Shell", CodeSourceJar: jar, LoaderReadOK: true}, "")
	if v.Status != Spoofed {
		t.Fatalf("want spoofed, got %v (%s)", v.Status, v.Detail)
	}
	if !v.LoaderContradiction {
		t.Error("the loader answering where the archive did not must still be flagged")
	}
	if !strings.Contains(v.Detail, ".classdata") {
		t.Errorf("the detail must name the relocated path it also looked for, got %q", v.Detail)
	}
}

// The relocated form must be ANCHORED. A class whose bytes sit at a same-named entry somewhere else
// in the tree must not be accepted -- otherwise an implant could be "verified" by any jar that
// happens to contain a similarly named file.
func TestRelocatedFormIsAnchoredNotASuffixMatch(t *testing.T) {
	jar := makeJar(t, t.TempDir(),
		"other/inst/com/evil/Shell.classdata", "com/evil/Shell.classdata")
	v := Verify(Claim{ClassName: "com.evil.Shell", CodeSourceJar: jar, LoaderReadOK: true}, "")
	if v.Status != Spoofed {
		t.Fatalf("only the anchored inst/ prefix counts; want spoofed, got %v (%s)", v.Status, v.Detail)
	}
}
