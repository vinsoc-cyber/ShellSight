package discover

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The resolution chain these tests pin is vendor-documented and recorded with citations in
// the webroot-discovery prior-art review (held privately) (Finding 2):
//
//	-Dcatalina.base -> $BASE/conf/server.xml -> <Host appBase> -> $BASE/<appBase>
//	                                         -> <Context docBase>
//
// The review's verdict on it was REUSE, because it is the incumbent's method and it is correct.

const stockishServerXML = `<?xml version="1.0" encoding="UTF-8"?>
<Server port="8005" shutdown="SHUTDOWN">
  <Service name="Catalina">
    <Connector port="8080" protocol="HTTP/1.1" />
    <Engine name="Catalina" defaultHost="localhost">
      <Host name="localhost" appBase="webapps" unpackWARs="true" autoDeploy="true">
      </Host>
      <!-- The stock file ships commented examples like this one. Reading them as configuration
           manufactures discovered-then-refused paths out of a comment.
      <Host name="ghost.example" appBase="/srv/ghost">
        <Context docBase="/srv/ghost-app" path="/app" />
      </Host>
      -->
    </Engine>
  </Service>
</Server>
`

func writeServerXML(t *testing.T, base, body string) string {
	t.Helper()
	conf := filepath.Join(base, "conf")
	if err := os.MkdirAll(conf, 0o755); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(conf, "server.xml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// --- T078: appBase resolution -------------------------------------------------------------------

func TestAppBaseResolvesRelativeToTheInstanceBase(t *testing.T) {
	base := t.TempDir()
	conf := writeServerXML(t, base, stockishServerXML)
	roots, note := rootsForCatalinaBase(catalinaBase{
		Path: base, Mechanism: MechTomcatEnv, Source: "CATALINA_BASE",
	})
	if note != "" {
		t.Fatalf("a well-formed server.xml needs no note, got %q", note)
	}
	if len(roots) != 1 {
		t.Fatalf("one live Host, one root — the commented example must be ignored, got %+v", roots)
	}
	want := filepath.Join(base, "webapps")
	if roots[0].Path != want {
		t.Fatalf("appBase must resolve under the instance base: want %q got %q", want, roots[0].Path)
	}
	// Provenance: the mechanism says how the INSTANCE was found, the source says which file named
	// the directory. Conflating them would lose one of the two facts.
	if roots[0].Mechanism != MechTomcatEnv || roots[0].Source != conf {
		t.Fatalf("provenance wrong: %+v", roots[0])
	}
}

func TestAHostWithNoAppBaseGetsTheDocumentedDefault(t *testing.T) {
	// Tomcat 10.1 config/host.html: "Default: webapps". A missing attribute is not a dead end, and
	// treating it as one would silently skip a live instance.
	base := t.TempDir()
	writeServerXML(t, base, `<Server><Service><Engine><Host name="localhost"/></Engine></Service></Server>`)
	roots, _ := rootsForCatalinaBase(catalinaBase{Path: base, Mechanism: MechTomcatEnv, Source: "CATALINA_BASE"})
	if len(roots) != 1 || roots[0].Path != filepath.Join(base, "webapps") {
		t.Fatalf("want the default webapps under the base, got %+v", roots)
	}
}

func TestAnAbsoluteAppBaseIsUsedAsGiven(t *testing.T) {
	base := t.TempDir()
	elsewhere := filepath.Join(t.TempDir(), "srv", "sites")
	writeServerXML(t, base, `<Server><Service><Engine><Host name="a" appBase="`+
		filepath.ToSlash(elsewhere)+`"/></Engine></Service></Server>`)
	roots, _ := rootsForCatalinaBase(catalinaBase{Path: base, Mechanism: MechTomcatEnv, Source: "CATALINA_BASE"})
	if len(roots) != 1 {
		t.Fatalf("got %+v", roots)
	}
	if !strings.EqualFold(filepath.ToSlash(roots[0].Path), filepath.ToSlash(filepath.Clean(elsewhere))) {
		t.Fatalf("an absolute appBase must not be joined to the base: got %q want %q",
			roots[0].Path, elsewhere)
	}
}

func TestAContextDocBaseOutsideAppBaseIsFound(t *testing.T) {
	// The case a webapps-only scan misses completely: one application deployed from somewhere else
	// entirely. An attacker who can write server.xml can also point a Context at a directory they
	// control, and a scanner that only looks at webapps never sees it.
	base := t.TempDir()
	writeServerXML(t, base, `<Server><Service><Engine>
	  <Host name="localhost" appBase="webapps">
	    <Context docBase="/opt/legacy-app" path="/legacy"/>
	  </Host>
	</Engine></Service></Server>`)
	roots, _ := rootsForCatalinaBase(catalinaBase{Path: base, Mechanism: MechTomcatEnv, Source: "CATALINA_BASE"})
	if len(roots) != 2 {
		t.Fatalf("want appBase and docBase, got %+v", roots)
	}
	var sawLegacy bool
	for _, r := range roots {
		if strings.Contains(filepath.ToSlash(r.Path), "legacy-app") {
			sawLegacy = true
		}
	}
	if !sawLegacy {
		t.Fatalf("the Context docBase must be discovered, got %+v", roots)
	}
}

func TestAnUnreadableServerXMLFallsBackToWebappsAndSaysSo(t *testing.T) {
	// A stopped instance, an unreadable base, or a CATALINA_HOME that is only a binary distribution.
	// $BASE/webapps is still the right guess, but it is attributed to the env var — not to a config
	// file that was never read, which would be a fabricated citation.
	base := t.TempDir()
	roots, note := rootsForCatalinaBase(catalinaBase{Path: base, Mechanism: MechTomcatEnv, Source: "CATALINA_BASE"})
	if len(roots) != 1 || roots[0].Path != filepath.Join(base, "webapps") {
		t.Fatalf("want the documented default, got %+v", roots)
	}
	if roots[0].Source != "CATALINA_BASE" {
		t.Fatalf("must not cite a file it never read, got %+v", roots[0])
	}
	if note != "" {
		t.Fatalf("an absent server.xml is the ordinary case, not a parse note, got %q", note)
	}
}

func TestAMalformedServerXMLIsReportedAndStillFallsBack(t *testing.T) {
	// A host that is nonetheless serving out of webapps must not become invisible because its config
	// was truncated or edited. Report the problem, keep the coverage.
	base := t.TempDir()
	writeServerXML(t, base, `<Server><Service><Engine><Host appBase="webapps"`)
	roots, note := rootsForCatalinaBase(catalinaBase{Path: base, Mechanism: MechTomcatProcess, Source: "pid 42 -Dcatalina.base"})
	if len(roots) != 1 || roots[0].Path != filepath.Join(base, "webapps") {
		t.Fatalf("want the fallback root, got %+v", roots)
	}
	if note == "" || !strings.Contains(note, "server.xml") {
		t.Fatalf("a malformed config must be reported, got %q", note)
	}
}

func TestCommentedConfigurationIsNotRead(t *testing.T) {
	appBases, docBases, err := parseServerXML([]byte(stockishServerXML))
	if err != nil {
		t.Fatal(err)
	}
	if len(appBases) != 1 || appBases[0] != "webapps" {
		t.Fatalf("only the live Host counts, got %v", appBases)
	}
	if len(docBases) != 0 {
		t.Fatalf("the commented Context must not be read, got %v", docBases)
	}
}

// --- T084: instances the environment does not mention -------------------------------------------

func TestCatalinaBaseIsReadOffAProcessCommandLine(t *testing.T) {
	// FR-034a. An instance started by systemd or by another user has its location on the command
	// line and nowhere in the scanning user's environment, and there is no fixed path for
	// config-file discovery to look in either — a Tomcat instance can live anywhere.
	bases := catalinaBasesFromCmdlines(map[int][]string{
		1234: {"/usr/bin/java", "-Djava.util.logging.config.file=/opt/tc/conf/logging.properties",
			"-Dcatalina.base=/opt/tomcat-instance", "-Dcatalina.home=/opt/tomcat", "org.apache.catalina.startup.Bootstrap"},
		99: {"/usr/sbin/sshd", "-D"},
	})
	if len(bases) != 2 {
		t.Fatalf("want base and home, got %+v", bases)
	}
	byPath := map[string]catalinaBase{}
	for _, b := range bases {
		byPath[b.Path] = b
	}
	inst, ok := byPath["/opt/tomcat-instance"]
	if !ok {
		t.Fatalf("catalina.base missing from %+v", bases)
	}
	if inst.Mechanism != MechTomcatProcess || !strings.Contains(inst.Source, "1234") {
		t.Fatalf("a process-derived base must name the pid it came from, got %+v", inst)
	}
}

func TestAJVMWithoutCatalinaPropertiesIsIgnored(t *testing.T) {
	// Not every JVM is a Tomcat. A scanner that treated any java process as one would propose the
	// working directory of every unrelated service on the host.
	bases := catalinaBasesFromCmdlines(map[int][]string{
		7: {"/usr/bin/java", "-jar", "/opt/app/app.jar"},
	})
	if len(bases) != 0 {
		t.Fatalf("want none, got %+v", bases)
	}
}

func TestAPropertyIsMatchedExactlyNotByPrefix(t *testing.T) {
	// -Dcatalina.base.override= must not be read as -Dcatalina.base=. The value would be a
	// fabricated path, and on a compromised host an attacker chooses the argument.
	if got := catalinaProperty([]string{"-Dcatalina.based=/wrong"}, "catalina.base"); got != "" {
		t.Fatalf("prefix match leaked: %q", got)
	}
	if got := catalinaProperty([]string{"-Dcatalina.base=/right"}, "catalina.base"); got != "/right" {
		t.Fatalf("exact match failed: %q", got)
	}
}

func TestTomcatReportsBothMechanismsEvenWhenNeitherFindsAnything(t *testing.T) {
	// "Discovery must degrade, not fail" (prior-art review, property 1). On a host with no Tomcat,
	// each mechanism must still say what it did — and an absent CATALINA_BASE is a different fact
	// from an unreadable process table.
	t.Setenv("CATALINA_BASE", "")
	t.Setenv("CATALINA_HOME", "")
	// The premise is "a host with no Tomcat". The WSL2 verification host has had a real Debian
	// tomcat10 running since the 2026-08-25 measurement (pid 252, -Dcatalina.base=/var/lib/tomcat10),
	// on which tomcat-process correctly SUCCEEDS with no detail -- so the case cannot be built there.
	if len(catalinaBasesFromCmdlines(readProcessTable().ByPID)) > 0 {
		t.Skip("a Tomcat is running on this host; the no-Tomcat case cannot be built here")
	}
	_, outcomes := tomcatRoots(Options{})
	seen := map[Mechanism]Outcome{}
	for _, o := range outcomes {
		seen[o.Mechanism] = o
	}
	for _, m := range []Mechanism{MechTomcatEnv, MechTomcatProcess, MechTomcatServerXML} {
		o, ok := seen[m]
		if !ok {
			t.Errorf("mechanism %q did not account for itself", m)
			continue
		}
		if o.Status == "" || o.Detail == "" {
			t.Errorf("mechanism %q must say what it did and why: %+v", m, o)
		}
	}
}

func TestRefusingTomcatProcessInspectionLeavesTheEnvLookupWorking(t *testing.T) {
	base := t.TempDir()
	writeServerXML(t, base, stockishServerXML)
	if err := os.MkdirAll(filepath.Join(base, "webapps"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CATALINA_BASE", base)
	t.Setenv("CATALINA_HOME", "")
	roots, outcomes := tomcatRoots(Options{Refuse: map[Mechanism]bool{MechTomcatProcess: true}})
	if len(roots) == 0 {
		t.Fatal("refusing process inspection must not disable the env lookup")
	}
	for _, o := range outcomes {
		if o.Mechanism == MechTomcatProcess && o.Status != StatusRefused {
			t.Fatalf("the refused mechanism must say so, got %+v", o)
		}
	}
}
