package discover

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// T085 / FR-033: JBoss, WebLogic and WebSphere. The genuine coverage gap -- and the one place in
// discovery where the method is NOT vendor-documented.
//
// The prior-art review is explicit that -Djboss.home.dir, -Dweblogic.* and -Dserver.root are
// "conventional startup properties rather than documented discovery APIs" and must be treated as
// "heuristics with a confirmation step (does the derived path exist and contain a deployment
// layout?), not as authoritative facts". These tests pin that confirmation, in both directions.
//
// Linux-only because the confirmation needs a process table.

func install(t *testing.T, base string, dirs ...string) string {
	t.Helper()
	for _, d := range dirs {
		if err := os.MkdirAll(filepath.Join(base, filepath.FromSlash(d)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return base
}

func TestAJBossDeploymentDirectoryIsDiscovered(t *testing.T) {
	home := install(t, filepath.Join(t.TempDir(), "wildfly"), "standalone/deployments", "modules", "bin")
	fakeProc(t, map[string][]string{
		"812": {"/usr/bin/java", "-D[Standalone]", "-Djboss.home.dir=" + home,
			"-Djboss.server.base.dir=" + filepath.Join(home, "standalone"),
			"org.jboss.as.standalone"},
	})
	roots, outcomes := appserverRoots(Options{})
	if outcomes[0].Status != StatusSucceeded {
		t.Fatalf("outcome: %+v", outcomes[0])
	}
	want := filepath.Join(home, "standalone", "deployments")
	var got *Root
	for i := range roots {
		if roots[i].Path == want {
			got = &roots[i]
		}
	}
	if got == nil {
		t.Fatalf("want %q, got %+v", want, roots)
	}
	// The product and the property belong in the provenance: an operator triaging a finding needs to
	// know this came from a JVM command line, which is a weaker claim than a config file.
	for _, want := range []string{"812", "jboss", "JBoss"} {
		if !strings.Contains(got.Source, want) {
			t.Errorf("source %q must mention %q", got.Source, want)
		}
	}
}

func TestTheServerHomeItselfIsNeverProposed(t *testing.T) {
	// The confirmation step's whole point. $JBOSS_HOME holds thousands of JARs, logs and configs;
	// scanning it would buy false positives and hours of I/O, and it is not where applications live.
	home := install(t, filepath.Join(t.TempDir(), "wildfly"), "standalone/deployments")
	fakeProc(t, map[string][]string{"812": {"java", "-Djboss.home.dir=" + home}})
	roots, _ := appserverRoots(Options{})
	for _, r := range roots {
		if r.Path == home {
			t.Fatalf("the server home must never be a webroot: %+v", r)
		}
	}
	if len(roots) == 0 {
		t.Fatal("the deployment directory beneath it should still have been found")
	}
}

func TestAnInstallWithNoKnownLayoutIsNamedNotDropped(t *testing.T) {
	// THE UNCOMFORTABLE DIRECTION. The layout list is finite and fails CLOSED: a layout it does not
	// know means no root, which on a real server is a missed webshell. A silent miss would be
	// indistinguishable from "no application server here", so the base is named and --path suggested.
	home := install(t, filepath.Join(t.TempDir(), "exotic-jboss"), "some/vendor/layout")
	fakeProc(t, map[string][]string{"900": {"java", "-Djboss.home.dir=" + home}})
	roots, outcomes := appserverRoots(Options{})
	if len(roots) != 0 {
		t.Fatalf("nothing is confirmed here, so nothing may be proposed, got %+v", roots)
	}
	if outcomes[0].Status != StatusAttempted {
		t.Fatalf("want attempted, got %+v", outcomes[0])
	}
	for _, want := range []string{home, "--path", "unrecognised"} {
		if !strings.Contains(outcomes[0].Detail, want) {
			t.Errorf("the detail must contain %q so the gap is answerable, got %q", want, outcomes[0].Detail)
		}
	}
}

func TestAPropertyNamingNothingIsNotReportedAsAnUnrecognisedLayout(t *testing.T) {
	// A stale command line, or a forged -D on a compromised host. It says nothing about where
	// applications live, and reporting it as an unrecognised layout would bury the case that matters
	// under the case that does not.
	fakeProc(t, map[string][]string{
		"901": {"java", "-Djboss.home.dir=/opt/gone-" + t.Name()},
	})
	roots, outcomes := appserverRoots(Options{})
	if len(roots) != 0 {
		t.Fatalf("got %+v", roots)
	}
	if strings.Contains(outcomes[0].Detail, "unrecognised") {
		t.Fatalf("a nonexistent path is not an unrecognised layout, got %q", outcomes[0].Detail)
	}
	if !strings.Contains(outcomes[0].Detail, "does not exist") {
		t.Fatalf("it should still be disclosed, got %q", outcomes[0].Detail)
	}
}

func TestWebLogicPerServerStageDirectoriesAreGlobbed(t *testing.T) {
	// Managed-server directories are named by the operator, so the layout carries a `*` segment and
	// each match is its own root.
	domain := install(t, filepath.Join(t.TempDir(), "domain"),
		"autodeploy", "servers/AdminServer/stage", "servers/managed1/stage", "config")
	fakeProc(t, map[string][]string{
		"1500": {"java", "-Dweblogic.Name=AdminServer", "-Dweblogic.RootDirectory=" + domain,
			"weblogic.Server"},
	})
	roots, outcomes := appserverRoots(Options{})
	if outcomes[0].Status != StatusSucceeded {
		t.Fatalf("outcome: %+v", outcomes[0])
	}
	found := map[string]bool{}
	for _, r := range roots {
		found[r.Path] = true
	}
	for _, want := range []string{
		filepath.Join(domain, "autodeploy"),
		filepath.Join(domain, "servers", "AdminServer", "stage"),
		filepath.Join(domain, "servers", "managed1", "stage"),
	} {
		if !found[want] {
			t.Errorf("want %q among %v", want, roots)
		}
	}
	// config/ is not a deployment directory and must not be swept in with them.
	if found[filepath.Join(domain, "config")] {
		t.Error("config/ is not where applications live")
	}
}

func TestWebSphereInstalledAppsIsDiscovered(t *testing.T) {
	profile := install(t, filepath.Join(t.TempDir(), "AppSrv01"), "installedApps", "logs", "config")
	fakeProc(t, map[string][]string{
		"2100": {"java", "-Dserver.root=" + profile, "com.ibm.ws.runtime.WsServer"},
	})
	roots, _ := appserverRoots(Options{})
	want := filepath.Join(profile, "installedApps")
	var ok bool
	for _, r := range roots {
		if r.Path == want {
			ok = true
			if !strings.Contains(r.Source, "WebSphere") {
				t.Errorf("source must name the product, got %q", r.Source)
			}
		}
	}
	if !ok {
		t.Fatalf("want %q, got %+v", want, roots)
	}
}

func TestAnAppserverPropertyIsMatchedExactly(t *testing.T) {
	// On a compromised host the attacker writes the command line, so -Djboss.home.dir.evil must not
	// be read as -Djboss.home.dir. The confirmation step would still gate it, but a prefix match
	// would let an attacker choose WHICH real directory gets scanned and reported.
	home := install(t, filepath.Join(t.TempDir(), "wildfly"), "standalone/deployments")
	fakeProc(t, map[string][]string{"812": {"java", "-Djboss.home.dir.evil=" + home}})
	roots, _ := appserverRoots(Options{})
	if len(roots) != 0 {
		t.Fatalf("a near-miss property name must not match, got %+v", roots)
	}
}

func TestAnAppserverWithNoDeploymentsDirectoryProposesNothing(t *testing.T) {
	// A base that exists with the right product but an empty layout: confirmation fails, so nothing
	// is proposed. Better a disclosed gap than a scan of the product install.
	home := install(t, filepath.Join(t.TempDir(), "wildfly"), "modules")
	fakeProc(t, map[string][]string{"812": {"java", "-Djboss.home.dir=" + home}})
	roots, outcomes := appserverRoots(Options{})
	if len(roots) != 0 {
		t.Fatalf("got %+v", roots)
	}
	if !strings.Contains(outcomes[0].Detail, home) {
		t.Fatalf("the install must be named, got %q", outcomes[0].Detail)
	}
}

func TestAppserverDiscoveryIsRefusable(t *testing.T) {
	home := install(t, filepath.Join(t.TempDir(), "wildfly"), "standalone/deployments")
	fakeProc(t, map[string][]string{"812": {"java", "-Djboss.home.dir=" + home}})
	roots, outcomes := appserverRoots(Options{Refuse: map[Mechanism]bool{MechAppserverProcess: true}})
	if len(roots) != 0 || outcomes[0].Status != StatusRefused {
		t.Fatalf("got %+v / %+v", roots, outcomes)
	}
}

func TestOneProcessSweepServesBothJavaMechanisms(t *testing.T) {
	// Tomcat and the application servers read the same table. Sweeping /proc twice would double the
	// cost on a busy host and let the two disagree about what was running.
	home := install(t, filepath.Join(t.TempDir(), "wildfly"), "standalone/deployments")
	fakeProc(t, map[string][]string{
		"812":  {"java", "-Djboss.home.dir=" + home},
		"2417": {"java", "-Dcatalina.base=/opt/tomcat/instance"},
	})
	appRoots, _ := appserverRoots(Options{})
	if len(appRoots) == 0 {
		t.Fatal("the JBoss deployment directory must be found")
	}
	bases, _ := catalinaBasesFromProcesses(Options{})
	if len(bases) != 1 || bases[0].Path != "/opt/tomcat/instance" {
		t.Fatalf("the Tomcat instance must be found from the same table, got %+v", bases)
	}
}
