package discover

// Spec 007 US2: locate an application server's deployment directories in a filesystem where nothing is
// running -- an image, a snapshot, another container's root view -- from the locations its vendor or
// its official image documents (prior-art Finding 4, research R3). Every layout below is one cited row
// of that table; a layout that is not cited is not here, and the mechanism must SAY it is not checked.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const fixtureServerXML = `<?xml version="1.0" encoding="UTF-8"?>
<Server port="8005" shutdown="SHUTDOWN">
  <Service name="Catalina">
    <Engine name="Catalina" defaultHost="localhost">
      <Host name="localhost" appBase="webapps" unpackWARs="true" autoDeploy="true"/>
    </Engine>
  </Service>
</Server>`

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// --- one builder per cited layout; each takes the image root and returns the in-filesystem
// --- deployment directory the mechanism must propose.

func layoutTomcatOfficial(t *testing.T, root string) string {
	writeFile(t, filepath.Join(root, "usr/local/tomcat/conf/server.xml"), fixtureServerXML)
	mustDir(t, filepath.Join(root, "usr/local/tomcat/webapps/ROOT"))
	return "/usr/local/tomcat/webapps"
}

func layoutTomcatDebian(t *testing.T, root string) string {
	// CATALINA_BASE=/var/lib/tomcat10 whose conf is a symlink to /etc/tomcat10 -- ABSOLUTE, in the
	// image's namespace. Resolving it in ours would look for /etc/tomcat10 on the scanning host.
	writeFile(t, filepath.Join(root, "etc/tomcat10/server.xml"), fixtureServerXML)
	mustDir(t, filepath.Join(root, "var/lib/tomcat10/webapps/ROOT"))
	if err := os.Symlink("/etc/tomcat10", filepath.Join(root, "var/lib/tomcat10/conf")); err != nil {
		t.Skipf("cannot create a symlink on this platform: %v", err)
	}
	return "/var/lib/tomcat10/webapps"
}

func layoutTomcatBitnami(t *testing.T, root string) string {
	writeFile(t, filepath.Join(root, "opt/bitnami/tomcat/conf/server.xml"), fixtureServerXML)
	mustDir(t, filepath.Join(root, "opt/bitnami/tomcat/webapps"))
	return "/opt/bitnami/tomcat/webapps"
}

func layoutWildFly(t *testing.T, root string) string {
	mustDir(t, filepath.Join(root, "opt/jboss/wildfly/standalone/deployments"))
	return "/opt/jboss/wildfly/standalone/deployments"
}

func layoutWebLogic(t *testing.T, root string) string {
	mustDir(t, filepath.Join(root, "u01/oracle/user_projects/domains/base_domain/autodeploy"))
	return "/u01/oracle/user_projects/domains/base_domain/autodeploy"
}

func layoutLiberty(t *testing.T, root string) string {
	mustDir(t, filepath.Join(root, "opt/ibm/wlp/usr/servers/defaultServer/dropins"))
	mustDir(t, filepath.Join(root, "opt/ibm/wlp/usr/servers/defaultServer/apps"))
	return "/opt/ibm/wlp/usr/servers/defaultServer/dropins"
}

func layoutOpenLiberty(t *testing.T, root string) string {
	mustDir(t, filepath.Join(root, "opt/ol/wlp/usr/servers/defaultServer/dropins"))
	return "/opt/ol/wlp/usr/servers/defaultServer/dropins"
}

func layoutWebSphereTraditional(t *testing.T, root string) string {
	mustDir(t, filepath.Join(root, "opt/IBM/WebSphere/AppServer/profiles/AppSrv01/installedApps"))
	return "/opt/IBM/WebSphere/AppServer/profiles/AppSrv01/installedApps"
}

func findRoot(res Result, inFS string) (Root, bool) {
	for _, r := range res.Roots {
		if r.InFilesystem == inFS {
			return r, true
		}
	}
	return Root{}, false
}

func outcomeFor(res Result, m Mechanism) (Outcome, bool) {
	for _, o := range res.Outcomes {
		if o.Mechanism == m {
			return o, true
		}
	}
	return Outcome{}, false
}

func TestEveryCitedLayoutIsDiscoveredInsideAnImage(t *testing.T) {
	cases := []struct {
		name      string
		build     func(*testing.T, string) string
		mechanism Mechanism
	}{
		{"tomcat official image", layoutTomcatOfficial, MechTomcatConvention},
		{"tomcat debian package", layoutTomcatDebian, MechTomcatConvention},
		{"tomcat bitnami image", layoutTomcatBitnami, MechTomcatConvention},
		{"wildfly official image", layoutWildFly, MechAppserverConvention},
		{"weblogic official image", layoutWebLogic, MechAppserverConvention},
		{"websphere liberty image", layoutLiberty, MechAppserverConvention},
		{"open liberty image", layoutOpenLiberty, MechAppserverConvention},
		{"websphere traditional image", layoutWebSphereTraditional, MechAppserverConvention},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			want := tc.build(t, root)
			res := Discover(nil, Options{Root: root})
			r, ok := findRoot(res, want)
			if !ok {
				t.Fatalf("%s: want a root served as %s, got roots=%+v rejected=%+v outcomes=%+v",
					tc.name, want, res.Roots, res.Rejected, res.Outcomes)
			}
			if r.Mechanism != tc.mechanism {
				t.Fatalf("%s: want mechanism %s, got %s", tc.name, tc.mechanism, r.Mechanism)
			}
			if !strings.HasPrefix(r.Path, filepath.Clean(root)) {
				t.Fatalf("%s: the scanned path must be inside the image mount, got %s", tc.name, r.Path)
			}
			if r.Source == "" {
				t.Fatalf("%s: a conventional root must cite either the configuration file it read or the source of the convention", tc.name)
			}
			o, ok := outcomeFor(res, tc.mechanism)
			if !ok || o.Status != StatusSucceeded {
				t.Fatalf("%s: want %s=succeeded, got %+v", tc.name, tc.mechanism, o)
			}
		})
	}
}

func TestATomcatInstanceWithAReadableServerXMLCitesIt(t *testing.T) {
	root := t.TempDir()
	want := layoutTomcatOfficial(t, root)
	res := Discover(nil, Options{Root: root})
	r, ok := findRoot(res, want)
	if !ok {
		t.Fatalf("want %s, got %+v", want, res.Roots)
	}
	if !strings.HasSuffix(filepath.ToSlash(r.Source), "/usr/local/tomcat/conf/server.xml") {
		t.Fatalf("a root read from server.xml must cite that file, got source %q", r.Source)
	}
}

func TestATomcatLocationWithoutServerXMLIsNotAnInstance(t *testing.T) {
	// A binary distribution unpacked at a conventional location, never configured: no conf/server.xml.
	// Tomcat's own minimum for an instance is conf/server.xml (introduction.html), so this proposes
	// nothing -- but the location is NAMED, because a responder must be able to tell "no Tomcat here"
	// from "Tomcat here, in a shape this release does not recognise".
	root := t.TempDir()
	mustDir(t, filepath.Join(root, "usr/local/tomcat/bin"))
	mustDir(t, filepath.Join(root, "usr/local/tomcat/webapps"))
	res := Discover(nil, Options{Root: root})
	if len(res.Roots) != 0 {
		t.Fatalf("a location without an instance layout must propose nothing, got %+v", res.Roots)
	}
	o, ok := outcomeFor(res, MechTomcatConvention)
	if !ok || o.Status != StatusAttempted || !strings.Contains(o.Detail, "exists without an instance layout: /usr/local/tomcat") {
		t.Fatalf("the unconfirmed location must be named in the outcome, got %+v", o)
	}
}

func TestAnAbsoluteAppBaseInsideTheImageIsMappedUnderTheRoot(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "usr/local/tomcat/conf/server.xml"),
		strings.Replace(fixtureServerXML, `appBase="webapps"`, `appBase="/srv/apps"`, 1))
	mustDir(t, filepath.Join(root, "srv/apps"))
	res := Discover(nil, Options{Root: root})
	r, ok := findRoot(res, "/srv/apps")
	if !ok {
		t.Fatalf("an absolute appBase names a directory in the IMAGE; want it served as /srv/apps, got %+v rejected=%+v", res.Roots, res.Rejected)
	}
	if r.Path != filepath.Join(root, "srv", "apps") {
		t.Fatalf("want the appBase mapped under the mount, got %s", r.Path)
	}
}

func TestADocBaseEscapingTheImageIsDropped(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "usr/local/tomcat/conf/server.xml"),
		strings.Replace(fixtureServerXML, `<Host name="localhost" appBase="webapps" unpackWARs="true" autoDeploy="true"/>`,
			`<Host name="localhost" appBase="webapps"><Context path="/x" docBase="../../../../../../etc"/></Host>`, 1))
	mustDir(t, filepath.Join(root, "usr/local/tomcat/webapps"))
	res := Discover(nil, Options{Root: root})
	for _, r := range res.Roots {
		if !strings.HasPrefix(r.Path, filepath.Clean(root)) {
			t.Fatalf("a docBase must never escape the image mount, got %s", r.Path)
		}
	}
	if _, ok := findRoot(res, "/usr/local/tomcat/webapps"); !ok {
		t.Fatalf("the appBase must still be proposed, got %+v", res.Roots)
	}
}

func TestTheOutcomeEnumeratesWhatWasCheckedAndWhatIsNot(t *testing.T) {
	// Constitution IV: the rows that stayed uncited are visible in the outcome, never implied.
	root := t.TempDir()
	res := Discover(nil, Options{Root: root})
	o, ok := outcomeFor(res, MechTomcatConvention)
	if !ok {
		t.Fatalf("tomcat-convention must always account for itself, got %+v", res.Outcomes)
	}
	if o.Status != StatusAttempted {
		t.Fatalf("with nothing found the status is attempted, got %s", o.Status)
	}
	for _, want := range []string{"checked", "conventional location(s)", "/usr/local/tomcat",
		"not checked in this release (no primary citation)", "/usr/share/tomcat", "/var/lib/tomcat"} {
		if !strings.Contains(o.Detail, want) {
			t.Errorf("tomcat-convention detail must contain %q, got %q", want, o.Detail)
		}
	}
	a, ok := outcomeFor(res, MechAppserverConvention)
	if !ok || a.Status != StatusAttempted {
		t.Fatalf("appserver-convention must account for itself, got %+v", a)
	}
	for _, want := range []string{"checked", "/opt/jboss/wildfly", "not checked in this release (no primary citation)", "/opt/eap"} {
		if !strings.Contains(a.Detail, want) {
			t.Errorf("appserver-convention detail must contain %q, got %q", want, a.Detail)
		}
	}
}

func TestTheConventionMechanismsCanBeRefused(t *testing.T) {
	root := t.TempDir()
	layoutTomcatOfficial(t, root)
	layoutWildFly(t, root)
	res := Discover(nil, Options{Root: root, Refuse: map[Mechanism]bool{MechTomcatConvention: true, MechAppserverConvention: true}})
	if len(res.Roots) != 0 {
		t.Fatalf("refused mechanisms must propose nothing, got %+v", res.Roots)
	}
	for _, m := range []Mechanism{MechTomcatConvention, MechAppserverConvention} {
		if o, ok := outcomeFor(res, m); !ok || o.Status != StatusRefused {
			t.Fatalf("want %s=refused, got %+v", m, o)
		}
	}
}

func TestAConventionalLocationSymlinkedToTheImageRootIsRefusedAndReported(t *testing.T) {
	root := t.TempDir()
	// /usr/local/tomcat/webapps -> / inside the image, with a real conf/server.xml beside it.
	writeFile(t, filepath.Join(root, "usr/local/tomcat/conf/server.xml"), fixtureServerXML)
	if err := os.Symlink("/", filepath.Join(root, "usr/local/tomcat/webapps")); err != nil {
		t.Skipf("cannot create a symlink on this platform: %v", err)
	}
	res := Discover(nil, Options{Root: root})
	if len(res.Roots) != 0 {
		t.Fatalf("a webapps pointing at the image root must not be scanned, got %+v", res.Roots)
	}
	found := false
	for _, rj := range res.Rejected {
		if rj.Mechanism == MechTomcatConvention && strings.Contains(rj.Reason, "containment") {
			found = true
		}
	}
	if !found {
		t.Fatalf("the refusal must be reported under tomcat-convention, got %+v", res.Rejected)
	}
}

func TestAConventionalTomcatIsDiscoveredOnTheLiveHostToo(t *testing.T) {
	// Same mechanism, no --root: a stopped instance that no environment variable names, at a location
	// the table knows. The table is redirected into a temp tree because this host has no Tomcat.
	base := t.TempDir()
	writeFile(t, filepath.Join(base, "tomcat/conf/server.xml"), fixtureServerXML)
	mustDir(t, filepath.Join(base, "tomcat/webapps"))
	prior := conventionTable
	conventionTable = func() []conventionSpec {
		return []conventionSpec{{
			Product: "Tomcat", Locations: []string{filepath.Join(base, "tomcat")},
			Citation: "test table", Confirm: confirmTomcatServerXML,
		}}
	}
	t.Cleanup(func() { conventionTable = prior })

	res := Discover(nil, Options{Refuse: map[Mechanism]bool{MechApacheConfig: true, MechNginxConfig: true,
		MechApacheDump: true, MechNginxDump: true, MechTomcatEnv: true, MechTomcatProcess: true,
		MechAppserverProcess: true, MechConvention: true, MechIISConfig: true, MechIISDefault: true}})
	want := filepath.Join(base, "tomcat", "webapps")
	var got *Root
	for i := range res.Roots {
		if pathKey(res.Roots[i].Path) == pathKey(want) {
			got = &res.Roots[i]
		}
	}
	if got == nil {
		t.Fatalf("want %s via tomcat-convention on the live host, got roots=%+v rejected=%+v", want, res.Roots, res.Rejected)
	}
	if got.Mechanism != MechTomcatConvention || got.InFilesystem != "" {
		t.Fatalf("live host: one namespace, mechanism tomcat-convention; got %+v", *got)
	}
}
