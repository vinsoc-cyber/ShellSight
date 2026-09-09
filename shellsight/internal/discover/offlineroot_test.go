package discover

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// FR-034 names three cases discovery must cover: "a mounted image, a snapshot, and a host whose web
// server is stopped". The third worked. The first did not, and the way it failed was the dangerous
// way — measured against the real binaries, a responder who mounted an image containing a webshell and
// ran the scan US6 exists to make possible got:
//
//	verdict=clean incomplete=false
//	    root /srv/hidden-apache  via apache-dump (/etc/apache2/extra-vhosts/hidden.conf)
//
// A clean verdict about an image that was never opened, with the ANALYST'S config files cited as
// provenance. Every config path in this package was an absolute literal rooted at the live `/`.

// fakeImage builds a filesystem as if mounted from another host, and points discovery at it.
func fakeImage(t *testing.T) (root, webroot string) {
	t.Helper()
	root = t.TempDir()
	webroot = filepath.Join(root, "var", "www", "imagesite")
	if err := os.MkdirAll(webroot, 0o755); err != nil {
		t.Fatal(err)
	}
	conf := filepath.Join(root, "etc", "nginx", "nginx.conf")
	if err := os.MkdirAll(filepath.Dir(conf), 0o755); err != nil {
		t.Fatal(err)
	}
	// The image's config speaks in ITS namespace, not ours.
	body := "http {\n  server {\n    root /var/www/imagesite;\n  }\n}\n"
	if err := os.WriteFile(conf, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	// Candidate lists are consulted in the scanned filesystem's namespace, so they must stay the
	// stock absolute paths and be mapped by Options.Root rather than by the test.
	priorN := nginxConfigPaths
	nginxConfigPaths = func() []string { return []string{"/etc/nginx/nginx.conf"} }
	priorA := apacheConfigPaths
	apacheConfigPaths = func() []string { return []string{"/etc/apache2/apache2.conf"} }
	t.Cleanup(func() { nginxConfigPaths, apacheConfigPaths = priorN, priorA })
	return root, webroot
}

// covering returns the root that scans want -- itself, or the enclosing root that subsumes it.
//
// Either is correct: /var/www exists inside the image and subsumes /var/www/imagesite, so the nested
// directory is scanned as part of its parent (T077). What matters is that it is covered, not how it is
// represented.
func covering(res Result, want string) *Root {
	for i := range res.Roots {
		if pathKey(res.Roots[i].Path) == pathKey(want) {
			return &res.Roots[i]
		}
		for _, sub := range res.Roots[i].Subsumes {
			if pathKey(sub) == pathKey(want) {
				return &res.Roots[i]
			}
		}
	}
	return nil
}

func TestAMountedImagesOwnConfigIsRead(t *testing.T) {
	root, webroot := fakeImage(t)
	res := Discover(nil, Options{Root: root})

	found := covering(res, webroot)
	if found == nil {
		t.Fatalf("the image's own webroot must be covered, got %+v", res.Roots)
	}
	// Every root must live inside the image: a scan of an image that reached outside it would be
	// reporting about the analyst's own machine.
	for _, r := range res.Roots {
		if !withinRoot(root, r.Path) {
			t.Errorf("a root outside the scanned filesystem: %q", r.Path)
		}
		// Both namespaces, because they answer different questions: the mount path is where the
		// scanner opened it, the in-filesystem path is what the compromised host was serving.
		if r.InFilesystem == "" {
			t.Errorf("a root from a mounted filesystem must keep that filesystem's own name: %+v", r)
		}
	}
	// The image's nginx.conf must have been the file read, not this host's.
	var readImageConfig bool
	for _, o := range res.Outcomes {
		if o.Mechanism == MechNginxConfig && o.Status == StatusSucceeded {
			readImageConfig = true
		}
	}
	if !readImageConfig {
		t.Errorf("the image's nginx.conf must have been read, got %+v", res.Outcomes)
	}
}

func TestAConfigPathThatEscapesTheImageIsRefusedAndReported(t *testing.T) {
	// An image's configuration is attacker-writable like any other, and filepath.Join cleans `..`
	// away silently — so `DocumentRoot /../../../etc` would resolve to the ANALYST'S /etc, turning a
	// request to scan an image into a scan of the machine doing the scanning.
	root, _ := fakeImage(t)
	conf := filepath.Join(root, "etc", "apache2", "apache2.conf")
	if err := os.MkdirAll(filepath.Dir(conf), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(conf, []byte("DocumentRoot /../../../etc\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	res := Discover(nil, Options{Root: root})
	for _, r := range res.Roots {
		if !withinRoot(root, r.Path) {
			t.Fatalf("a root outside the scanned filesystem reached the scanner: %q", r.Path)
		}
	}
	// Refusing silently would hide an attacker-authored escape attempt, which is a lead.
	var reported bool
	for _, o := range res.Outcomes {
		if o.Mechanism == MechApacheConfig && strings.Contains(o.Detail, "escapes the scanned filesystem") {
			reported = true
		}
	}
	if !reported {
		t.Fatalf("the escape attempt must be reported, got %+v", res.Outcomes)
	}
}

func TestLiveHostMechanismsRefuseToAnswerAboutAnImage(t *testing.T) {
	// Environment variables, the process table and a config-dump binary all describe the machine doing
	// the scanning. On a mounted image their answers are about the WRONG HOST, which is worse than no
	// answer — so they must report unavailable rather than contribute roots.
	root, _ := fakeImage(t)
	res := Discover(nil, Options{Root: root})

	byMech := map[Mechanism]Outcome{}
	for _, o := range res.Outcomes {
		byMech[o.Mechanism] = o
	}
	for _, m := range []Mechanism{
		MechTomcatEnv, MechTomcatProcess, MechAppserverProcess, MechApacheDump, MechNginxDump, MechIISConfig,
	} {
		o, ok := byMech[m]
		if !ok {
			t.Errorf("%s must still account for itself", m)
			continue
		}
		if o.Status != StatusUnavailable {
			t.Errorf("%s must be unavailable when scanning a mounted filesystem, got %+v", m, o)
		}
		if !strings.Contains(o.Detail, "running host") {
			t.Errorf("%s must say WHY it cannot answer, got %q", m, o.Detail)
		}
	}
	for _, r := range res.Roots {
		switch r.Mechanism {
		case MechTomcatEnv, MechTomcatProcess, MechAppserverProcess, MechApacheDump, MechNginxDump, MechIISConfig:
			t.Errorf("a live-host mechanism contributed a root for an image: %+v", r)
		}
	}
}

func TestConventionalLocationsAreLookedForInsideTheImage(t *testing.T) {
	root := t.TempDir()
	inside := filepath.Join(root, "var", "www", "html")
	if err := os.MkdirAll(inside, 0o755); err != nil {
		t.Fatal(err)
	}
	res := Discover(nil, Options{Root: root})
	if covering(res, inside) == nil {
		t.Fatalf("the image's conventional webroot must be covered, got %+v", res.Roots)
	}
	for _, r := range res.Roots {
		if !withinRoot(root, r.Path) {
			t.Errorf("a root outside the image: %q", r.Path)
		}
		if !strings.HasPrefix(r.InFilesystem, "/") {
			t.Errorf("want the image's own absolute name, got %q", r.InFilesystem)
		}
	}
}

func TestWithoutARootNothingChanges(t *testing.T) {
	// The control. The live path must be untouched by this feature, and InFilesystem must stay empty
	// so a normal report gains nothing.
	res := Discover(nil, Options{})
	for _, r := range res.Roots {
		if r.InFilesystem != "" {
			t.Errorf("a live scan must not carry a second namespace: %+v", r)
		}
	}
}

func TestWithinRootTruthTable(t *testing.T) {
	for _, tc := range []struct {
		root, path string
		want       bool
	}{
		{"/mnt/img", "/mnt/img", true},
		{"/mnt/img", "/mnt/img/var/www", true},
		{"/mnt/img", "/mnt/img-other", false}, // prefix, not containment
		{"/mnt/img", "/etc", false},
		{"/mnt/img", "/mnt", false},
	} {
		root := filepath.FromSlash(tc.root)
		path := filepath.FromSlash(tc.path)
		if got := withinRoot(root, path); got != tc.want {
			t.Errorf("withinRoot(%q, %q) = %v, want %v", root, path, got, tc.want)
		}
	}
}
