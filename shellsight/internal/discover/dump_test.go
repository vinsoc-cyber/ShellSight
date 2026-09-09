package discover

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// These tests run against REAL captured output, not against a format read off a web page.
//
// nginx 1.28.3 and Apache 2.4.66 were installed on an Ubuntu 25.10 host for the purpose, with a vhost
// placed in a custom include directory that is in neither glob set. testdata/ holds what they printed.
// That also closes an open question the prior-art review recorded as untested: whether the -S output
// needed separate parsers per distro family.

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// stubExec makes the dump mechanisms testable on a host with no web server.
func stubExec(t *testing.T, output []byte, runErr error, installed ...string) {
	t.Helper()
	priorRun, priorLook := runCommand, lookPath
	present := map[string]bool{}
	for _, n := range installed {
		present[n] = true
	}
	runCommand = func(string, ...string) ([]byte, error) { return output, runErr }
	lookPath = func(name string) (string, error) {
		if present[name] {
			return "/usr/sbin/" + name, nil
		}
		return "", errors.New("not found")
	}
	t.Cleanup(func() { runCommand, lookPath = priorRun, priorLook })
}

// --- T082: nginx -T resolves includes -----------------------------------------------------------

func TestTheNginxDumpFindsARootInsideAnIncludedFile(t *testing.T) {
	// THE MEASUREMENT. /srv/hidden-nginx lives in /etc/nginx/extra/site.conf, reached only by an
	// `include` line. nginxConfigFiles() globs sites-enabled/* and conf.d/*.conf, so it cannot see
	// that file at all -- which is the entire justification for shelling out.
	roots := parseNginxDump(fixture(t, "nginx-T-ubuntu.txt"))
	var hidden *Root
	for i := range roots {
		if roots[i].Path == "/srv/hidden-nginx" {
			hidden = &roots[i]
		}
	}
	if hidden == nil {
		t.Fatalf("the included root must be found, got %+v", roots)
	}
	// Provenance has to name the FILE, not "nginx -T". The point of the dump is that it reaches files
	// the glob list never names, so telling an operator to go and read one is the useful half.
	if hidden.Source != "/etc/nginx/extra/site.conf" {
		t.Fatalf("the root must be attributed to its own file, got %q", hidden.Source)
	}
	if hidden.Mechanism != MechNginxDump {
		t.Fatalf("mechanism: %+v", *hidden)
	}
}

func TestTheGlobListCannotSeeWhatTheDumpFound(t *testing.T) {
	// The control that makes the previous test mean something: if the globs already covered the
	// include directory, the dump would be buying nothing and this whole mechanism would be a
	// gratuitous exec on a possibly-compromised host.
	for _, g := range nginxConfigFiles() {
		if strings.Contains(filepath.ToSlash(g), "/etc/nginx/extra") {
			t.Fatalf("the glob list already covers the include directory (%q), so the dump is not "+
				"buying include resolution and its exec cost is unjustified", g)
		}
	}
}

func TestOutputThatIsNotADumpYieldsNoRoots(t *testing.T) {
	// A replaced binary, a usage error, or a truncated pipe. Parsing an unrecognised blob as one
	// anonymous file would produce roots with a fabricated source, which is worse than none.
	if roots := parseNginxDump([]byte("root /etc;\nroot /var/www;\n")); len(roots) != 0 {
		t.Fatalf("no file markers means no attributable roots, got %+v", roots)
	}
}

func TestAnAbsentNginxIsUnavailableNotAFailure(t *testing.T) {
	stubExec(t, nil, nil) // nothing installed
	roots, outcomes := nginxDumpRoots(Options{})
	if len(roots) != 0 || len(outcomes) != 1 || outcomes[0].Status != StatusUnavailable {
		t.Fatalf("want a single unavailable outcome, got %+v / %+v", roots, outcomes)
	}
}

func TestAFailedNginxDumpKeepsConfigParsingApplicable(t *testing.T) {
	// The common case for an unprivileged responder: nginx -T reads files owned by root. It must
	// degrade to attempted with a reason, never look like a broken scan, because the primary
	// config-file method is unaffected.
	stubExec(t, []byte(""), errors.New("exit status 1"), "nginx")
	_, outcomes := nginxDumpRoots(Options{})
	if outcomes[0].Status != StatusAttempted || !strings.Contains(outcomes[0].Detail, "config-file parsing still applies") {
		t.Fatalf("want a degraded outcome that says the primary method still holds, got %+v", outcomes[0])
	}
}

func TestPartialDumpOutputIsStillParsed(t *testing.T) {
	// A dump that failed halfway named real files first, and those roots are real.
	stubExec(t, fixture(t, "nginx-T-ubuntu.txt"), errors.New("exit status 1"), "nginx")
	roots, outcomes := nginxDumpRoots(Options{})
	if len(roots) == 0 {
		t.Fatal("output present but nothing parsed")
	}
	if outcomes[0].Status != StatusSucceeded || outcomes[0].Detail == "" {
		t.Fatalf("succeeded, but the non-zero exit must be disclosed, got %+v", outcomes[0])
	}
}

// --- T083: apache -S resolves includes, and the Debian wrapper trap -----------------------------

func TestTheApacheDumpNamesTheVhostFilesIncludingUnglobbedOnes(t *testing.T) {
	main, files := parseApacheDump(fixture(t, "apache2ctl-S-ubuntu.txt"))
	if main != "/var/www/html" {
		t.Fatalf("Main DocumentRoot: got %q", main)
	}
	var sawHidden bool
	for _, f := range files {
		if f == "/etc/apache2/extra-vhosts/hidden.conf" {
			sawHidden = true
		}
	}
	if !sawHidden {
		t.Fatalf("the unglobbed vhost file must be revealed, got %v", files)
	}
	// -S does NOT print per-vhost DocumentRoot -- verified against real output -- so the files it
	// names have to be read afterwards. That indirection IS the include resolution.
	if strings.Contains(string(fixture(t, "apache2ctl-S-ubuntu.txt")), "/srv/hidden-apache") {
		t.Fatal("this fixture is expected NOT to contain the vhost's DocumentRoot; if -S started " +
			"printing it, apacheDumpRoots can read it directly and this indirection is unnecessary")
	}
}

func TestTheApacheDumpReadsDocumentRootOutOfTheFilesItNamed(t *testing.T) {
	// End to end with a real -S body but vhost files under a temp root, since the fixture's absolute
	// paths do not exist here.
	dir := t.TempDir()
	vhost := filepath.Join(dir, "hidden.conf")
	if err := os.WriteFile(vhost, []byte("<VirtualHost *:8081>\n  DocumentRoot /srv/hidden-apache\n</VirtualHost>\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	dump := "VirtualHost configuration:\n*:8081  hidden.example (" + filepath.ToSlash(vhost) + ":1)\n" +
		"ServerRoot: \"/etc/apache2\"\nMain DocumentRoot: \"/var/www/html\"\n"
	stubExec(t, []byte(dump), nil, "apache2ctl")
	roots, outcomes := apacheDumpRoots(Options{})
	if outcomes[0].Status != StatusSucceeded {
		t.Fatalf("outcome: %+v", outcomes[0])
	}
	var sawMain, sawHidden bool
	for _, r := range roots {
		switch r.Path {
		case "/var/www/html":
			sawMain = true
		case "/srv/hidden-apache":
			sawHidden = true
			if r.Source != filepath.ToSlash(vhost) {
				t.Errorf("the root must cite the vhost file, got %q", r.Source)
			}
		}
	}
	if !sawMain || !sawHidden {
		t.Fatalf("want both the main root and the vhost root, got %+v", roots)
	}
}

func TestApacheCtlIsPreferredAndTheRawBinaryIsNeverTried(t *testing.T) {
	// MEASURED, not assumed. `apache2 -S` on Debian/Ubuntu fails without envvars sourced —
	// testdata/apache2-S-no-envvars-ubuntu.txt is the real failure from Apache 2.4.66:
	//     AH00111: Config variable ${APACHE_RUN_DIR} is not defined
	// apache2ctl sources envvars itself. So the raw binary is not a fallback, it is a known-broken
	// invocation, and it must not be in the list at all.
	body := string(fixture(t, "apache2-S-no-envvars-ubuntu.txt"))
	if !strings.Contains(body, "APACHE_RUN_DIR") {
		t.Fatal("the fixture no longer shows the envvars failure it exists to record")
	}
	for _, w := range apacheWrappers {
		if w == "apache2" {
			t.Fatal("apache2 must not be invoked directly: it fails without envvars on Debian")
		}
	}
	if apacheWrappers[0] != "apache2ctl" {
		t.Fatalf("apache2ctl must be tried first, got %v", apacheWrappers)
	}
}

func TestAnAbsentApacheWrapperIsUnavailable(t *testing.T) {
	stubExec(t, nil, nil)
	roots, outcomes := apacheDumpRoots(Options{})
	if len(roots) != 0 || outcomes[0].Status != StatusUnavailable {
		t.Fatalf("got %+v / %+v", roots, outcomes)
	}
	if !strings.Contains(outcomes[0].Detail, "apache2ctl") {
		t.Fatalf("the detail must name what was looked for, got %q", outcomes[0].Detail)
	}
}

// --- one parser, two distro families ------------------------------------------------------------

// The prior-art review recorded this as untested: "Does httpd -S output on RHEL and Debian differ
// enough to need separate parsers? Not tested -- no Apache installed in the verification environment."
//
// Now measured on the non-Debian shape. Apache 2.4.68 (Unix) installed into an Alpine musl rootfs:
// the binary is /usr/sbin/httpd, there is NO apache2ctl at all, and ServerRoot is /var/www with the
// main root at /var/www/localhost/htdocs -- a layout that shares nothing with Debian's. The -S output
// format is nevertheless identical, because it comes from Apache's own DUMP_VHOSTS/DUMP_RUN_CFG rather
// than from the distribution.
//
// Answer: no separate parser. testdata/httpd-S-alpine.txt is that output, so this stays true only as
// long as it stays true.

func TestOneParserHandlesBothDistroFamilies(t *testing.T) {
	debian := fixture(t, "apache2ctl-S-ubuntu.txt")
	other := fixture(t, "httpd-S-alpine.txt")

	dMain, dFiles := parseApacheDump(debian)
	oMain, oFiles := parseApacheDump(other)

	if dMain != "/var/www/html" {
		t.Errorf("debian main root: got %q", dMain)
	}
	if oMain != "/var/www/localhost/htdocs" {
		t.Errorf("non-debian main root: got %q", oMain)
	}
	// The layouts share no paths, which is the point: the parser must not have learned Debian's.
	if strings.HasPrefix(oMain, "/var/www/html") {
		t.Error("the two fixtures must exercise genuinely different layouts")
	}
	if len(dFiles) == 0 || len(oFiles) == 0 {
		t.Fatalf("both must yield vhost files: debian=%v other=%v", dFiles, oFiles)
	}
	var sawHidden bool
	for _, f := range oFiles {
		if f == "/etc/apache2/extra-vhosts/hidden.conf" {
			sawHidden = true
		}
	}
	if !sawHidden {
		t.Errorf("the non-globbed include must be revealed here too, got %v", oFiles)
	}
}

func TestTheNonDebianDumpNeedsNoWrapper(t *testing.T) {
	// apache2ctl does not exist on that host, so `httpd` has to be reachable in the resolution order —
	// and it is last, after the two wrappers, which is correct: where a wrapper exists it is the one
	// that sources envvars.
	var sawHTTPD bool
	for _, w := range apacheWrappers {
		if w == "httpd" {
			sawHTTPD = true
		}
	}
	if !sawHTTPD {
		t.Fatal("httpd must be in the resolution order: on a non-Debian host it is the only option")
	}
	if apacheWrappers[len(apacheWrappers)-1] != "httpd" {
		t.Errorf("httpd should be the last resort, after the wrappers that source envvars, got %v", apacheWrappers)
	}
}

func TestTheDumpParserIgnoresWarningNoise(t *testing.T) {
	// Measured: `httpd -S` on that host wrote 440 bytes of dump to STDOUT and 236 bytes of AH00557 /
	// AH00558 warnings to STDERR. apacheDumpRoots reads stdout and drops stderr, so the warnings never
	// reach the parser — but a future change routing them together must not break it, so the parser is
	// checked against the combined form too.
	combined := []byte("AH00557: httpd: apr_sockaddr_info_get() failed for host\n" +
		"AH00558: httpd: Could not reliably determine the server's fully qualified domain name\n" +
		string(fixture(t, "httpd-S-alpine.txt")))
	main, files := parseApacheDump(combined)
	if main != "/var/www/localhost/htdocs" {
		t.Errorf("warnings must not disturb the parse, got %q", main)
	}
	if len(files) == 0 {
		t.Error("vhost files must still be found alongside warning lines")
	}
}

// --- FR-039: the exec trade ---------------------------------------------------------------------

func TestExecBasedDiscoveryIsIndividuallyRefusable(t *testing.T) {
	// This executes a binary on the host, and on a compromised host that binary is attacker-
	// reachable. Refusing the exec must not disable config parsing, which is the primary method and
	// touches nothing but file contents.
	stubExec(t, fixture(t, "nginx-T-ubuntu.txt"), nil, "nginx", "apache2ctl")
	opts := Options{Refuse: map[Mechanism]bool{MechNginxDump: true, MechApacheDump: true}}

	for _, mech := range []func(Options) ([]Root, []Outcome){nginxDumpRoots, apacheDumpRoots} {
		roots, outcomes := mech(opts)
		if len(roots) != 0 {
			t.Fatalf("a refused mechanism must read nothing, got %+v", roots)
		}
		if len(outcomes) != 1 || outcomes[0].Status != StatusRefused {
			t.Fatalf("a refused mechanism must say so, got %+v", outcomes)
		}
	}
	// ...and the config-file mechanisms are untouched by that refusal.
	_, nginxOut := nginxConfigRoots(opts)
	if nginxOut[0].Status == StatusRefused {
		t.Fatal("refusing the exec must not refuse config parsing")
	}
}

func TestADumpIsBoundedByATimeout(t *testing.T) {
	// A server binary that never returns -- or one an intruder replaced with something that does not
	// -- must not take the scan with it. Asserted on the value rather than by hanging a test.
	if dumpTimeout <= 0 {
		t.Fatal("a config dump must be bounded")
	}
	if dumpTimeout > 30*1e9 {
		t.Fatalf("a %v bound is long enough to look like a hang during an IR", dumpTimeout)
	}
}
