package discover

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Discovery reads attacker-writable input. Every source it consults -- a config file, a process
// command line, server.xml -- is writable by someone on a compromised host, so a derived path is a
// proposal, not a fact. These tests pin the three properties the prior-art review
// (the webroot-discovery prior-art review (held privately)) found no
// OSS implementation supplies: provenance on every root, validation before use, and no directory
// scanned twice.

func mustDir(t *testing.T, path string) string {
	t.Helper()
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

// --- T073: validation before scanning (FR-037) --------------------------------------------------

func TestAProposedRootThatDoesNotExistIsRejected(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "gone")
	res := assemble([]Root{{Path: missing, Mechanism: MechNginxConfig, Source: "/etc/nginx/nginx.conf"}}, nil)
	if len(res.Roots) != 0 {
		t.Fatalf("a nonexistent path must not reach the scanner, got %v", res.Roots)
	}
	if len(res.Rejected) != 1 || !strings.Contains(res.Rejected[0].Reason, "exist") {
		t.Fatalf("the rejection must be recorded with a reason, got %+v", res.Rejected)
	}
	// Recorded, not silently dropped: an operator who configured a root that is gone needs to be
	// told, and a config naming a path that vanished is itself worth seeing during an IR.
	if res.Rejected[0].Mechanism != MechNginxConfig || res.Rejected[0].Source == "" {
		t.Fatalf("a rejection must keep its provenance, got %+v", res.Rejected[0])
	}
}

func TestAProposedRootThatIsAFileIsRejected(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "index.php")
	if err := os.WriteFile(file, []byte("<?php\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	res := assemble([]Root{{Path: file, Mechanism: MechApacheConfig, Source: "/etc/apache2/apache2.conf"}}, nil)
	if len(res.Roots) != 0 {
		t.Fatalf("a file is not a webroot, got %v", res.Roots)
	}
	if len(res.Rejected) != 1 || !strings.Contains(res.Rejected[0].Reason, "directory") {
		t.Fatalf("want a not-a-directory rejection, got %+v", res.Rejected)
	}
}

func TestAProposedRootThatWouldSweepTheWholeFilesystemIsRejected(t *testing.T) {
	// The concrete attack: on a compromised host the config is writable, and `root /;` turns a
	// webroot sweep into a full-disk scan -- hours of I/O, a flood of false positives, and a
	// responder's time. FR-037 says discovery must not widen the scan; this is what widening looks
	// like in practice.
	root := "/"
	if runtime.GOOS == "windows" {
		root = filepath.VolumeName(os.Getenv("SystemDrive")) + `\`
		if root == `\` {
			root = `C:\`
		}
	}
	res := assemble([]Root{{Path: root, Mechanism: MechNginxConfig, Source: "/etc/nginx/nginx.conf"}}, nil)
	if len(res.Roots) != 0 {
		t.Fatalf("the filesystem root must never be scanned as a webroot, got %v", res.Roots)
	}
	if len(res.Rejected) != 1 || !strings.Contains(res.Rejected[0].Reason, "containment") {
		t.Fatalf("want a containment rejection, got %+v", res.Rejected)
	}
}

func TestAnOperatorMayNameABroadPathThatDiscoveryMayNotChoose(t *testing.T) {
	// Containment narrows discovery, not the operator. The threat FR-037 addresses is a path derived
	// from attacker-writable input -- a config file, a process command line -- and an explicit --path
	// is reachable by nobody on the host. Refusing it would override a deliberate decision (a mounted
	// image, an unusual layout) and, worse, would surface at the gate as "none of the 1 requested
	// webroot(s) exist", which is not what happened.
	root := "/"
	if runtime.GOOS == "windows" {
		root = os.Getenv("SystemDrive") + `\`
		if root == `\` {
			root = `C:\`
		}
	}
	discovered := assemble([]Root{{Path: root, Mechanism: MechNginxConfig, Source: "/etc/nginx/nginx.conf"}}, nil)
	if len(discovered.Roots) != 0 {
		t.Fatalf("discovery must not choose the filesystem root, got %v", discovered.Roots)
	}
	explicit := assemble([]Root{{Path: root, Mechanism: MechExplicit}}, nil)
	if len(explicit.Roots) != 1 {
		t.Fatalf("an explicit path is the operator's call, got roots=%v rejected=%+v",
			explicit.Roots, explicit.Rejected)
	}
}

func TestASymlinkedRootIsJudgedByWhereItPoints(t *testing.T) {
	// A symlink is the same attack wearing a different hat: /var/www/html -> / passes every
	// stat-based check and then sweeps the disk. Containment is decided after resolution.
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs privilege on Windows; the Linux release is the one FR-037 is about")
	}
	link := filepath.Join(t.TempDir(), "html")
	if err := os.Symlink("/", link); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}
	res := assemble([]Root{{Path: link, Mechanism: MechConvention}}, nil)
	if len(res.Roots) != 0 {
		t.Fatalf("a symlink to / must be rejected, got %v", res.Roots)
	}
	if len(res.Rejected) != 1 || !strings.Contains(res.Rejected[0].Reason, "containment") {
		t.Fatalf("want a containment rejection, got %+v", res.Rejected)
	}
}

func TestAnOrdinaryDirectoryIsAccepted(t *testing.T) {
	// The control. Validation that rejects everything would be indistinguishable from broken
	// discovery, and would reintroduce the silent clean T075 just fixed.
	dir := mustDir(t, filepath.Join(t.TempDir(), "var", "www", "html"))
	res := assemble([]Root{{Path: dir, Mechanism: MechApacheConfig, Source: "/etc/apache2/apache2.conf"}}, nil)
	if len(res.Roots) != 1 || res.Roots[0].Path != filepath.Clean(dir) {
		t.Fatalf("a real webroot must be accepted, got %v rejected=%v", res.Roots, res.Rejected)
	}
	if len(res.Rejected) != 0 {
		t.Fatalf("nothing to reject here, got %+v", res.Rejected)
	}
}

// --- what a report must not shout about ---------------------------------------------------------

func TestAGuessThatMissesIsNotReportedAsARefusal(t *testing.T) {
	// Found by reading an actual report, not by a test: every conventional location absent from the
	// host came out as "REFUSED ... the directory does not exist", so a stock Windows box produced
	// five alarming lines for the entirely normal case. That is how a report teaches its reader to
	// skip the section it most needs read.
	missing := filepath.Join(t.TempDir(), "var", "www", "html")
	res := assemble([]Root{{Path: missing, Mechanism: MechConvention}}, nil)
	if len(res.Roots) != 0 {
		t.Fatalf("an absent directory is not a root, got %v", res.Roots)
	}
	if len(res.Rejected) != 0 {
		t.Fatalf("a guess that misses says nothing about the host, got %+v", res.Rejected)
	}
}

func TestAConfiguredPathThatVanishedIsStillReported(t *testing.T) {
	// The control on the rule above. Something real named this directory, so its absence IS a fact
	// about the host and worth seeing during an incident.
	missing := filepath.Join(t.TempDir(), "srv", "site")
	res := assemble([]Root{
		{Path: missing, Mechanism: MechNginxConfig, Source: "/etc/nginx/nginx.conf"},
	}, nil)
	if len(res.Rejected) != 1 || res.Rejected[0].Source == "" {
		t.Fatalf("a config-named path that vanished must be reported with its source, got %+v", res.Rejected)
	}
}

func TestAGuessThatExistsAndIsDangerousIsStillReported(t *testing.T) {
	// Only ABSENCE is dropped. A conventional location that exists and fails containment is a fact
	// about this host whoever proposed the path -- /var/www/html symlinked to / is the attack
	// FR-037 is about, and it would arrive by convention.
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs privilege on Windows")
	}
	link := filepath.Join(t.TempDir(), "html")
	if err := os.Symlink("/", link); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}
	res := assemble([]Root{{Path: link, Mechanism: MechConvention}}, nil)
	if len(res.Rejected) != 1 || !strings.Contains(res.Rejected[0].Reason, "containment") {
		t.Fatalf("a dangerous guess must still be reported, got %+v", res.Rejected)
	}
}

func TestACandidateFromAnotherPlatformIsNotFabricatedIntoAPath(t *testing.T) {
	// filepath.Abs("/var/www") on Windows yields C:\var\www -- a path that never existed on any
	// host, reported to the operator as though the scanner had looked for it there. The candidate
	// lists span platforms on purpose, so a candidate that is not absolute HERE is simply not
	// applicable.
	//
	// The inverse holds on Linux for the Windows entries in the same lists.
	foreign := `C:\inetpub\wwwroot`
	if runtime.GOOS == "windows" {
		foreign = "/var/www/html-that-should-not-become-a-drive-path"
	}
	if filepath.IsAbs(foreign) {
		t.Skipf("%q is absolute on %s, so there is nothing to fabricate", foreign, runtime.GOOS)
	}
	res := assemble([]Root{{Path: foreign, Mechanism: MechConvention}}, nil)
	if len(res.Roots) != 0 || len(res.Rejected) != 0 {
		t.Fatalf("a foreign-platform candidate must vanish quietly, got roots=%v rejected=%+v",
			res.Roots, res.Rejected)
	}
	// ...but if a real source named it, the operator hears about it rather than nothing.
	named := assemble([]Root{
		{Path: foreign, Mechanism: MechApacheConfig, Source: "/etc/apache2/apache2.conf"},
	}, nil)
	if len(named.Rejected) != 1 || !strings.Contains(named.Rejected[0].Reason, "absolute") {
		t.Fatalf("a config-named unresolvable path must be reported, got %+v", named.Rejected)
	}
}

// --- T074: provenance on every root (FR-036) ----------------------------------------------------

func TestEveryAcceptedRootCarriesTheMechanismThatFoundIt(t *testing.T) {
	base := t.TempDir()
	a := mustDir(t, filepath.Join(base, "a"))
	b := mustDir(t, filepath.Join(base, "b"))
	res := assemble([]Root{
		{Path: a, Mechanism: MechNginxConfig, Source: "/etc/nginx/sites-enabled/default"},
		{Path: b, Mechanism: MechConvention},
	}, nil)
	if len(res.Roots) != 2 {
		t.Fatalf("want 2 roots, got %v", res.Roots)
	}
	for _, r := range res.Roots {
		if r.Mechanism == "" {
			t.Fatalf("a root reached the scanner with no mechanism: %+v", r)
		}
	}
	// The distinction FR-036 exists for: a directory read from live configuration is not the same
	// evidence as one guessed from a distro default, and a responder must be able to tell.
	if res.Roots[0].Source == "" {
		t.Fatalf("a config-derived root must name the file it came from: %+v", res.Roots[0])
	}
	if res.Roots[1].Source != "" {
		t.Fatalf("a conventional root has no source file to name: %+v", res.Roots[1])
	}
}

func TestAMechanismReportsWhetherItRanAndWhatItFound(t *testing.T) {
	dir := mustDir(t, filepath.Join(t.TempDir(), "www"))
	res := assemble(
		[]Root{{Path: dir, Mechanism: MechApacheConfig, Source: "/etc/apache2/apache2.conf"}},
		[]Outcome{
			{Mechanism: MechApacheConfig, Status: StatusSucceeded, Roots: 1},
			{Mechanism: MechNginxConfig, Status: StatusUnavailable, Detail: "no nginx config found"},
			{Mechanism: MechTomcatEnv, Status: StatusAttempted, Detail: "CATALINA_BASE set, webapps absent"},
			{Mechanism: MechConvention, Status: StatusAttempted},
		},
	)
	if len(res.Outcomes) != 4 {
		t.Fatalf("every mechanism must report, got %+v", res.Outcomes)
	}
	// "Discovery must degrade, not fail" (prior-art review, property 1): an unavailable mechanism is
	// a fact about the host, not an error, and it has to be distinguishable from one that ran and
	// found nothing -- otherwise a responder cannot tell "no nginx here" from "nginx here, no roots
	// configured", and those mean different things during an IR.
	byMech := map[Mechanism]Outcome{}
	for _, o := range res.Outcomes {
		byMech[o.Mechanism] = o
	}
	if byMech[MechNginxConfig].Status != StatusUnavailable {
		t.Fatalf("absent config must be unavailable, got %+v", byMech[MechNginxConfig])
	}
	if byMech[MechTomcatEnv].Status != StatusAttempted {
		t.Fatalf("ran-but-empty must be attempted, got %+v", byMech[MechTomcatEnv])
	}
	if byMech[MechNginxConfig].Detail == "" || byMech[MechTomcatEnv].Detail == "" {
		t.Fatal("a mechanism that produced nothing must say why")
	}
}

func TestARejectedRootIsNotCountedAsFound(t *testing.T) {
	// Otherwise the outcome would claim a root the scanner never sees, and the report would
	// disagree with itself.
	missing := filepath.Join(t.TempDir(), "gone")
	res := assemble(
		[]Root{{Path: missing, Mechanism: MechNginxConfig, Source: "/etc/nginx/nginx.conf"}},
		[]Outcome{{Mechanism: MechNginxConfig, Status: StatusSucceeded, Roots: 1}},
	)
	for _, o := range res.Outcomes {
		if o.Mechanism == MechNginxConfig {
			if o.Roots != 0 {
				t.Fatalf("a rejected root must not be counted, got %+v", o)
			}
			if o.Status == StatusSucceeded {
				t.Fatalf("a mechanism whose every root was rejected did not succeed, got %+v", o)
			}
		}
	}
}

// --- T077: no directory scanned or counted twice ------------------------------------------------

func TestTheSameRootFoundTwiceIsScannedOnce(t *testing.T) {
	dir := mustDir(t, filepath.Join(t.TempDir(), "www"))
	res := assemble([]Root{
		{Path: dir, Mechanism: MechNginxConfig, Source: "/etc/nginx/nginx.conf"},
		{Path: dir, Mechanism: MechConvention},
	}, nil)
	if len(res.Roots) != 1 {
		t.Fatalf("one directory, one root, got %v", res.Roots)
	}
	// The stronger claim wins: config-derived beats guessed, because that is the provenance a
	// responder should see for a directory both mechanisms proposed.
	if res.Roots[0].Mechanism != MechNginxConfig {
		t.Fatalf("the more specific mechanism must be kept, got %+v", res.Roots[0])
	}
	if len(res.Roots[0].AlsoFoundBy) != 1 || res.Roots[0].AlsoFoundBy[0] != MechConvention {
		t.Fatalf("agreement between mechanisms must not be thrown away, got %+v", res.Roots[0])
	}
}

func TestANestedRootIsSubsumedByItsParent(t *testing.T) {
	// /var/www and /var/www/html are both discoverable on a stock Debian box: the first by
	// convention, the second by convention AND usually by config. Scanning both walks every file
	// under html twice, doubles targets_scanned, and doubles the work on the largest tree.
	base := t.TempDir()
	parent := mustDir(t, filepath.Join(base, "var", "www"))
	child := mustDir(t, filepath.Join(parent, "html"))
	res := assemble([]Root{
		{Path: child, Mechanism: MechNginxConfig, Source: "/etc/nginx/nginx.conf"},
		{Path: parent, Mechanism: MechConvention},
	}, nil)
	if len(res.Roots) != 1 {
		t.Fatalf("a nested root must be subsumed, got %v", res.Roots)
	}
	if res.Roots[0].Path != filepath.Clean(parent) {
		t.Fatalf("the enclosing directory covers both, got %q", res.Roots[0].Path)
	}
	if len(res.Roots[0].Subsumes) != 1 || res.Roots[0].Subsumes[0] != filepath.Clean(child) {
		t.Fatalf("what was subsumed must stay visible, got %+v", res.Roots[0])
	}
}

func TestASiblingRootIsNotSubsumed(t *testing.T) {
	// The control on the prefix test: /var/www-old is not inside /var/www, and a string prefix
	// comparison would wrongly swallow it.
	base := t.TempDir()
	a := mustDir(t, filepath.Join(base, "www"))
	b := mustDir(t, filepath.Join(base, "www-old"))
	res := assemble([]Root{
		{Path: a, Mechanism: MechConvention},
		{Path: b, Mechanism: MechConvention},
	}, nil)
	if len(res.Roots) != 2 {
		t.Fatalf("siblings are separate roots, got %v", res.Roots)
	}
}

// --- T076: suppressing discovery (FR-039) -------------------------------------------------------

func TestDisablingDiscoveryFindsNothingAndSaysWhy(t *testing.T) {
	res := Discover(nil, Options{Disabled: true})
	if len(res.Roots) != 0 {
		t.Fatalf("disabled discovery must find nothing, got %v", res.Roots)
	}
	// "We were told not to look" must be visible in coverage and impossible to mistake for "we
	// looked and found nothing" -- those lead a responder to opposite conclusions.
	if len(res.Outcomes) != 1 || res.Outcomes[0].Mechanism != MechDiscovery ||
		res.Outcomes[0].Status != StatusRefused || res.Outcomes[0].Detail == "" {
		t.Fatalf("disabling discovery must account for itself, got %+v", res.Outcomes)
	}
}

func TestAnExplicitPathIsScannedEvenWithDiscoveryDisabled(t *testing.T) {
	// Both are ways of suppressing DISCOVERY, so asking for both is coherent: scan exactly this and
	// look for nothing else. Refusing here would make --discover=false useless with --path, which is
	// the combination a careful responder on a compromised host would actually choose.
	dir := mustDir(t, filepath.Join(t.TempDir(), "site"))
	res := Discover([]string{dir}, Options{Disabled: true})
	if len(res.Roots) != 1 || res.Roots[0].Path != filepath.Clean(dir) {
		t.Fatalf("an explicit root must still be scanned, got %v", res.Roots)
	}
	if res.Roots[0].Mechanism != MechExplicit {
		t.Fatalf("attributed to the operator, got %+v", res.Roots[0])
	}
}

func TestRefusingOneMechanismLeavesTheOthersWorking(t *testing.T) {
	// The shape T086 builds on: exec-based discovery must be refusable INDIVIDUALLY, because it runs
	// a host binary an intruder may have replaced, while config parsing stays available.
	res := Discover(nil, Options{Refuse: map[Mechanism]bool{MechConvention: true}})
	var sawRefusal bool
	for _, o := range res.Outcomes {
		if o.Mechanism == MechConvention {
			if o.Status != StatusRefused {
				t.Fatalf("a refused mechanism must say so, got %+v", o)
			}
			sawRefusal = true
		}
		if o.Mechanism != MechConvention && o.Status == StatusRefused {
			t.Errorf("refusing one mechanism must not refuse another, got %+v", o)
		}
	}
	if !sawRefusal {
		t.Fatalf("the refused mechanism must still appear in the outcomes, got %+v", res.Outcomes)
	}
	for _, r := range res.Roots {
		if r.Mechanism == MechConvention {
			t.Errorf("a refused mechanism must contribute no roots, got %+v", r)
		}
	}
}

// --- the real host: smoke, not assertion --------------------------------------------------------

func TestDiscoverOnThisHostReturnsWellFormedProvenance(t *testing.T) {
	// What this host has is not the test's business -- the build box has inetpub, WSL has nothing.
	// What must hold everywhere: every root is absolute, validated, and attributed, and every
	// mechanism accounts for itself.
	res := Discover(nil, Options{})
	for _, r := range res.Roots {
		if !filepath.IsAbs(r.Path) {
			t.Errorf("root %q is not absolute", r.Path)
		}
		if r.Mechanism == "" {
			t.Errorf("root %q has no mechanism", r.Path)
		}
		if fi, err := os.Stat(r.Path); err != nil || !fi.IsDir() {
			t.Errorf("root %q did not survive validation but was returned", r.Path)
		}
	}
	if len(res.Outcomes) == 0 {
		t.Fatal("discovery must account for the mechanisms it consulted, even on a bare host")
	}
	// Logged rather than asserted: what this host has is not the test's business, but seeing what
	// each mechanism did is how a strange host gets diagnosed, and -v is where you look.
	for _, r := range res.Roots {
		t.Logf("root %s via %s source=%s also=%v subsumes=%v", r.Path, r.Mechanism, r.Source, r.AlsoFoundBy, r.Subsumes)
	}
	for _, o := range res.Outcomes {
		t.Logf("mechanism %-18s %-12s roots=%d %s", o.Mechanism, o.Status, o.Roots, o.Detail)
	}
	for _, rj := range res.Rejected {
		t.Logf("refused %s (%s) %s", rj.Path, rj.Mechanism, rj.Reason)
	}
	for _, o := range res.Outcomes {
		if o.Status == "" {
			t.Errorf("mechanism %q reported no status", o.Mechanism)
		}
	}
}

func TestExplicitRootsSuppressDiscoveryEntirely(t *testing.T) {
	// FR-039, first half. Also the property that keeps every measurement run honest: the parity and
	// coverage harnesses pass one population directory and must scan exactly that.
	if len(Discover(nil, Options{}).Roots) == 0 {
		t.Skip("this host discovers nothing, so there is nothing to suppress")
	}
	dir := mustDir(t, filepath.Join(t.TempDir(), "site"))
	res := Discover([]string{dir}, Options{})
	if len(res.Roots) != 1 || res.Roots[0].Path != filepath.Clean(dir) {
		t.Fatalf("an explicit root must be the only root, got %v", res.Roots)
	}
	if res.Roots[0].Mechanism != MechExplicit {
		t.Fatalf("an operator-supplied root is attributed to the operator, got %+v", res.Roots[0])
	}
}

func TestWebrootsStillReturnsBarePathsForExistingCallers(t *testing.T) {
	dir := mustDir(t, filepath.Join(t.TempDir(), "site"))
	got := Webroots([]string{dir, filepath.Join(t.TempDir(), "absent")})
	if len(got) != 1 || got[0] != filepath.Clean(dir) {
		t.Fatalf("Webroots must keep filtering to existing directories, got %v", got)
	}
}
