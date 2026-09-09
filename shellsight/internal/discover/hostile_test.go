package discover

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Discovery reads attacker-writable input. Containment (T073) covers WHERE a proposal points; this
// covers HOW MUCH of it reaches the report, because the volume is attacker-chosen too.
//
// Measured before anything was built, since "obvious" hardening is usually inert. It was not inert:
//
//	50,000 root directives -> 50,000 rejections, each rendered one per line in the report
//	one 1 MiB path         -> 1,048,577 bytes carried verbatim into the report and report.json
//
// So an intruder who can edit a config buries every real finding under refusal noise, for the price of
// editing a file. What is bounded is the REPORT; the work is not, because capping how many proposals
// get evaluated would fail toward missing a real webroot — the one direction this must never fail in,
// and 50,000 proposals validate in 775ms anyway.

func writeConf(t *testing.T, body string) {
	t.Helper()
	dir := t.TempDir()
	conf := filepath.Join(dir, "nginx.conf")
	if err := os.WriteFile(conf, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	prior := nginxConfigPaths
	nginxConfigPaths = func() []string { return []string{conf} }
	t.Cleanup(func() { nginxConfigPaths = prior })
}

// onlyNginxConfig isolates these tests to the ONE mechanism they are about.
//
// It refused only the two dump mechanisms before, which left eleven others reading the real host --
// so `RejectedTotal` counted the fixture's rejections PLUS whatever the machine contributed, and the
// exact-equality assertions below passed only on a host with no web server configured. Measured on a
// Windows workstation with IIS present: three stale `physicalPath` entries in
// applicationHost.config named directories that no longer exist, so both tests failed by exactly 3.
//
// That is the wrong direction for a suite to fail in. A host with IIS sites is not an exotic
// environment -- it is the environment this product is FOR -- and a test that reds on it teaches
// whoever brings up a new box to distrust the suite. Refusing everything but the mechanism under
// test keeps all three bounds asserted and removes the host from the measurement.
func onlyNginxConfig() Options {
	refuse := map[Mechanism]bool{}
	for _, m := range []Mechanism{
		MechIISConfig, MechIISDefault,
		MechApacheConfig, MechApacheDump,
		MechNginxDump,
		MechTomcatEnv, MechTomcatProcess, MechTomcatServerXML,
		MechAppserverProcess, MechConvention,
	} {
		refuse[m] = true
	}
	return Options{Refuse: refuse}
}

func TestAFloodOfRefusedPathsIsBoundedInTheReport(t *testing.T) {
	const n = 50000
	var b strings.Builder
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "  root /nonexistent/path-%d;\n", i)
	}
	writeConf(t, "http {\n"+b.String()+"}\n")

	start := time.Now()
	res := Discover(nil, onlyNginxConfig())
	elapsed := time.Since(start)
	t.Logf("%d directives -> %d retained, %d total, in %v", n, len(res.Rejected), res.RejectedTotal, elapsed)

	if len(res.Rejected) > maxReportedRejections {
		t.Fatalf("the report list must be bounded, got %d entries", len(res.Rejected))
	}
	// The bound has to be VISIBLE, or a truncated list reads as a complete one — the same failure as
	// a silent cap anywhere else in this project.
	if res.RejectedTotal != n {
		t.Fatalf("the true count must survive the bound: got %d, want %d", res.RejectedTotal, n)
	}
}

func TestAnAttackerChosenPathLengthIsNotTheReportsLength(t *testing.T) {
	huge := "/" + strings.Repeat("a", 1<<20)
	writeConf(t, "http {\n  root "+huge+";\n}\n")

	res := Discover(nil, onlyNginxConfig())
	if res.RejectedTotal != 1 {
		t.Fatalf("want the one rejection counted, got %d", res.RejectedTotal)
	}
	if len(res.Rejected) != 1 {
		t.Fatalf("want it retained, got %d", len(res.Rejected))
	}
	got := res.Rejected[0].Path
	if len(got) > maxReportedPathLen+64 {
		t.Fatalf("a %d-byte path reached the report", len(got))
	}
	// Truncation must announce itself and state the original size, so a reader is not left comparing
	// a silently-shortened path against what is on disk.
	if !strings.Contains(got, "bytes total") {
		t.Fatalf("truncation must say so and give the original length, got %q", got[:80])
	}
	t.Logf("1 MiB path reported as %d bytes", len(got))
}

func TestABoundedListStillReportsTheRealCases(t *testing.T) {
	// The control. A bound that dropped everything would hide the refusals that matter — a config
	// naming the filesystem root, or one naming a directory that vanished — which are leads during an
	// incident rather than noise.
	//
	// The root is spelled per-platform: `/` is NOT absolute on Windows, so writing it there produces a
	// not-absolute refusal instead of a containment one. Correct behaviour, and the first version of
	// this test asserted against it.
	root, absent := "/", "/nonexistent-xyz"
	if runtime.GOOS == "windows" {
		root, absent = `C:\`, `C:\nonexistent-xyz`
	}
	writeConf(t, "http {\n  root "+root+";\n  root "+absent+";\n}\n")
	res := Discover(nil, onlyNginxConfig())
	if res.RejectedTotal < 2 {
		t.Fatalf("both refusals must be counted, got %d (%+v)", res.RejectedTotal, res.Rejected)
	}
	var sawContainment bool
	for _, r := range res.Rejected {
		if strings.Contains(r.Reason, "containment") {
			sawContainment = true
		}
	}
	if !sawContainment {
		t.Fatalf("the containment refusal must be retained, got %+v", res.Rejected)
	}
}

func TestAnOrdinaryHostReportsNoBoundAtAll(t *testing.T) {
	// RejectedTotal is omitempty and equals len(Rejected) in the normal case, so a normal report gains
	// no extra line. A hardening change that added noise to every clean scan would not be worth it.
	writeConf(t, "http {\n  root /nonexistent-abc;\n}\n")
	res := Discover(nil, onlyNginxConfig())
	if res.RejectedTotal != len(res.Rejected) {
		t.Fatalf("no bound should be in play here: total=%d retained=%d", res.RejectedTotal, len(res.Rejected))
	}
}
