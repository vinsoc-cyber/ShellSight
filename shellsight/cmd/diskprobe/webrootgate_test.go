package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"shellsight/internal/discover"
	"shellsight/internal/finding"
)

// FR-038: scanning nothing is not evidence of absence.
//
// The probe carried two coverage guards -- an explicitly-requested root that does not exist, and
// every resolved root failing to scan -- and none for the case between them: no path supplied AND
// discovery finding nothing. main.go guarded `len(spec.Webroots) > 0 && len(roots) == 0` and
// `len(roots) > 0 && scannedOK == 0`, so the both-zero host fell straight through to
// `Status: CovRan, TargetsScanned: 0` and exited 0 -- a clean verdict for a scan that never
// happened, on precisely the unfamiliar host discovery exists to serve.
//
// Every arm is pinned here, because an over-broad gate is the opposite failure: it would make a
// legitimately-scannable host inconclusive, which is what US4 exists to prevent.

// stubDiscovery replaces discovery for the duration of one test.
//
// The seam is load-bearing, not convenience: a host with no discoverable webroot cannot be arranged
// in a test on any real machine -- this one has C:\inetpub\wwwroot -- and being untestable in
// practice is exactly how the silent clean survived to be found by reading the source.
func stubDiscovery(t *testing.T, res discover.Result) {
	t.Helper()
	prior := resolveDiscovery
	resolveDiscovery = func([]string, discover.Options) discover.Result { return res }
	t.Cleanup(func() { resolveDiscovery = prior })
}

// found builds a discovery result naming these directories, as a config read would.
func found(paths ...string) discover.Result {
	res := discover.Result{Outcomes: []discover.Outcome{
		{Mechanism: discover.MechNginxConfig, Status: discover.StatusSucceeded, Roots: len(paths)},
	}}
	for _, p := range paths {
		res.Roots = append(res.Roots, discover.Root{
			Path: p, Mechanism: discover.MechNginxConfig, Source: "/etc/nginx/nginx.conf",
		})
	}
	return res
}

func TestAHostWithNoDiscoverableWebrootIsNotReportedClean(t *testing.T) {
	stubDiscovery(t, discover.Result{Outcomes: []discover.Outcome{
		{Mechanism: discover.MechNginxConfig, Status: discover.StatusUnavailable,
			Detail: "no Nginx configuration in the standard locations"},
	}})
	var stdout, stderr bytes.Buffer
	code := runDiskProbe(context.Background(),
		[]string{"--rules", rulesDir(), "--deobf=false"},
		strings.NewReader("{}"), &stdout, &stderr)
	if code != exitCoverage {
		t.Fatalf("a host where nothing was discovered must be a coverage failure, got exit %d; stdout=%q",
			code, stdout.String())
	}
	if !strings.Contains(stderr.String(), "no webroot") {
		t.Fatalf("the run must say so explicitly (FR-038), stderr=%q", stderr.String())
	}
}

func TestAnExplicitlyRequestedWebrootThatIsAbsentIsNotReportedClean(t *testing.T) {
	// The arm that already worked. Pinned so that generalising the gate cannot silently drop it, and
	// so the cases keep DISTINCT messages: "you named roots that are gone" and "this host told us
	// nothing" send a responder to different places.
	stubDiscovery(t, discover.Result{})
	missing := filepath.Join(t.TempDir(), "nonexistent-webroot")
	spec, err := json.Marshal(finding.TargetSpec{Host: "host", Webroots: []string{missing}})
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := runDiskProbe(context.Background(),
		[]string{"--rules", rulesDir(), "--deobf=false"},
		bytes.NewReader(spec), &stdout, &stderr)
	if code != exitCoverage {
		t.Fatalf("an absent requested webroot must be a coverage failure, got exit %d", code)
	}
	if !strings.Contains(stderr.String(), "requested") {
		t.Fatalf("the message must name the request, not discovery, stderr=%q", stderr.String())
	}
}

func TestEveryCandidateRejectedReadsAsRefusalNotAbsence(t *testing.T) {
	// Discovery DID find something and validation refused all of it. Reporting "nothing could be
	// discovered" would hide the more interesting fact: something on this host named a directory we
	// would not scan, and on a compromised host that is a lead rather than noise.
	stubDiscovery(t, discover.Result{
		Outcomes: []discover.Outcome{{Mechanism: discover.MechNginxConfig, Status: discover.StatusAttempted}},
		Rejected: []discover.Rejection{{
			Path: "/", Mechanism: discover.MechNginxConfig, Source: "/etc/nginx/nginx.conf",
			Reason: "rejected by containment: the filesystem root is not a webroot",
		}},
	})
	var stdout, stderr bytes.Buffer
	code := runDiskProbe(context.Background(),
		[]string{"--rules", rulesDir(), "--deobf=false"},
		strings.NewReader("{}"), &stdout, &stderr)
	if code != exitCoverage {
		t.Fatalf("no usable webroot must be a coverage failure, got exit %d", code)
	}
	msg := stderr.String()
	for _, want := range []string{"rejected", "containment", "1 discovered candidate"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("the message must explain what was refused and why, want %q in %q", want, msg)
		}
	}
}

func TestADiscoveredWebrootStillCompletesTheScan(t *testing.T) {
	// The control on gate breadth: when discovery DOES find a directory, the run must complete
	// normally. Without this, "no webroot discovered => failure" could be written as
	// "no webroot => failure" and every discovery-driven scan would report inconclusive.
	yr := yrPath()
	if yr == "" {
		t.Skip("yr binary not found")
	}
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "index.php"), []byte("<?php phpinfo(); ?>\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	stubDiscovery(t, found(root))
	var stdout, stderr bytes.Buffer
	code := runDiskProbe(context.Background(),
		[]string{"--yr", yr, "--rules", rulesDir(), "--deobf=false"},
		strings.NewReader("{}"), &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("a discovered webroot must be scanned, got exit %d; stderr=%q", code, stderr.String())
	}
	var out finding.ProbeOutput
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		t.Fatalf("probe output: %v", err)
	}
	if out.Coverage == nil || out.Coverage.TargetsScanned != 1 {
		t.Fatalf("the discovered root must be counted as scanned, coverage=%+v", out.Coverage)
	}

	// FR-036: the scan says how it found what it scanned. Without this the operator cannot tell a
	// directory read out of live configuration from one guessed off a distro default, and those are
	// not the same evidence.
	d := out.Coverage.Discovery
	if d == nil {
		t.Fatal("coverage must carry the discovery report")
	}
	if len(d.Roots) != 1 || d.Roots[0].Path != root {
		t.Fatalf("the report must name the root that was scanned, got %+v", d.Roots)
	}
	if d.Roots[0].Mechanism != string(discover.MechNginxConfig) || d.Roots[0].Source == "" {
		t.Fatalf("a config-derived root must name its mechanism and file, got %+v", d.Roots[0])
	}
	if len(d.Mechanisms) == 0 {
		t.Fatal("every mechanism consulted must account for itself")
	}
}

func TestAnExplicitTargetSetIsStillAttributed(t *testing.T) {
	// Always attached, including for an explicit scan: "the operator named this" must be an
	// assertion the report makes, not something inferred from a missing field. The same reason
	// ScanSkips is serialised when it is all zeroes.
	yr := yrPath()
	if yr == "" {
		t.Skip("yr binary not found")
	}
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "ok.php"), []byte("<?php echo 1; ?>\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	spec, err := json.Marshal(finding.TargetSpec{Host: "host", Webroots: []string{root}})
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := runDiskProbe(context.Background(),
		[]string{"--yr", yr, "--rules", rulesDir(), "--deobf=false"},
		bytes.NewReader(spec), &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("exit %d; stderr=%q", code, stderr.String())
	}
	var out finding.ProbeOutput
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Coverage == nil || out.Coverage.Discovery == nil {
		t.Fatal("an explicit scan must still report its provenance")
	}
	roots := out.Coverage.Discovery.Roots
	if len(roots) != 1 || roots[0].Mechanism != string(discover.MechExplicit) {
		t.Fatalf("an operator-supplied root is attributed to the operator, got %+v", roots)
	}
}

func TestDisablingDiscoveryWithNoPathIsAnErrorNotAnEmptyScan(t *testing.T) {
	// Real discovery, not the stub: --discover=false must reach discover.Options and produce the
	// refusal. Same failure as T075 by a different route -- a scan of nothing is not an all-clear --
	// so it must exit non-zero and say which of the two things went wrong.
	var stdout, stderr bytes.Buffer
	code := runDiskProbe(context.Background(),
		[]string{"--rules", rulesDir(), "--deobf=false", "--discover=false"},
		strings.NewReader("{}"), &stdout, &stderr)
	if code != exitCoverage {
		t.Fatalf("disabling discovery with no path must fail, got exit %d; stdout=%q", code, stdout.String())
	}
	msg := stderr.String()
	if !strings.Contains(msg, "disabled") {
		t.Fatalf("the message must say discovery was disabled, got %q", msg)
	}
	// It must NOT claim nothing could be discovered: nothing was looked for.
	if strings.Contains(msg, "could be discovered") {
		t.Fatalf("that message describes a different failure, got %q", msg)
	}
}

func TestDisablingDiscoveryStillScansAnExplicitPath(t *testing.T) {
	yr := yrPath()
	if yr == "" {
		t.Skip("yr binary not found")
	}
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "ok.php"), []byte("<?php echo 1; ?>\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	spec, err := json.Marshal(finding.TargetSpec{Host: "host", Webroots: []string{root}})
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := runDiskProbe(context.Background(),
		[]string{"--yr", yr, "--rules", rulesDir(), "--deobf=false", "--discover=false"},
		bytes.NewReader(spec), &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("an explicit path must still be scanned with discovery off, got exit %d; stderr=%q",
			code, stderr.String())
	}
}

// captureDiscovery records the Options the probe passed to discovery, which is the only way to see
// that a flag actually reached the layer that acts on it.
func captureDiscovery(t *testing.T, res discover.Result) *discover.Options {
	t.Helper()
	var seen discover.Options
	prior := resolveDiscovery
	resolveDiscovery = func(_ []string, opts discover.Options) discover.Result {
		seen = opts
		return res
	}
	t.Cleanup(func() { resolveDiscovery = prior })
	return &seen
}

func TestAMechanismRefusalReachesDiscovery(t *testing.T) {
	yr := yrPath()
	if yr == "" {
		t.Skip("yr binary not found")
	}
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "ok.php"), []byte("<?php echo 1; ?>\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	opts := captureDiscovery(t, found(root))
	var stdout, stderr bytes.Buffer
	code := runDiskProbe(context.Background(),
		[]string{"--yr", yr, "--rules", rulesDir(), "--deobf=false", "--discovery-refuse", "exec"},
		strings.NewReader("{}"), &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("exit %d; stderr=%q", code, stderr.String())
	}
	for _, m := range discover.ExecMechanisms() {
		if !opts.Refuse[m] {
			t.Errorf("the refusal must reach discovery for %q, got %+v", m, opts.Refuse)
		}
	}
	// Refusing an exec must not disable discovery altogether: config parsing is the primary method
	// and is unaffected by a binary someone may have replaced.
	if opts.Disabled {
		t.Error("refusing a mechanism must not disable discovery")
	}
}

func TestAnUnknownRefusedMechanismWarnsAndDoesNotRefuse(t *testing.T) {
	// An operator who believes they blocked an exec on an incident host, and did not, has been told
	// something false. Silence here is the worst outcome of the three.
	opts := captureDiscovery(t, found(t.TempDir()))
	var stdout, stderr bytes.Buffer
	runDiskProbe(context.Background(),
		[]string{"--rules", rulesDir(), "--deobf=false", "--discovery-refuse", "nginx-dmup"},
		strings.NewReader("{}"), &stdout, &stderr)
	if !strings.Contains(stderr.String(), "nginx-dmup") {
		t.Fatalf("the typo must be reported, stderr=%q", stderr.String())
	}
	if len(opts.Refuse) != 0 {
		t.Fatalf("an unknown name must refuse nothing, got %+v", opts.Refuse)
	}
}

func TestTheWebrootGateDistinguishesEveryWayThereIsNothingToScan(t *testing.T) {
	rejected := discover.Result{Rejected: []discover.Rejection{
		{Path: "/", Mechanism: discover.MechNginxConfig, Reason: "rejected by containment: x"},
	}}
	for _, tc := range []struct {
		name       string
		requested  int
		res        discover.Result
		wantFail   bool
		wantSubstr string
	}{
		{"discovery found something", 0, found("/a", "/b"), false, ""},
		{"requested roots resolved", 3, found("/a", "/b", "/c"), false, ""},
		{"some requested roots resolved", 3, found("/a"), false, ""},
		{"discovery found nothing", 0, discover.Result{}, true, "no webroot could be discovered"},
		{"every requested root absent", 3, discover.Result{}, true, "requested"},
		{"every candidate refused", 0, rejected, true, "rejected"},
		{"discovery switched off", 0, discover.Result{Outcomes: []discover.Outcome{
			{Mechanism: discover.MechDiscovery, Status: discover.StatusRefused},
		}}, true, "disabled"},
		// A rejection alongside a usable root is not a failure: the usable root gets scanned and the
		// refusal is reported in coverage, not at the gate.
		{"one refused, one usable", 0, discover.Result{
			Roots:    found("/a").Roots,
			Rejected: rejected.Rejected,
		}, false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			msg := webrootGate(tc.requested, tc.res)
			if (msg != "") != tc.wantFail {
				t.Fatalf("requested=%d roots=%d rejected=%d: got %q, wantFail=%v",
					tc.requested, len(tc.res.Roots), len(tc.res.Rejected), msg, tc.wantFail)
			}
			if tc.wantSubstr != "" && !strings.Contains(msg, tc.wantSubstr) {
				t.Fatalf("message %q must contain %q", msg, tc.wantSubstr)
			}
		})
	}
}
