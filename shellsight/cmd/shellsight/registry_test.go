package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"shellsight/internal/finding"
	"shellsight/internal/orchestrator"
	"shellsight/internal/output"
)

// These tests assert the capability set for a platform the test is NOT running on. That is the
// whole point of making registryFor pure (FR-030): the Linux capability set has to be reviewable
// from the Windows development box, because the alternative -- discovering on the target host that
// a capability silently vanished -- is what an IR responder cannot afford.

func viewsOf(specs []probeSpec) []string {
	out := make([]string, 0, len(specs))
	for _, s := range specs {
		out = append(out, s.View)
	}
	sort.Strings(out)
	return out
}

func TestRegistryForLinuxIsDiskAndJavaMem(t *testing.T) {
	got := viewsOf(registryFor("linux"))
	want := []string{"disk", "java-mem"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("linux capability set = %v, want %v\n"+
			"java-mem runs natively via cmd/jvmprobe; the remaining views need a Windows-only runtime.",
			got, want)
	}
}

// The point of the native path: no JRE anywhere. If this regresses to a `java -jar` invocation the
// binary stops being self-contained, which is the whole reason the Linux path exists.
func TestLinuxJavaMemLaunchesNativeProbeNotAJVM(t *testing.T) {
	dir := t.TempDir()
	// java-mem is an OPTIONAL companion: it vanishes when its binary is not packaged, which is the
	// production behaviour. Staging it here is what makes the route observable.
	if err := os.WriteFile(filepath.Join(dir, "jvmprobe"), []byte("#!/bin/true\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	reg := probeRegistryIn(dir, "linux", "", "")
	p, ok := reg["java-mem"]
	if !ok {
		t.Fatal("java-mem must be registered on linux")
	}
	if !strings.Contains(p.Path, "jvmprobe") {
		t.Errorf("linux java-mem must launch the native jvmprobe, got %q", p.Path)
	}
	for _, a := range p.Args {
		if a == "-jar" {
			t.Error("linux java-mem must not shell out to a JVM: it would need a host JRE")
		}
	}
}

func TestRegistryForWindowsAddsTheMemoryAndBehaviouralViews(t *testing.T) {
	got := viewsOf(registryFor("windows"))
	for _, want := range []string{"disk", "java-mem", "dotnet-mem", "dotnet-mem-x86", "behavioral", "native-mem"} {
		if !contains(got, want) {
			t.Errorf("windows capability set is missing %q; got %v", want, got)
		}
	}
}

func TestRegistryForIsPure(t *testing.T) {
	// No filesystem, no environment: calling it twice with a mutated environment and a deleted
	// working directory must not change the answer. If this ever regresses, the cross-platform
	// assertions above stop meaning anything -- they would silently start describing the HOST.
	before := viewsOf(registryFor("linux"))
	t.Setenv("JAVA_HOME", filepath.Join(t.TempDir(), "nope"))
	t.Setenv("PATH", "")
	after := viewsOf(registryFor("linux"))
	if strings.Join(before, ",") != strings.Join(after, ",") {
		t.Fatalf("registryFor is not pure: %v then %v", before, after)
	}
}

func TestExeNameAppliesTheExtensionPerPlatform(t *testing.T) {
	if got := exeName("diskprobe", "windows"); got != "diskprobe.exe" {
		t.Errorf(`exeName("diskprobe","windows") = %q, want "diskprobe.exe"`, got)
	}
	for _, goos := range []string{"linux", "darwin", "freebsd"} {
		if got := exeName("diskprobe", goos); got != "diskprobe" {
			t.Errorf("exeName(%q) = %q, want %q", goos, got, "diskprobe")
		}
	}
}

func TestDefaultViewsIsDerivedFromTheTable(t *testing.T) {
	// The assertion that matters is that the default set is DERIVED, not restated. Adding a row and
	// observing the set change is the only check that a future edit cannot satisfy by editing a
	// literal -- which is exactly how defaultViews and probeRegistry drifted apart before.
	base := defaultViewsFor("linux")
	saved := probeSpecs
	t.Cleanup(func() { probeSpecs = saved })

	probeSpecs = append(append([]probeSpec{}, saved...),
		probeSpec{View: "zz-probe", Bin: "zzprobe", Default: true})

	got := defaultViewsFor("linux")
	if got == base {
		t.Fatalf("adding a default row did not change the derived set (%q) -- it is still a literal", got)
	}
	if !strings.Contains(got, "zz-probe") {
		t.Fatalf("derived set %q does not contain the added row", got)
	}
}

func TestDefaultSetExcludesNonDefaultAndForeignRows(t *testing.T) {
	linux := defaultViewsFor("linux")
	// java-mem is no longer in this list: Linux CAN run it, natively. The others still need a
	// Windows-only runtime.
	if strings.Contains(linux, "dotnet-mem") || strings.Contains(linux, "native-mem") ||
		strings.Contains(linux, "behavioral") {
		t.Fatalf("linux default set names a capability the platform cannot run: %q", linux)
	}
	win := defaultViewsFor("windows")
	if strings.Contains(win, "dotnet-mem-x86") {
		t.Fatalf("dotnet-mem-x86 is a companion, not a default view: %q", win)
	}
	if strings.Contains(win, "mock") {
		t.Fatalf("mock is test scaffolding and must never be a default view: %q", win)
	}
}

func TestNoSpecNamesAnExtensionOrASeparator(t *testing.T) {
	// E1 validation rule. A Bin carrying ".exe" would defeat exeName silently on Linux, which is
	// precisely the defect this table replaces.
	for _, s := range probeSpecs {
		if s.Bin == "" {
			continue
		}
		if filepath.Ext(s.Bin) != "" {
			t.Errorf("spec %q: Bin %q carries a file extension", s.View, s.Bin)
		}
		if strings.ContainsAny(s.Bin, `/\`) {
			t.Errorf("spec %q: Bin %q contains a path separator", s.View, s.Bin)
		}
	}
}

func TestSpecViewNamesAreUnique(t *testing.T) {
	seen := map[string]bool{}
	for _, s := range probeSpecs {
		if seen[s.View] {
			t.Errorf("duplicate view %q", s.View)
		}
		seen[s.View] = true
	}
}

func TestEverySpecNamesASupportedPlatform(t *testing.T) {
	// A row whose OS list matches nothing is a configuration error, not a silent no-op: it would
	// simply never register and no test would notice.
	for _, s := range probeSpecs {
		if len(s.OS) == 0 {
			continue
		}
		if len(registryForView(s.View)) == 0 {
			t.Errorf("spec %q names no supported platform: OS=%v", s.View, s.OS)
		}
	}
}

// registryForView reports the supported platforms on which the named view registers.
func registryForView(view string) []string {
	var out []string
	for _, goos := range supportedGOOS {
		for _, s := range registryFor(goos) {
			if s.View == view {
				out = append(out, goos)
			}
		}
	}
	return out
}

func TestAnAbsentOptionalProbeIsNotRegistered(t *testing.T) {
	// Optional only. A platform-supported, non-optional component that is missing must stay LOUD --
	// US4/T061 requires status `failed` and exit 5 -- so it is deliberately still registered and
	// allowed to fail at exec time rather than quietly disappearing from the report.
	dir := t.TempDir()
	reg := probeRegistryIn(dir, runtime.GOOS, "", "")
	if _, ok := reg["dotnet-mem-x86"]; ok {
		t.Error("dotnet-mem-x86 registered with no binary present")
	}
	if _, ok := reg["disk"]; !ok {
		t.Error("disk must stay registered even when absent, so the run fails loudly rather than silently shrinking")
	}
}

func TestRegisteredPathsCarryThePlatformExtension(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range []struct{ goos, want string }{{"windows", "diskprobe.exe"}, {"linux", "diskprobe"}} {
		reg := probeRegistryIn(dir, tc.goos, "", "")
		p, ok := reg["disk"]
		if !ok {
			t.Fatalf("%s: disk not registered", tc.goos)
		}
		if filepath.Base(p.Path) != tc.want {
			t.Errorf("%s: disk path = %q, want base %q", tc.goos, p.Path, tc.want)
		}
		if !containsArg(p.Args, filepath.Join("third_party", "yara-x", exeName("yr", tc.goos))) {
			t.Errorf("%s: engine path does not carry the platform extension: %v", tc.goos, p.Args)
		}
	}
}

func TestNoRegisteredPathNamesAnExtensionOnLinux(t *testing.T) {
	// The end-to-end property the whole change exists for: nothing resolved for a Linux run may
	// mention ".exe", including the engine and the optional companions.
	dir := t.TempDir()
	for _, s := range registryFor("linux") {
		if s.Bin != "" {
			if err := os.WriteFile(filepath.Join(dir, s.Bin), []byte("x"), 0o755); err != nil {
				t.Fatal(err)
			}
		}
	}
	for view, p := range probeRegistryIn(dir, "linux", "", "") {
		if strings.Contains(strings.ToLower(p.Path), ".exe") {
			t.Errorf("view %q resolves to a Windows path: %s", view, p.Path)
		}
		for _, a := range p.Args {
			if strings.Contains(strings.ToLower(a), ".exe") {
				t.Errorf("view %q passes a Windows path: %s", view, a)
			}
		}
	}
}

// --- explicitly requesting a capability the platform cannot support (US4) ---

// A SOC that runs one command line across a mixed fleet asks for the same views everywhere. On the
// Linux hosts that used to print `unknown view "dotnet-mem" (skipped)` -- which says the capability
// does not exist as a CONCEPT, i.e. that the operator made a typo, when in fact the request was
// perfectly well-formed and simply cannot apply here. The report then carried no record of it at
// all, so nothing downstream could tell "we did not look in .NET memory" from "there is no .NET
// memory on this host to look in".
func TestARequestedWindowsOnlyCapabilityIsNotApplicableOnLinux(t *testing.T) {
	// java-mem is deliberately NOT in this list any more: Linux runs it natively via cmd/jvmprobe.
	for _, view := range []string{"dotnet-mem", "behavioral", "native-mem"} {
		p, known := naProbeFor(view, "linux")
		if !known {
			t.Errorf("%q is in the capability table; requesting it on Linux must be reported as n/a, not as an unknown name", view)
			continue
		}
		if p.View != view {
			t.Errorf("%q: the record must name the requested view, got %q", view, p.View)
		}
		if p.NotApplicable == "" {
			t.Errorf("%q: FR-012 requires a reason for any status other than ran", view)
		}
		if !strings.Contains(p.NotApplicable, "linux") {
			t.Errorf("%q: the reason must name the host platform, got %q", view, p.NotApplicable)
		}
		if p.Path != "" || len(p.Args) != 0 {
			t.Errorf("%q: a capability that cannot exist must carry nothing to execute, got path=%q args=%v", view, p.Path, p.Args)
		}
	}
}

// The converse, in both directions: a capability that CAN exist here is not n/a (it is registered,
// and if its component is missing it must fail loudly -- T061), and a name the table has never heard
// of stays an unknown name. Collapsing those two would turn every typo into a silent, reassuring
// "not applicable on this platform".
func TestOnlyAKnownButUnsupportedCapabilityIsNotApplicable(t *testing.T) {
	if _, known := naProbeFor("disk", "linux"); known {
		t.Error("disk runs on Linux; it must never be reported as not applicable there")
	}
	if _, known := naProbeFor("dotnet-mem", "windows"); known {
		t.Error("dotnet-mem runs on Windows; it must never be reported as not applicable there")
	}
	for _, typo := range []string{"", "dotnet_mem", "disc", "memory"} {
		if _, known := naProbeFor(typo, "linux"); known {
			t.Errorf("%q is not in the capability table and must stay an unknown name, not become n/a", typo)
		}
	}
}

// Every row the table excludes from a platform must be explainable on that platform. Otherwise a
// future row could be dropped from the registry and produce no record at all -- the silent-shrink
// failure the Optional field's comment is about, arriving through a different door.
func TestEveryCapabilityAbsentFromAPlatformCanExplainItself(t *testing.T) {
	for _, goos := range supportedGOOS {
		applicable := map[string]bool{}
		for _, s := range registryFor(goos) {
			applicable[s.View] = true
		}
		for _, s := range probeSpecs {
			if applicable[s.View] {
				continue
			}
			p, known := naProbeFor(s.View, goos)
			if !known || p.NotApplicable == "" {
				t.Errorf("%s on %s: excluded from the registry with no explanation available", s.View, goos)
			}
		}
	}
}

// --- view selection: what a request turns into (US4) ---

// coverageOf renders a selection as view -> "run" | reason, which is what the report will say.
//
// CannotRun counts too. A probe carrying one is never executed either, and a helper that
// called it "run" would report the silent-shrink state as a healthy scan inside the very failure
// messages meant to expose it.
func coverageOf(probes []orchestrator.Probe) map[string]string {
	out := map[string]string{}
	for _, p := range probes {
		switch {
		case p.NotApplicable != "":
			out[p.View] = p.NotApplicable
		case p.CannotRun != "":
			out[p.View] = p.CannotRun
		default:
			out[p.View] = "run"
		}
	}
	return out
}

// Scenario 2 of quickstart.md: a DEFAULT scan on Linux must state the capabilities that cannot exist
// there, not merely omit them. A report that says nothing about dotnet-mem cannot be told apart from
// a report by a tool that forgot dotnet-mem exists -- the same reasoning that makes US3 emit
// ScanSkips even when every counter is zero.
func TestADefaultLinuxScanStatesEveryCapabilityTheHostCannotSupport(t *testing.T) {
	reg := map[string]orchestrator.Probe{
		"disk":     {View: "disk", Path: "/opt/ss/diskprobe"},
		"java-mem": {View: "java-mem", Path: "/opt/ss/jvmprobe"},
	}
	probes, runnable, unknown := selectProbes(reg, strings.Split(defaultViewsFor("linux"), ","), "linux", nil, nil)
	// TWO runnable views on Linux now: disk, and java-mem via the native probe.
	if runnable != 2 {
		t.Fatalf("want disk and java-mem runnable, got %d: %+v", runnable, probes)
	}
	if len(unknown) != 0 {
		t.Errorf("the platform's own default set must contain no unknown names, got %v", unknown)
	}
	got := coverageOf(probes)
	if got["disk"] != "run" {
		t.Errorf("disk must run on Linux, got %q", got["disk"])
	}
	if got["java-mem"] != "run" {
		t.Errorf("java-mem must run on Linux via the native probe, got %q", got["java-mem"])
	}
	for _, view := range []string{"dotnet-mem", "dotnet-mem-x86", "behavioral", "native-mem"} {
		reason, ok := got[view]
		if !ok {
			t.Errorf("%s is absent from a Linux report; not-applicable must be stated, not inferred from silence", view)
			continue
		}
		if reason == "run" || !strings.Contains(reason, "linux") {
			t.Errorf("%s: want a reason naming the host platform, got %q", view, reason)
		}
	}
	if len(probes) != len(probeSpecs) {
		t.Errorf("every capability in the table must appear exactly once, got %d of %d: %+v",
			len(probes), len(probeSpecs), coverageOf(probes))
	}
}

// Asking for a capability that is already reported as n/a must not report it twice. One capability,
// one coverage record -- a duplicated view breaks the one-to-one invariant the orchestrator asserts.
func TestAnExplicitlyRequestedUnsupportedCapabilityIsRecordedOnce(t *testing.T) {
	reg := map[string]orchestrator.Probe{"disk": {View: "disk", Path: "/opt/ss/diskprobe"}}
	probes, runnable, unknown := selectProbes(reg, []string{"disk", "dotnet-mem", "dotnet-mem", "disk"}, "linux", nil, nil)
	if runnable != 1 {
		t.Errorf("want 1 runnable view, got %d", runnable)
	}
	if len(unknown) != 0 {
		t.Errorf("dotnet-mem is a real capability name, not an unknown one: %v", unknown)
	}
	seen := map[string]int{}
	for _, p := range probes {
		seen[p.View]++
	}
	for view, n := range seen {
		if n != 1 {
			t.Errorf("%s appears %d times, want exactly 1", view, n)
		}
	}
}

// A typo must stay a typo. Answering "not applicable on this platform" to a misspelled view name is
// a reassuring answer to a question nobody asked, and it hides the fact that the requested view
// never ran anywhere.
func TestAnUnknownViewNameIsReportedNotRecorded(t *testing.T) {
	reg := map[string]orchestrator.Probe{"disk": {View: "disk", Path: "/opt/ss/diskprobe"}}
	probes, _, unknown := selectProbes(reg, []string{"disk", "disc", "dotnet_mem"}, "linux", nil, nil)
	if len(unknown) != 2 || unknown[0] != "disc" || unknown[1] != "dotnet_mem" {
		t.Fatalf("want both typos reported, got %v", unknown)
	}
	if _, ok := coverageOf(probes)["disc"]; ok {
		t.Error("a name the table does not know must not appear in coverage at all")
	}
}

// Requesting ONLY capabilities this host cannot support examines nothing. n/a does not set
// `incomplete`, so a report built from those records alone would read clean and exit 0 for a scan
// that never looked at anything -- which is the one output this tool must never produce.
func TestARequestOfOnlyUnsupportedCapabilitiesIsNotRunnable(t *testing.T) {
	reg := map[string]orchestrator.Probe{"disk": {View: "disk", Path: "/opt/ss/diskprobe"}}
	_, runnable, unknown := selectProbes(reg, []string{"dotnet-mem", "behavioral"}, "linux", nil, nil)
	if runnable != 0 {
		t.Fatalf("want nothing runnable, got %d", runnable)
	}
	if len(unknown) != 0 {
		t.Errorf("these are real capability names: %v", unknown)
	}
}

// Windows gains nothing and loses nothing: every row is either all-platform or Windows-only, so a
// Windows report is exactly what it was before US4.
func TestAWindowsSelectionGainsNoNotApplicableRecords(t *testing.T) {
	reg := map[string]orchestrator.Probe{}
	for _, s := range registryFor("windows") {
		reg[s.View] = orchestrator.Probe{View: s.View, Path: `C:\ss\` + s.View}
	}
	probes, runnable, _ := selectProbes(reg, strings.Split(defaultViewsFor("windows"), ","), "windows", nil, nil)
	if runnable != len(probes) {
		t.Fatalf("no capability is not-applicable on Windows, got %d of %d runnable: %+v",
			runnable, len(probes), coverageOf(probes))
	}
	if len(naProbesFor("windows")) != 0 {
		t.Errorf("naProbesFor(windows) must be empty, got %+v", naProbesFor("windows"))
	}
}

func contains(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}

// --- a compiled rule set replaces the rule tree ---

func TestDiskProbeGetsTheRulesDirectoryByDefault(t *testing.T) {
	reg := probeRegistryIn(`C:\agent`, "windows", "", "")
	disk, ok := reg["disk"]
	if !ok {
		t.Fatal("disk is missing from the registry")
	}
	if !argsContainPair(disk.Args, "--rules", filepath.Join(`C:\agent`, "kb", "rules")) {
		t.Fatalf("args = %v, want --rules pointing at the staged tree", disk.Args)
	}
	if argsContainFlag(disk.Args, "--rules-blob") {
		t.Error("--rules-blob passed when no blob was given")
	}
}

func TestABlobReplacesTheRulesDirectoryEntirely(t *testing.T) {
	// Not both: diskprobe exits on -rules and -rules-blob together rather than picking one, so
	// passing both here would make every disk scan fail at exec time rather than at the point the
	// mistake was made.
	blob := `C:\agent\rules\set.yarc`
	reg := probeRegistryIn(`C:\agent`, "windows", "", blob)
	disk := reg["disk"]
	if !argsContainPair(disk.Args, "--rules-blob", blob) {
		t.Fatalf("args = %v, want --rules-blob", disk.Args)
	}
	if argsContainFlag(disk.Args, "--rules") {
		t.Error("--rules passed alongside --rules-blob; diskprobe refuses that combination")
	}
}

func TestABlobDoesNotDisturbTheMemoryViews(t *testing.T) {
	// mem-contracts.json lives inside the rules DIRECTORY, and a memory view needs it whether or
	// not a compiled blob was supplied for the disk view. Resolving contracts from the blob's
	// directory would break every memory probe in a disk+memory build.
	reg := probeRegistryIn(`C:\agent`, "windows", "", `C:\somewhere\else\set.yarc`)
	dn, ok := reg["dotnet-mem"]
	if !ok {
		t.Fatal("dotnet-mem is missing from the windows registry")
	}
	want := filepath.Join(`C:\agent`, "kb", "rules", "mem-contracts.json")
	if !argsContainPair(dn.Args, "--mem-contracts", want) {
		t.Fatalf("args = %v, want mem-contracts under the staged rules dir", dn.Args)
	}
}

// Exact, and pair-aware. The package's containsArg is a SUBSTRING match, which cannot express
// either half of the claim above: strings.Contains("--rules-blob", "--rules") is true, so "no
// --rules alongside the blob" would misfire, and a flag appearing somewhere in the slice says
// nothing about which value follows it.
func argsContainFlag(args []string, flag string) bool {
	for _, a := range args {
		if a == flag {
			return true
		}
	}
	return false
}

func argsContainPair(args []string, flag, value string) bool {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == flag && args[i+1] == value {
			return true
		}
	}
	return false
}

// --- what a build declares it does not carry (C4) ---

// Three states, and they have to stay three.
//
//	n/a      the build does not carry this view. Expected, benign, DECLARED by agent.json.
//	failed   the build carries it and it did not run. An incident.
//	ran      it ran.
//
// A report that spells the first two the same way is worthless in both directions: the reader
// cannot tell a view that was out of scope from a view that broke, so neither a clean verdict nor
// an alarm means anything. Every test below exists to keep one of those two confusions impossible.

// coverageFor runs one selected probe the way the scan does and returns the coverage record the
// report will carry.
//
// selectProbes only DECIDES; orchestrator.RunProbe is what turns that decision into the word an
// analyst reads. Asserting on Probe.NotApplicable alone would prove the decision and nothing about
// the report, which is the half that matters.
func coverageFor(t *testing.T, p orchestrator.Probe) finding.Coverage {
	t.Helper()
	_, cov := orchestrator.RunProbe(context.Background(), p, finding.TargetSpec{Host: "test"},
		30*time.Second)
	return cov
}

// probeForView fails loudly when a view has no record at all, because silence is the third way to
// lose the distinction: a view nobody mentions is neither n/a nor failed, it is simply gone.
func probeForView(t *testing.T, probes []orchestrator.Probe, view string) orchestrator.Probe {
	t.Helper()
	for _, p := range probes {
		if p.View == view {
			return p
		}
	}
	t.Fatalf("%s has no record at all; absence must be DECLARED, not inferred from silence: %+v",
		view, coverageOf(probes))
	return orchestrator.Probe{}
}

func TestAViewNotInTheBuildReportsNotIncluded(t *testing.T) {
	// C4. A disk-only agent must SAY it carries no memory views, not stay silent about them and
	// not claim they failed.
	reg := map[string]orchestrator.Probe{
		"disk":     {View: "disk", Path: "diskprobe"},
		"java-mem": {View: "java-mem", Path: "jvmprobe"},
	}
	probes, runnable, unknown := selectProbes(reg, []string{"disk", "java-mem"}, "linux", []string{"disk"}, nil)
	if len(unknown) != 0 {
		t.Fatalf("unknown = %v, want none", unknown)
	}
	if runnable != 1 {
		t.Errorf("runnable = %d, want 1 -- only disk is in this build", runnable)
	}
	jm := probeForView(t, probes, "java-mem")
	if jm.NotApplicable == "" {
		t.Fatal("java-mem is not marked not-applicable")
	}
	if !strings.Contains(jm.NotApplicable, "not included in this build") {
		t.Errorf("reason = %q, want it to name the build", jm.NotApplicable)
	}
	// Never executed, which is what keeps the decision out of exec's hands: a spawn that fails
	// cannot tell "this build ships no jvmprobe" from "jvmprobe is broken".
	if jm.Path != "" {
		t.Errorf("path = %q, want none -- a view the build does not carry must not be launched", jm.Path)
	}
}

func TestAViewInTheBuildIsStillRunnable(t *testing.T) {
	reg := map[string]orchestrator.Probe{"disk": {View: "disk", Path: "diskprobe"}}
	probes, runnable, _ := selectProbes(reg, []string{"disk"}, "linux", []string{"disk"}, nil)
	if runnable != 1 {
		t.Fatalf("runnable = %d, want 1", runnable)
	}
	for _, p := range probes {
		if p.View == "disk" && p.NotApplicable != "" {
			t.Errorf("disk is in the build but was marked not-applicable: %q", p.NotApplicable)
		}
	}
}

func TestNoBuildSetMeansEveryViewIsAvailable(t *testing.T) {
	// A scanner run by hand has no agent.json. Today's behaviour must be untouched: a nil build
	// set means no build declared anything, so nothing is excluded by it.
	reg := map[string]orchestrator.Probe{
		"disk":     {View: "disk", Path: "diskprobe"},
		"java-mem": {View: "java-mem", Path: "jvmprobe"},
	}
	probes, runnable, _ := selectProbes(reg, []string{"disk", "java-mem"}, "linux", nil, nil)
	if runnable != 2 {
		t.Errorf("runnable = %d, want 2 -- a nil build set excludes nothing", runnable)
	}
	for _, p := range probes {
		if strings.Contains(p.NotApplicable, "not included in this build") {
			t.Errorf("%s was excluded by a build that does not exist: %q", p.View, p.NotApplicable)
		}
	}
}

func TestAMissingBinaryStillFailsLoudlyWhenTheBuildDeclaresTheView(t *testing.T) {
	// The assertion C4 exists to protect. A view the build DECLARES but whose binary is absent is
	// a broken package, and registry.go's comment is explicit that it must stay loud: "Dropping a
	// required probe from the registry would turn a broken install into a smaller, quieter,
	// apparently-successful scan." A declared-absent state must not become a way to hide that.
	//
	// reg has no entry for java-mem, which is what probeRegistryIn produces when the binary is
	// missing and the spec is Optional. Because the build DECLARES java-mem, it must not be
	// answered with a reassuring n/a.
	reg := map[string]orchestrator.Probe{"disk": {View: "disk", Path: "diskprobe"}}
	probes, runnable, _ := selectProbes(reg, []string{"disk", "java-mem"}, "linux",
		[]string{"disk", "java-mem"}, nil)
	if runnable != 1 {
		t.Errorf("runnable = %d, want 1", runnable)
	}
	for _, p := range probes {
		if p.View == "java-mem" && strings.Contains(p.NotApplicable, "not included in this build") {
			t.Fatal("a DECLARED view with a missing binary was reported as not-included; " +
				"that turns a broken install into a quieter scan")
		}
	}
}

func TestABuildStatesEveryViewItDoesNotCarryEvenUnrequested(t *testing.T) {
	// The same reasoning as naProbesFor: a capability missing from the coverage list is
	// indistinguishable from a capability nobody thought about. A disk-only agent that merely omits
	// java-mem reads exactly like a scanner that has never heard of Java memshells.
	reg := map[string]orchestrator.Probe{"disk": {View: "disk", Path: "/opt/ss/diskprobe"}}
	probes, runnable, unknown := selectProbes(reg, []string{"disk"}, "linux", []string{"disk"}, nil)
	if runnable != 1 || len(unknown) != 0 {
		t.Fatalf("runnable = %d, unknown = %v; want 1 and none", runnable, unknown)
	}
	got := coverageOf(probes)
	if len(probes) != len(probeSpecs) {
		t.Errorf("every capability in the table must appear exactly once, got %d of %d: %+v",
			len(probes), len(probeSpecs), got)
	}
	if got["disk"] != "run" {
		t.Errorf("disk = %q, want it to run", got["disk"])
	}
	if !strings.Contains(got["java-mem"], "not included in this build") {
		t.Errorf("java-mem = %q, want the build named as the reason -- java-mem exists on Linux, so "+
			"its absence here is the BUILD's doing", got["java-mem"])
	}
	// The Windows-only views are absent for a DIFFERENT reason and must keep saying the other one.
	// "this host cannot support it" and "this build did not ship it" lead an operator to opposite
	// conclusions, exactly as DeferredOn does against OS.
	for _, view := range []string{"dotnet-mem", "dotnet-mem-x86", "behavioral", "native-mem"} {
		if !strings.Contains(got[view], "linux") {
			t.Errorf("%s = %q, want the host platform named, not the build", view, got[view])
		}
		if strings.Contains(got[view], "not included in this build") {
			t.Errorf("%s = %q: a platform limit was reported as a build choice", view, got[view])
		}
	}
}

func TestADeclaredAbsenceIsCoveredAsNAAndNeverAsFailed(t *testing.T) {
	// The component IS in the registry, so the only thing keeping it from running is the build's
	// own declaration. Were the not-in-build path ever routed through exec, this would come back
	// `failed` -- which an operator reads as an incident on a host where nothing is wrong.
	dir := t.TempDir()
	reg := map[string]orchestrator.Probe{
		"disk":     {View: "disk", Path: filepath.Join(dir, exeName("diskprobe", runtime.GOOS))},
		"java-mem": {View: "java-mem", Path: filepath.Join(dir, exeName("jvmprobe", runtime.GOOS))},
	}
	probes, _, _ := selectProbes(reg, []string{"disk", "java-mem"}, runtime.GOOS, []string{"disk"}, nil)
	cov := coverageFor(t, probeForView(t, probes, "java-mem"))
	if cov.Status == finding.CovFailed {
		t.Fatalf("a view this build does not carry was covered as %q (%s)\n"+
			"`failed` is an incident and `n/a` is a declared absence; a report that spells them the "+
			"same way cannot be trusted about either", cov.Status, cov.Reason)
	}
	if cov.Status != finding.CovNA {
		t.Fatalf("status = %q, want %q", cov.Status, finding.CovNA)
	}
	if !strings.Contains(cov.Reason, "not included in this build") {
		t.Errorf("reason = %q, want it to name the build", cov.Reason)
	}
}

func TestACarriedViewWithNoComponentIsCoveredAsFailedAndNeverAsNA(t *testing.T) {
	// The mirror image, and the reason a declared build set is not allowed to become a way out.
	// This build DECLARES java-mem and the component is not there, so the scan must say so loudly.
	// Answering it with a reassuring n/a would turn a broken package into a smaller, quieter,
	// apparently-successful scan -- and n/a does not set `incomplete`, so it would exit 0.
	dir := t.TempDir()
	reg := map[string]orchestrator.Probe{
		"java-mem": {View: "java-mem", Path: filepath.Join(dir, exeName("jvmprobe", runtime.GOOS))},
	}
	probes, runnable, _ := selectProbes(reg, []string{"java-mem"}, runtime.GOOS, []string{"java-mem"}, nil)
	if runnable != 1 {
		t.Fatalf("runnable = %d, want 1 -- the build declares java-mem, so it must be attempted", runnable)
	}
	cov := coverageFor(t, probeForView(t, probes, "java-mem"))
	if cov.Status == finding.CovNA {
		t.Fatalf("a declared view whose component is missing was covered as %q (%s)\n"+
			"that is a broken install reported as an expected absence", cov.Status, cov.Reason)
	}
	if cov.Status != finding.CovFailed {
		t.Fatalf("status = %q, want %q", cov.Status, finding.CovFailed)
	}
}

// --- the third state: a view with no component at all ---

// n/a and failed were kept apart above. This is the state that was neither.
//
// A view the build DECLARES whose Optional binary is absent used to get NO coverage record: the
// registry dropped it (registry.go's Optional path), selectProbes found nothing and its default
// branch deliberately refused to answer n/a -- correctly, since "not included in this build" would
// be a lie about a view the build declares -- so it said nothing at all. Reproduced on a built
// binary with agent.json = {"views":["disk","dotnet-mem-x86"]} and no dotnetmem-x86.exe: five
// coverage records, none of them dotnet-mem-x86, and the only trace a stderr line calling a view
// the table plainly holds "unknown". `incomplete` was true in that run only because disk failed
// independently -- had disk succeeded the report would have read clean at exit 0 with a declared
// view missing from it entirely.
//
// These assert on the EMITTED report rather than on the Probe struct. Task 6's four tests all
// asserted on Probe.NotApplicable and all stayed green under a mutation that flipped CovNA to
// CovFailed, inverting the exact meaning they existed to pin: a test on the struct a decision
// produces proves the decision happened and nothing about what it means.

// reportFor emits a report the way a scan does -- orchestrator.Scan, then output.Write -- and reads
// report.json back off disk. Nothing about a coverage record is asserted from memory.
func reportFor(t *testing.T, probes ...orchestrator.Probe) finding.Report {
	t.Helper()
	rep := orchestrator.Scan(context.Background(), probes, finding.TargetSpec{Host: "test"},
		"test", "20260904_000000", 30*time.Second)
	runDir, err := output.Write(rep, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(runDir, "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	var got finding.Report
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	return got
}

// coverageInReport finds one view's record, failing when there is none. Silence is the third way to
// lose the distinction: a view nobody mentions is neither n/a nor failed, it is simply gone.
func coverageInReport(t *testing.T, rep finding.Report, view string) finding.Coverage {
	t.Helper()
	for _, c := range rep.Coverage {
		if c.View == view {
			return c
		}
	}
	t.Fatalf("%s has no coverage record in the emitted report at all; a declared view that went "+
		"unexamined must SAY so, and this report carries %d records: %+v",
		view, len(rep.Coverage), rep.Coverage)
	return finding.Coverage{}
}

func TestADeclaredViewWithNoComponentIsFailedInTheEmittedReport(t *testing.T) {
	// reg has no java-mem entry, which is exactly what probeRegistryIn produces for an Optional spec
	// whose binary is absent. The build declares it anyway.
	reg := map[string]orchestrator.Probe{"disk": {View: "disk", Path: "diskprobe"}}
	probes, _, unknown := selectProbes(reg, []string{"disk", "java-mem"}, "linux",
		[]string{"disk", "java-mem"}, nil)
	if len(unknown) != 0 {
		t.Errorf("unknown = %v; java-mem is a name the table holds, not a typo", unknown)
	}
	// Only the missing view goes into the report, so `incomplete` below is attributable to IT.
	// Reproduced on the real binary, the disk view failed alongside and made the whole run
	// incomplete on its own -- which is how the hole survived: the symptom it produces is invisible
	// whenever anything else is also wrong.
	rep := reportFor(t, probeForView(t, probes, "java-mem"))
	cov := coverageInReport(t, rep, "java-mem")
	if cov.Status == finding.CovNA {
		t.Fatalf("a declared view with no component was covered as %q (%s)\n"+
			"n/a is a declared absence and does not set `incomplete`; answering a broken package "+
			"with it is how a missing capability becomes a clean report at exit 0",
			cov.Status, cov.Reason)
	}
	if cov.Status != finding.CovFailed {
		t.Fatalf("status = %q, want %q", cov.Status, finding.CovFailed)
	}
	// The reason has to name the component, from the table -- "java-mem could not run" gives an
	// operator standing on a customer's host nothing to repair.
	want := mustSpec(t, "java-mem").binariesFor("linux")
	var named bool
	for _, b := range want {
		if strings.Contains(cov.Reason, b) {
			named = true
		}
	}
	if !named {
		t.Errorf("reason = %q, want it to name one of the components the table declares for "+
			"java-mem on linux (%v)", cov.Reason, want)
	}
	if strings.Contains(cov.Reason, "not included in this build") {
		t.Errorf("reason = %q: a broken package was worded as a declared absence", cov.Reason)
	}
	// And the verdict the operator acts on. A missing component alone must make the run incomplete
	// and must not exit 0 -- the whole point of preferring `failed` here.
	if !rep.Verdict.Incomplete {
		t.Error("the report is not marked incomplete; a declared view went unexamined")
	}
	if got := exitCode(rep.Verdict); got == 0 {
		t.Errorf("exit code = %d, want non-zero: nothing was examined and a declared view is missing", got)
	}
}

func TestACannotRunWithNoDeclarationIsAlsoFailed(t *testing.T) {
	// No agent.json, so nothing declares the view either present or absent -- a scanner run by hand
	// out of a tree where the optional companion was never built. The scanner cannot tell that from
	// a package that shipped broken, and when it cannot tell, the loud answer is the only safe one:
	// a reassuring absence here is how a broken package becomes a quiet scan.
	reg := map[string]orchestrator.Probe{"disk": {View: "disk", Path: "diskprobe"}}
	probes, _, unknown := selectProbes(reg, []string{"disk", "java-mem"}, "linux", nil, nil)
	if len(unknown) != 0 {
		t.Errorf("unknown = %v; java-mem is a name the table holds, not a typo", unknown)
	}
	cov := coverageInReport(t, reportFor(t, probeForView(t, probes, "java-mem")), "java-mem")
	if cov.Status != finding.CovFailed {
		t.Fatalf("status = %q (%s), want %q", cov.Status, cov.Reason, finding.CovFailed)
	}
}

func TestAKnownViewWithNoComponentIsNeverCalledUnknown(t *testing.T) {
	// The stderr line runScan prints for every name selectProbes could not place is
	// `unknown view %q (skipped)`, which says the capability does not exist as a CONCEPT -- i.e.
	// that the operator made a typo. Saying that about a view the table holds sends them to fix
	// their command line while the real fault is in the package.
	//
	// Windows-only rows, because a missing component is only tellable from an unsupported platform
	// on a platform that DOES support it.
	reg := map[string]orchestrator.Probe{"disk": {View: "disk", Path: `C:\ss\diskprobe.exe`}}
	_, _, unknown := selectProbes(reg,
		[]string{"disk", "dotnet-mem-x86", "native-mem", "dotnet_mem"}, "windows", nil, nil)
	if len(unknown) != 1 || unknown[0] != "dotnet_mem" {
		t.Fatalf("unknown = %v, want only the typo: every other name is in the capability table", unknown)
	}
}

// mustSpec is specFor with the test's own failure attached, so a renamed view fails where it is
// used rather than silently matching an empty spec.
func mustSpec(t *testing.T, view string) probeSpec {
	t.Helper()
	s, ok := specFor(view)
	if !ok {
		t.Fatalf("%s is not in the capability table", view)
	}
	return s
}

// TestABuildDeclaringAViewTheTableDoesNotKnowIsFailedNotSilent covers the last route by which a
// declared view could go unexamined without the report saying so.
//
// Reproduced on the built binary before this was closed: agent.json declaring "dotnet-mem-x64" --
// a name no capability has -- produced six coverage records and none for it. The only trace was
// `warning: unknown view "dotnet-mem-x64" (skipped)` on stderr, and stderr is not in the report.
//
// It is not a typo, because nobody typed it on this host. It is a package and a scanner that
// disagree about what the build carries: a console newer than the release it stamped, or an edited
// agent.json. The operator who mistypes -views reads the warning and retries; nobody reads this one.
func TestABuildDeclaringAViewTheTableDoesNotKnowIsFailedNotSilent(t *testing.T) {
	const bogus = "dotnet-mem-x64"
	reg := map[string]orchestrator.Probe{"disk": {View: "disk", Path: "diskprobe"}}
	probes, _, unknown := selectProbes(reg, []string{"disk", bogus}, "windows",
		[]string{"disk", bogus}, nil)

	for _, u := range unknown {
		if u == bogus {
			t.Errorf("%s was warned about as a typo; the BUILD declared it, so a warning on stderr "+
				"is not where that belongs -- the report is", bogus)
		}
	}

	// Only the declared-unknown view goes into the report, so `incomplete` is attributable to it.
	rep := reportFor(t, probeForView(t, probes, bogus))
	cov := coverageInReport(t, rep, bogus)
	if cov.Status == finding.CovNA {
		t.Fatalf("covered as %q (%s)\nn/a does not set `incomplete`, so answering a scanner/package "+
			"disagreement with it turns it into a clean report at exit 0", cov.Status, cov.Reason)
	}
	if cov.Status != finding.CovFailed {
		t.Fatalf("status = %q, want %q", cov.Status, finding.CovFailed)
	}
	if !strings.Contains(cov.Reason, bogus) {
		t.Errorf("reason does not name the view: %q", cov.Reason)
	}
	if !rep.Verdict.Incomplete {
		t.Error("a declared view that nothing examined left the run complete; the exit code would " +
			"then say the host was swept when one declared capability never ran")
	}
}

// TestATypoOnTheCommandLineIsStillJustAWarning is the other half, and the reason the case above is
// gated on the declaration rather than on the name.
//
// A human typed this one and is reading the terminal, so a warning is the right answer and a
// coverage record would be noise -- there is no capability for the report to be honest ABOUT.
func TestATypoOnTheCommandLineIsStillJustAWarning(t *testing.T) {
	reg := map[string]orchestrator.Probe{"disk": {View: "disk", Path: "diskprobe"}}
	probes, _, unknown := selectProbes(reg, []string{"disk", "dsik"}, "windows", nil, nil)

	var warned bool
	for _, u := range unknown {
		if u == "dsik" {
			warned = true
		}
	}
	if !warned {
		t.Errorf("unknown = %v, want it to carry the typo", unknown)
	}
	for _, p := range probes {
		if p.View == "dsik" {
			t.Errorf("a typo got a coverage record (%+v); the report would then declare something "+
				"about a capability that does not exist", p)
		}
	}
}

// TestAPresentComponentIsNeverReportedAsNotIncluded closes the direction this plan never specified:
// every other case here is a view DECLARED and missing; this one is a view PRESENT and undeclared.
//
// Measured on the built binary before the fix: with diskprobe.exe, yr.exe and the whole rule tree in
// the agent directory and agent.json saying {"views":["behavioral"]}, the report said
// `disk -- not included in this build`, incomplete=false, exit 0. Not silence, which is what the
// other two holes produced, but a FALSE STATEMENT -- and the one an analyst trusts most, because a
// declared absence is what this tool sells.
//
// It is also the cheapest evasion of the three: editing one line of agent.json retires a whole view,
// and that is easier than deleting a binary.
func TestAPresentComponentIsNeverReportedAsNotIncluded(t *testing.T) {
	reg := map[string]orchestrator.Probe{
		"disk":       {View: "disk", Path: "diskprobe"},
		"behavioral": {View: "behavioral", Path: "behaviorprobe"},
	}
	// The package holds disk's components; agent.json declares only behavioral.
	//
	// `requested` is the DECLARED set, not every view -- which is what a real agent does, because
	// resolveViews turns agent.json's list into the requested list. An undeclared view therefore
	// never reaches the requested loop and is answered by the build sweep instead. Requesting disk
	// here by hand would let a fix that only touches the loop pass while doing nothing on a real
	// agent: that is precisely the false pass this test caught.
	carries := func(view string) bool { return view == "disk" }
	probes, _, _ := selectProbes(reg, []string{"behavioral"}, "linux",
		[]string{"behavioral"}, carries)

	rep := reportFor(t, probeForView(t, probes, "disk"))
	cov := coverageInReport(t, rep, "disk")
	if cov.Status == finding.CovNA {
		t.Fatalf("a component sitting in the package was reported as %q (%s)\n"+
			"that is not an omission, it is the report asserting something false -- and n/a does not "+
			"set `incomplete`, so it exits 0", cov.Status, cov.Reason)
	}
	if cov.Status != finding.CovFailed {
		t.Fatalf("status = %q, want %q", cov.Status, finding.CovFailed)
	}
	// The reason must say the component is PRESENT. Without that an operator cannot tell a tampered
	// configuration from a build that was legitimately trimmed.
	for _, want := range []string{"does not declare", "carries"} {
		if !strings.Contains(cov.Reason, want) {
			t.Errorf("reason does not say the component is present (missing %q): %q", want, cov.Reason)
		}
	}
	if !rep.Verdict.Incomplete {
		t.Error("an undeclared-but-present view left the run complete; an edited agent.json could " +
			"then retire a whole view and still exit 0")
	}
}

// TestAGenuinelyAbsentViewIsStillJustNotIncluded is the other half, and the reason the check above is
// gated on presence rather than applied to every undeclared view.
//
// A build really trimmed to behavioral-only carries no diskprobe. Reporting that as a failure would
// make every memory-only agent exit 5 for doing exactly what it was built to do -- which is the
// confusion Task 6 exists to prevent, arriving from the opposite side.
func TestAGenuinelyAbsentViewIsStillJustNotIncluded(t *testing.T) {
	reg := map[string]orchestrator.Probe{
		"disk":       {View: "disk", Path: "diskprobe"},
		"behavioral": {View: "behavioral", Path: "behaviorprobe"},
	}
	probes, _, _ := selectProbes(reg, []string{"behavioral"}, "linux",
		[]string{"behavioral"}, func(string) bool { return false })

	rep := reportFor(t, probeForView(t, probes, "disk"))
	cov := coverageInReport(t, rep, "disk")
	if cov.Status != finding.CovNA {
		t.Fatalf("a view the package genuinely does not carry was reported as %q (%s); "+
			"a trimmed build must not exit 5 for being trimmed", cov.Status, cov.Reason)
	}
	if rep.Verdict.Incomplete {
		t.Error("a declared absence set `incomplete`; every memory-only agent would exit 5")
	}
}

// TestPackageCarriesRequiresEveryComponent pins that a half-staged view does not count as carried.
// Answering "carried" for one would report the louder disagreement for the wrong reason.
func TestPackageCarriesRequiresEveryComponent(t *testing.T) {
	dir := t.TempDir()
	carries := packageCarriesIn(dir, "linux")
	if carries("disk") {
		t.Error("an empty directory reported as carrying disk")
	}

	// Stage every component but the last, then the last.
	components := mustSpec(t, "disk").componentsFor("linux")
	if len(components) < 2 {
		t.Skipf("disk declares %d components on linux; this test needs at least 2", len(components))
	}
	for _, c := range components[:len(components)-1] {
		full := filepath.Join(dir, filepath.FromSlash(c))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if carries("disk") {
		t.Errorf("reported as carried with %q still missing", components[len(components)-1])
	}

	last := filepath.Join(dir, filepath.FromSlash(components[len(components)-1]))
	if err := os.MkdirAll(filepath.Dir(last), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(last, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !carries("disk") {
		t.Error("every component present and still not reported as carried")
	}
}
