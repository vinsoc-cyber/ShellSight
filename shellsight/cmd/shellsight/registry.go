package main

// The capability table: the single place a detection capability is described.
//
// WHY THIS EXISTS
//
// Component names used to be seven string literals inside probeRegistry, each ending in ".exe", with
// the default capability set restated separately as a comma-joined const. Two consequences, both
// measured rather than supposed:
//
//   - On Linux the CLI resolved `diskprobe.exe`, `yr.exe` and friends, so it could not start at all --
//     even though every one of those components cross-compiles and the Linux/amd64 probe produces
//     byte-identical detections on all 31 corpus populations (2026-08-20 parity run, 0 differences
//     across 29,962 files). The detector was portable; only its resolver was not.
//   - The literal set and the registry drifted independently, because nothing tied them together.
//
// A row here is the only declaration. `defaultViews` is DERIVED from it (E1), so a capability cannot
// be registered without appearing in the default-set calculation, or vice versa.
//
// registryFor is a PURE function of the table and goos -- no filesystem, no environment. That is what
// lets the Linux capability set be asserted from the Windows development host (FR-030), which matters
// because the alternative is discovering on a responder's target host that a capability silently
// vanished.

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"shellsight/internal/orchestrator"
	"shellsight/internal/platform"
)

// probeSpec declares one detection capability (data-model E1).
type probeSpec struct {
	// View is the capability name as it appears in --views and in the report.
	View string
	// Bin is the executable base name with NO extension and no path separator; exeName applies the
	// extension and the resolver applies the directory. Empty when the capability is launched by an
	// external runtime rather than a bundled binary (java-mem runs through a JVM).
	Bin string
	// OS lists the platforms where the capability can exist; empty means every platform.
	OS []string
	// DeferredOn lists platforms where the capability CAN exist but this release does not ship it,
	// and DeferredWhy says why (FR-007a).
	//
	// Distinct from OS, and the distinction is not pedantic. "This host cannot support it" and "we
	// have not shipped it yet" lead an operator to opposite conclusions: the first says stop looking,
	// the second says escalate or wait for the release that ships it. Reporting a deferral as a
	// platform limit tells them something false about the world.
	//
	// A deferred capability still reports `n/a` -- so it does NOT set the incomplete flag and does not
	// turn every clean Linux scan into exit 5, which is what US4 exists to prevent -- while staying
	// distinguishable from a component that is missing because the package is broken. That case is a
	// platform-supported probe whose binary is absent, and it stays loud: `failed` and exit 5.
	DeferredOn  []string
	DeferredWhy string
	// Default reports whether the capability participates in the default set.
	Default bool
	// Optional suppresses registration when the binary is absent.
	//
	// NOT in E1, and deliberately narrow. A platform-supported component that is simply MISSING must
	// stay loud -- US4/T061 requires status `failed` and exit 5 -- so only genuinely optional
	// companions carry this. Dropping a required probe from the registry would turn a broken install
	// into a smaller, quieter, apparently-successful scan, which is the failure mode US3 spent its
	// whole budget eliminating elsewhere.
	Optional bool
	// BinariesOn/DataOn, and Binaries/Data for the all-platform case, are what a generated agent must
	// CARRY for this view, as paths relative to the agent directory.
	//
	// They exist for two jobs. A generator must not keep its own list -- G5 of the agent-generation
	// design, and this project has already paid for the alternative: internal/weblang exists because
	// seven places decided a file's language independently and two had silently diverged. And the
	// scanner must be able to NAME the component a broken package is missing, rather than reporting
	// only that a view did not run.
	//
	// Per-platform where the two genuinely differ: Linux java-mem is a native binary carrying its
	// agent embedded, Windows java-mem runs a jar on a host JRE.
	//
	// A test asserts these agree with what probeRegistryIn actually invokes. That is what makes the
	// table authoritative without rewiring the switch that invokes every probe -- rewiring would only
	// move the risk into the code path every scan runs through.
	BinariesOn map[string][]string
	DataOn     map[string][]string
	Binaries   []string
	Data       []string
	// NeedsRules reports whether this view scans with YARA. Only disk does, so a memory-only agent
	// carries neither yr nor a single rule -- which is why the console's form has to be able to say
	// that asking such a build for a rule set means nothing.
	NeedsRules bool
	// HostRequiresOn states, per platform, what the TARGET host must already have.
	//
	// Data rather than a message printed at exec time. registry.go warns and drops the java-mem view
	// when no JRE is found, and that warning appears on a customer's server hours after the build
	// choice that made it inevitable; the console has to be able to say it at generate time, which
	// means the requirement must be a value something else can read.
	HostRequiresOn map[string]string
}

// binariesFor returns the executable components this view needs on goos, relative to the agent
// directory: the all-platform ones first, then the platform's own.
func (s probeSpec) binariesFor(goos string) []string {
	return append(append([]string{}, s.Binaries...), s.BinariesOn[goos]...)
}

// dataFor returns the data files this view needs on goos, relative to the agent directory.
func (s probeSpec) dataFor(goos string) []string {
	return append(append([]string{}, s.Data...), s.DataOn[goos]...)
}

// componentsFor returns every path this view needs on goos, binaries and data alike.
func (s probeSpec) componentsFor(goos string) []string {
	return append(s.binariesFor(goos), s.dataFor(goos)...)
}

// supportedGOOS is the set of platforms the table is allowed to name.
var supportedGOOS = []string{"windows", "linux"}

// probeSpecs is the capability table.
//
// `mock` and `mock-fail` are absent by design: they are test scaffolding, `mockprobe` is on the
// forbidden-release-name list and can never ship, and including them would put test doubles in the
// capability set that the Linux archive is verified against.
var probeSpecs = []probeSpec{
	{View: "disk", Bin: "diskprobe", Default: true,
		BinariesOn: map[string][]string{
			"windows": {"diskprobe.exe", "third_party/yara-x/yr.exe"},
			"linux":   {"diskprobe", "third_party/yara-x/yr"},
		},
		// The rule LAYERS, not the directory holding them: a disk-only agent carries no
		// mem-contracts.json, which is the sibling file the memory views declare for themselves.
		Data:       []string{"kb/rules/foundation", "kb/rules/own"},
		NeedsRules: true},

	// DEFERRED on Linux, not unsupported there. The JVM attach path is portable; what is missing is
	// live validation against a Linux application server (US5/T064), and an unvalidated capability
	// that reports "ran" is worse than one that reports n/a. Shipping it is deleting one line.
	//
	// Modelled as DeferredOn rather than OS: []string{"windows"} because the earlier form made the
	// probe say "supported on windows only", which is untrue of the capability and tells a responder
	// hunting Linux Java memshells to give up.
	// java-mem runs on BOTH platforms, by different routes.
	//
	// On Linux it is the native cmd/jvmprobe: a static binary that speaks the HotSpot attach
	// protocol directly with the agent jar embedded, so no JRE is required anywhere. The deferral
	// this replaces asked for "live validation against a Linux application server before this tool
	// will claim it works"; that validation is
	// docs/measurements/2026-08-31-tomcat-memshell-corpus -- 92 real resident fileless memshells
	// across 8 tools and 17 component types, recall 84/92 at zero false positives on clean
	// Tomcat 9 and 10, versus 39/92 for the incumbent with no cell where it wins.
	//
	// On Windows it still runs through javamem.jar, which needs a host JRE.
	//
	// DataOn carries no Linux entry, and that is a statement rather than an omission. cmd/jvmprobe
	// never reads mem-contracts.json: its contract set is the compiled-in pipelineContracts map
	// (cmd/jvmprobe/fuse.go), staged to the embedded agent over the handoff (main_linux.go), which
	// is why the Linux branch of probeRegistryIn passes no --mem-contracts at all. The file still
	// ships in the Linux archive, for the `rules` subcommands -- but the java-mem VIEW does not
	// need it, and declaring otherwise would tell a generator to stage a dependency that is not one.
	{View: "java-mem", Bin: "jvmprobe", Default: true, Optional: true,
		BinariesOn: map[string][]string{
			"linux":   {"jvmprobe"},
			"windows": {"javamem.jar", "javamem-agent.jar"},
		},
		DataOn: map[string][]string{
			"windows": {"kb/rules/mem-contracts.json"},
		},
		HostRequiresOn: map[string]string{
			"windows": "a Java runtime on the target host",
		}},

	// The .NET runtime DLLs both dotnetmem binaries load are deliberately not listed. They are a
	// shared dependency of the two, not a component of either view, and enumerating ~137 of them
	// here would be a list that drifts every time the SDK moves. package.sh's staged lists remain
	// their source; a generator still needs them, and components.json does not yet say so.
	{View: "dotnet-mem", Bin: "dotnetmem", OS: []string{"windows"}, Default: true,
		Binaries: []string{"dotnetmem.exe", "dotnetmem.exe.config"},
		Data:     []string{"kb/rules/mem-contracts.json"}},
	// The 32-bit companion: analyses 32-bit w3wp workers that the x64 probe defers. Built only on a
	// NuGet-enabled box, hence optional, and never a default view -- runScan pairs it with dotnet-mem.
	{View: "dotnet-mem-x86", Bin: "dotnetmem-x86", OS: []string{"windows"}, Optional: true,
		Binaries: []string{"dotnetmem-x86.exe", "dotnetmem-x86.exe.config"},
		Data:     []string{"kb/rules/mem-contracts.json"}},
	{View: "behavioral", Bin: "behaviorprobe", OS: []string{"windows"}, Default: true,
		Binaries: []string{"behaviorprobe.exe"}},
	{View: "native-mem", Bin: "nativemem", OS: []string{"windows"}, Default: true,
		Binaries: []string{"nativemem.exe"}},
}

// registryFor returns the capability rows that can exist on goos, in table order.
//
// Pure: no filesystem access and no environment reads. Path resolution and existence checking happen
// afterwards in probeRegistryIn, so the two concerns stay separately testable.
func registryFor(goos string) []probeSpec { return registryForSpecs(probeSpecs, goos) }

// registryForSpecs is registryFor over an arbitrary table, so a test can exercise the deferral
// mechanism against a synthetic spec rather than requiring a real capability to be deferred.
func registryForSpecs(specs []probeSpec, goos string) []probeSpec {
	var out []probeSpec
	for _, s := range specs {
		if s.appliesTo(goos) {
			out = append(out, s)
		}
	}
	return out
}

func (s probeSpec) appliesTo(goos string) bool {
	if s.deferredOn(goos) {
		return false // the capability exists here; this release just does not ship it
	}
	if len(s.OS) == 0 {
		return true
	}
	for _, o := range s.OS {
		if o == goos {
			return true
		}
	}
	return false
}

func (s probeSpec) deferredOn(goos string) bool {
	for _, o := range s.DeferredOn {
		if o == goos {
			return true
		}
	}
	return false
}

// specFor returns the table row carrying a view name. known is false when no row does.
//
// The distinction selectProbes could not make before the table carried component lists: a view with
// no registry entry is either a TYPO or a component that should be in this package and is not, and
// those two need opposite answers. naProbeFor could not settle it -- it reports known only for a row
// the platform EXCLUDES, so a Windows-only view requested on Windows with its binary absent came
// back "not known" and was warned about as an unknown name the table plainly holds.
func specFor(view string) (probeSpec, bool) {
	for _, s := range probeSpecs {
		if s.View == view {
			return s, true
		}
	}
	return probeSpec{}, false
}

// naProbeFor returns the not-applicable record for a capability the table knows but this platform
// cannot support. known is false when no row carries that view name at all.
//
// The two cases must stay apart. A name the table has never heard of is a TYPO, and saying "not
// applicable on this platform" to a typo is a reassuring answer to a question nobody asked. A
// Windows-only capability requested on Linux is a perfectly well-formed request that simply cannot
// apply here, and the old code answered both with `unknown view "dotnet-mem" (skipped)` and then
// left the report with no record of the capability at all -- so nothing downstream could tell "we
// did not look in .NET memory" from "there is no .NET memory on this host to look in".
//
// Pure, like everything else in this file: the answer depends on the table and goos, never on the
// filesystem, so the Linux behaviour is assertable from the Windows development host (FR-030).
func naProbeFor(view, goos string) (orchestrator.Probe, bool) {
	return naProbeForSpecs(probeSpecs, view, goos)
}

// naProbeForSpecs is naProbeFor over an arbitrary table.
//
// Exists so a test can exercise the DEFERRAL MECHANISM against a synthetic spec instead of needing
// a real capability to be deferred. java-mem was the live example until it shipped on Linux; the
// machinery still has to work for whatever is deferred next.
func naProbeForSpecs(specs []probeSpec, view, goos string) (orchestrator.Probe, bool) {
	for _, s := range specs {
		if s.View != view || s.appliesTo(goos) {
			continue
		}
		reason := fmt.Sprintf("%s is supported on %s only; this host is %s",
			s.View, strings.Join(s.OS, "/"), goos)
		if s.deferredOn(goos) {
			// Names the platform as well, so this reads as a fact about the release rather than about
			// the capability -- and so a reader can tell which host it applies to.
			reason = fmt.Sprintf("%s is deferred on %s in this release: %s", s.View, goos, s.DeferredWhy)
		}
		return orchestrator.Probe{View: s.View, NotApplicable: reason}, true
	}
	return orchestrator.Probe{}, false
}

// naProbesFor returns a not-applicable record for EVERY capability the table says cannot exist on
// goos, in table order.
//
// Not only the ones the operator asked for. A capability missing from the coverage list is
// indistinguishable from a capability nobody thought about, so "not applicable here" has to be
// stated rather than inferred from an absence -- the same reason ScanSkips is emitted even when
// every counter is zero (US3/T049). An analyst reading a Linux report should not have to already
// know the Linux capability set in order to know what was out of scope.
//
// On Windows this returns nothing: every row is either all-platform or Windows-only, so a Windows
// report is byte-for-byte what it was before.
func naProbesFor(goos string) []orchestrator.Probe {
	var out []orchestrator.Probe
	for _, s := range probeSpecs {
		if p, known := naProbeFor(s.View, goos); known {
			out = append(out, p)
		}
	}
	return out
}

// selectProbes turns a requested view list into the probes to run plus the records to report.
//
// Pure, and separated from runScan for that reason: the Linux answer is asserted from this Windows
// box, and runnable is returned rather than inferred from len(probes) because a list made only of
// not-applicable records examines nothing while looking like a populated scan.
//
// inBuild is the view set the build DECLARES it carries (agent.json's `views`), or nil when no
// build declared anything. It gives the not-applicable path a SECOND trigger beside the platform
// one: a trimmed agent must SAY it carries no memory views rather than stay silent about them, and
// must not try to exec a component it never shipped and then report `failed`.
//
// The distinction that buys is the whole point of a declared build, and it runs three ways:
//
//	n/a      this build does not carry the view. Expected, benign, and DECLARED.
//	failed   this build carries it and it did not run. An incident.
//	ran      it ran.
//
// So a view the build DECLARES whose component is missing never reaches the n/a path below. It
// stays loud, for the reason probeSpec.Optional gives: dropping a required probe would turn a
// broken install into a smaller, quieter, apparently-successful scan.
// packageCarries, when non-nil, reports whether this package actually holds a view's declared
// components. nil means the question cannot be answered here -- every existing caller that only
// exercises selection logic passes nil, and the behaviour is then exactly what it was.
//
// It is a seam rather than a filesystem call inside this function for the reason the synthetic-table
// seams exist: selection is pure, and eleven tests depend on being able to ask it about a linux-arm64
// package from a Windows box.
func selectProbes(reg map[string]orchestrator.Probe, requested []string, goos string,
	inBuild []string, packageCarries func(view string) bool) (probes []orchestrator.Probe, runnable int, unknown []string) {
	// A nil inBuild means no build declared anything -- a scanner run by hand -- so nothing is
	// excluded by it and everything below behaves exactly as it did before.
	//
	// nil rather than empty is what carries that meaning, the same way agentcfg.Config.Present does
	// one layer up: agentcfg.Load refuses a configuration declaring no views, so an empty-but-stated
	// list cannot come from a real config, and reading one as "carries nothing" would let a
	// configuration that does not exist declare every view absent.
	var carried map[string]bool
	if inBuild != nil {
		carried = make(map[string]bool, len(inBuild))
		for _, v := range inBuild {
			carried[strings.TrimSpace(v)] = true
		}
	}
	seen := map[string]bool{}
	for _, v := range requested {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		switch p, ok := reg[v]; {
		case ok:
			if carried != nil && !carried[v] {
				// The build says it does not carry this view. Before believing that, check whether
				// the components are sitting right here -- because if they are, the declaration is
				// wrong and repeating it is not a declared absence but a FALSE STATEMENT.
				//
				// Measured 2026-09-04: with diskprobe.exe, yr.exe and the whole rule tree in the
				// agent directory and agent.json saying {"views":["behavioral"]}, the report said
				// `disk -- not included in this build`, incomplete=false, exit 0. Editing one line
				// of agent.json retired the entire disk view and produced a clean sweep, which is
				// cheaper for an intruder than deleting a binary and is the premise the rest of this
				// file already designs around.
				//
				// Distinct from every other absence here, and it is the direction the plan never
				// specified: the other cases are a view declared and MISSING, this one is a view
				// present and UNDECLARED.
				if packageCarries != nil && packageCarries(v) {
					if !seen[v] {
						seen[v] = true
						probes = append(probes, orchestrator.Probe{
							View:      v,
							CannotRun: undeclaredButPresentReason(v, goos),
						})
					}
					continue
				}
				// Genuinely not carried. This reuses the same NotApplicable path platform
				// deferrals take, so the incomplete flag and the exit code behave as they already
				// do for a capability this release does not ship. Critically the component is never
				// executed: a spawn that fails cannot tell "this build ships no jvmprobe" from
				// "jvmprobe is broken", so routing this decision through exec would collapse the two
				// states it exists to keep apart.
				if !seen[v] {
					seen[v] = true
					probes = append(probes, orchestrator.Probe{
						View:          v,
						NotApplicable: notInBuildReason(v),
					})
				}
				continue
			}
			if !seen[v] {
				seen[v] = true
				probes = append(probes, p)
				runnable++
			}
		default:
			// No registry entry. Four different absences hide behind that, and the table is what
			// tells them apart -- which is why this branch could answer only two of them before the
			// table carried component lists.
			s, inTable := specFor(v)
			switch {
			case !inTable && carried[v]:
				// A name the table has never heard of, declared by the BUILD. That is not a typo --
				// nobody typed it on this host. It is a package and a scanner that disagree about
				// what this build carries, which is what a console newer than its release, or an
				// edited agent.json, both look like.
				//
				// The operator case below can answer with a warning because a human is reading the
				// terminal and can retry. Here nobody is: the report IS the product, stderr is not
				// in it, and a declared view that nothing examined and nothing recorded is the one
				// output this tool must never produce. So it takes the same `failed` the missing
				// component above takes, for the same reason -- it sets `incomplete`, and n/a would
				// not.
				if !seen[v] {
					seen[v] = true
					probes = append(probes, orchestrator.Probe{
						View: v,
						CannotRun: fmt.Sprintf("agent.json declares %q, which this scanner "+
							"has no capability by that name; the package and the scanner disagree "+
							"about what this build carries", v),
					})
				}
			case !inTable:
				// A name the table has never heard of and no build declared: a typo on the command
				// line. It must not be answered with a reassuring "not applicable" -- that hides the
				// fact that the view the operator asked for never ran anywhere. A warning is enough
				// because the person who typed it is the person reading it.
				unknown = append(unknown, v)
			case !s.appliesTo(goos):
				// Known but unsupported (or deferred) here. No warning and no record at this point:
				// the platform sweep below states it exactly once, whether or not it was asked for.
			case carried != nil && !carried[v]:
				// The build DECLARED it does not carry this view, and sure enough there is no
				// component. Expected, benign, and already answered -- the not-in-build sweep below
				// states it once, with the same n/a the registered case gives.
			default:
				// The third state, and the one that used to be silent: the table holds this view,
				// this platform supports it, no declaration excludes it -- and there is nothing to
				// run. That is a BROKEN PACKAGE, and it is the only absence with no benign reading.
				//
				// It reached here because probeRegistryIn dropped an Optional spec whose binary was
				// missing. Optional was always about whether a REGISTRY entry survives; it was never
				// meant to decide whether a declaration is honoured. Before this, such a view got no
				// coverage record at all -- not n/a, not failed, nothing -- so a report could read
				// clean at exit 0 with a declared view silently missing, the one output this tool
				// must never produce.
				//
				// `failed`, never `n/a`, and never silence. n/a does not set `incomplete`, so
				// answering here with a declared absence would turn a broken install into a smaller,
				// quieter, apparently-successful scan.
				if !seen[v] {
					seen[v] = true
					probes = append(probes, orchestrator.Probe{
						View:      v,
						CannotRun: missingComponentReason(s, goos, carried != nil),
					})
				}
			}
		}
	}
	// State every view this build does not carry, whether or not it was asked for -- the same
	// reasoning as naProbesFor below: a capability missing from the coverage list is
	// indistinguishable from a capability nobody thought about.
	//
	// registryFor(goos) rather than reg, because this has to state a view the build omitted even
	// when that view's component is absent too. It cannot collide with the platform sweep that
	// follows: naProbesFor's rows are exactly the ones registryFor excludes.
	//
	// The presence check belongs HERE as much as in the requested loop above, and measuring is what
	// showed it: resolveViews makes the DECLARED set the requested set, so a view the build does not
	// declare is never in `requested` at all and never reaches that loop. Every undeclared view is
	// answered by this sweep. A unit test that puts the view in `requested` by hand passes against a
	// fix that does nothing on a real agent -- which is exactly what happened before this line.
	if carried != nil {
		for _, s := range registryFor(goos) {
			if carried[s.View] || seen[s.View] {
				continue
			}
			seen[s.View] = true
			if packageCarries != nil && packageCarries(s.View) {
				probes = append(probes, orchestrator.Probe{
					View:      s.View,
					CannotRun: undeclaredButPresentReason(s.View, goos),
				})
				continue
			}
			probes = append(probes, orchestrator.Probe{
				View:          s.View,
				NotApplicable: notInBuildReason(s.View),
			})
		}
	}
	for _, na := range naProbesFor(goos) {
		if !seen[na.View] {
			seen[na.View] = true
			probes = append(probes, na)
		}
	}
	return probes, runnable, unknown
}

// notInBuildReason is the single spelling of "this build does not carry that view".
//
// One definition, because this string is what an operator reads to tell a declared absence from a
// failure, and two copies of it are two things that can drift apart. It names agent.json so the
// reader can see the absence was DECLARED by the build rather than inferred from something being
// missing -- the difference between a coverage gap that was chosen and one that was suffered.
// packageCarriesIn answers, for a view the build did not declare, whether this package holds it
// anyway -- the seam selectProbes takes.
//
// EVERY declared component must be present, not merely one. A half-staged view is not a view the
// package carries, and calling it one would turn a broken package into the louder disagreement
// answer for the wrong reason.
//
// A view the table does not know carries nothing: there is no component list to look for, so there
// is nothing that could be present.
func packageCarriesIn(dir, goos string) func(view string) bool {
	return func(view string) bool {
		s, ok := specFor(view)
		if !ok {
			return false
		}
		components := s.componentsFor(goos)
		if len(components) == 0 {
			// Nothing declared means nothing to find. Answering "carried" here would report a
			// disagreement about a view whose presence this function cannot actually observe.
			return false
		}
		for _, c := range components {
			if _, err := os.Stat(filepath.Join(dir, filepath.FromSlash(c))); err != nil {
				return false
			}
		}
		return true
	}
}

// undeclaredButPresentReason states the disagreement the other direction: agent.json does not name
// this view, and the package holds it anyway.
//
// The reason has to say the component is PRESENT, because that is the only thing distinguishing a
// tampered configuration from a legitimately trimmed build, and an operator standing on a customer's
// host is the one who has to tell them apart.
func undeclaredButPresentReason(view, goos string) string {
	have := "its components"
	if s, ok := specFor(view); ok {
		if c := s.componentsFor(goos); len(c) > 0 {
			have = strings.Join(c, ", ")
		}
	}
	return fmt.Sprintf("agent.json does not declare %s, but this package carries %s; a declaration "+
		"that disagrees with what is on disk is not a coverage choice, and reporting it as one would "+
		"let an edited agent.json retire a view that could have run", view, have)
}

func notInBuildReason(view string) string {
	return fmt.Sprintf("%s is not included in this build; agent.json declares which views this "+
		"agent carries", view)
}

// missingComponentReason is the single spelling of "this view's component is not here".
//
// It NAMES the components, from the table, because "java-mem could not run" gives an operator
// standing on a customer's host nothing to act on -- and the table is the only place that knows the
// answer differs by platform: jvmprobe on Linux, a jar plus a host JRE on Windows. The host
// requirement is included for the same reason it is data at all: a missing JRE and a missing jar
// are different repairs.
//
// declared says whether agent.json named this view. Both cases are `failed`, and for the same
// reason -- something that should be in this package is not -- but they are not equally
// diagnosable, so they do not read the same. With a declaration the package is provably broken.
// Without one the scanner cannot tell a build trimmed on purpose from a broken one, and when it
// cannot tell, the loud answer is the only safe one: a reassuring absence here is exactly how a
// broken package becomes a quiet scan.
//
// Deliberately shares no phrase with notInBuildReason. Those two strings are what an operator reads
// to tell a declared absence from a failure, and a reader matching on the wrong half of a shared
// sentence would be reading the opposite of what happened.
func missingComponentReason(s probeSpec, goos string, declared bool) string {
	needs := strings.Join(s.binariesFor(goos), ", ")
	if needs == "" {
		needs = "its component"
	}
	if req := s.HostRequiresOn[goos]; req != "" {
		needs += ", and " + req
	}
	if declared {
		return fmt.Sprintf("agent.json declares %s but this package does not carry %s; a declared "+
			"view whose component is missing is a broken package, not a coverage choice", s.View, needs)
	}
	return fmt.Sprintf("%s was requested but this package does not carry %s; with no agent.json to "+
		"declare the view absent, a component that is missing cannot be told from a build trimmed on "+
		"purpose, so it is reported as the failure it may be", s.View, needs)
}

// defaultViewsFor derives the default capability set for goos from the table. It must never be
// restated as a literal -- that is what let the old const drift from the registry it described.
func defaultViewsFor(goos string) string {
	var out []string
	for _, s := range registryFor(goos) {
		if s.Default {
			out = append(out, s.View)
		}
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}

// defaultViews is the default capability set for the running platform.
var defaultViews = defaultViewsFor(runtime.GOOS)

// exeName applies the platform's executable extension. One definition, in internal/platform, so a
// resolver cannot be fixed here while another keeps the Windows answer.
func exeName(base, goos string) string { return platform.ExeName(base, goos) }

// binPath resolves a spec's executable inside dir for goos.
func (s probeSpec) binPath(dir, goos string) string {
	if s.Bin == "" {
		return ""
	}
	return filepath.Join(dir, exeName(s.Bin, goos))
}

// probeRegistry resolves the capability table into runnable probes for the running platform,
// relative to the shellsight binary.
//
// rulesDirOverride, when non-empty, relocates the whole rule tree -- YARA layers and
// mem-contracts.json alike. Every `rules` subcommand already accepted --rules-dir; scan did not, so
// rules could be managed anywhere but only scanned with from inside bin/, which is exactly what an
// upgrade replaces wholesale. This gives operators a location the installer never touches.
//
// rulesBlob, when non-empty, REPLACES that tree with one compiled rule set (.yarc) -- it does not
// join it. See the disk case below for why replacing rather than adding is the only safe wiring.
func probeRegistry(rulesDirOverride, rulesBlob string) map[string]orchestrator.Probe {
	return probeRegistryIn(exeDir(), runtime.GOOS, rulesDirOverride, rulesBlob)
}

// probeRegistryIn resolves the table inside dir for goos.
//
// Split out from probeRegistry for the same reason registryFor is pure: it lets a test resolve the
// LINUX layout on a Windows host, and assert that nothing in it names a `.exe`.
func probeRegistryIn(dir, goos, rulesDirOverride, rulesBlob string) map[string]orchestrator.Probe {
	rules := filepath.Join(dir, "kb", "rules")
	if rulesDirOverride != "" {
		rules = rulesDirOverride
	}
	yr := filepath.Join(dir, "third_party", "yara-x", exeName("yr", goos))
	artifacts := filepath.Join(dir, "artifacts")
	memContracts := filepath.Join(rules, "mem-contracts.json")

	reg := make(map[string]orchestrator.Probe, len(probeSpecs))
	for _, s := range registryFor(goos) {
		path := s.binPath(dir, goos)
		var args []string

		switch s.View {
		case "disk":
			// A blob REPLACES the tree rather than joining it: diskprobe exits on -rules and
			// -rules-blob together, so passing both here would turn a wiring mistake into a
			// failure at exec time instead of at the point it was made.
			//
			// memContracts keeps resolving from `rules` regardless. mem-contracts.json lives inside
			// the rules DIRECTORY and a memory view needs it whether or not a compiled blob was
			// supplied for this view; resolving it beside the blob would break every memory probe
			// in a disk+memory build.
			if rulesBlob != "" {
				args = []string{"--yr", yr, "--rules-blob", rulesBlob}
			} else {
				args = []string{"--yr", yr, "--rules", rules}
			}
		case "dotnet-mem", "dotnet-mem-x86":
			args = []string{"--artifacts-dir", artifacts, "--mem-contracts", memContracts}
		case "java-mem":
			if goos == "linux" {
				// Native path: no JRE, no jar on the command line. The agent is embedded in the
				// binary and staged into the target's namespace at attach time.
				path = s.binPath(dir, goos)
				args = nil
				break
			}
			java := javaLauncher(dir, goos)
			if java == "" {
				fmt.Fprintln(os.Stderr, "warning: java-mem view unavailable — no JRE found "+
					"(ensure java is on PATH or in JAVA_HOME, or place a jre/ dir beside the binary)")
				continue
			}
			path = java
			args = []string{"--add-modules", "jdk.attach", "-jar", filepath.Join(dir, "javamem.jar"),
				"--artifacts-dir", artifacts, "--force-live-attach", "--mem-contracts", memContracts}
		}

		// Only OPTIONAL companions vanish when absent. A missing required component stays registered
		// so it fails loudly at exec time -- see the Optional field's comment.
		if s.Optional && s.Bin != "" {
			if _, err := os.Stat(path); err != nil {
				continue
			}
		}
		reg[s.View] = orchestrator.Probe{View: s.View, Path: path, Args: args}
	}

	// Test scaffolding, registered only where mockprobe was actually built. It is on the
	// forbidden-release-name list, so this branch is dead in any shipped bundle by construction.
	if mock := filepath.Join(dir, exeName("mockprobe", goos)); fileExists(mock) {
		reg["mock"] = orchestrator.Probe{View: "mock", Path: mock, Args: []string{"emit"}}
		reg["mock-fail"] = orchestrator.Probe{View: "mock-fail", Path: mock, Args: []string{"fail"}}
	}
	return reg
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// javaLauncher resolves the JVM that runs javamem.jar.
// Fallback chain: bundled jre/ -> running JVM -> JAVA_HOME -> PATH.
// Returns "" if no JVM is found (the java-mem view is then simply unavailable; other views still run).
func javaLauncher(dir, goos string) string {
	java := exeName("java", goos)
	// 1) bundled jre beside the binary (if a future kit ever ships one)
	if bundled := filepath.Join(dir, "jre", "bin", java); fileExists(bundled) {
		return bundled
	}
	// 2) the java of a running JVM -- guaranteed compatible with the attach target
	if p := runningJVMJava(); p != "" {
		return p
	}
	// 3) JAVA_HOME
	if jh := os.Getenv("JAVA_HOME"); jh != "" {
		if j := filepath.Join(jh, "bin", java); fileExists(j) {
			return j
		}
	}
	// 4) java on PATH
	if j, err := exec.LookPath(java); err == nil {
		return j
	}
	return ""
}
