package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// What each view NEEDS, declared in the capability table and asserted against what the registry
// actually invokes.
//
// Declared and asserted rather than rewired. probeRegistryIn's `switch s.View` works and is the code
// path every probe is launched through; replacing it with table-driven argument building would be a
// large change to that path for no benefit here. So the table gains explicit component lists and a
// test asserts the two agree -- which is what makes the table the single source of truth (G5)
// without moving the risk into the launcher.
//
// Every path expectation is built with filepath.Join or compared in slash form, never as a `C:\...`
// literal: a host-shaped literal fails on the other platform against a correct implementation, which
// is the test lying about the code rather than the other way round.

func TestEveryViewDeclaresItsBinaries(t *testing.T) {
	// The declaration is what a generator assembles from. A view with no declared binaries would
	// produce an agent missing the thing it was built to run.
	//
	// Asked PER PLATFORM, because that is the only form of the question with an answer: disk and
	// java-mem declare nothing in the all-platform Binaries field -- their executables differ by
	// platform (diskprobe.exe vs diskprobe, a jar vs a native binary) and live in BinariesOn.
	for _, s := range probeSpecs {
		for _, goos := range supportedGOOS {
			if !s.appliesTo(goos) {
				continue
			}
			if len(s.binariesFor(goos)) == 0 {
				t.Errorf("%s applies to %s but declares no binaries there", s.View, goos)
			}
		}
	}
}

func TestDeclaredBinariesMatchWhatTheRegistryInvokes(t *testing.T) {
	// G5: one source of truth. The table declares each view's components; probeRegistryIn's switch
	// decides what is actually passed. This asserts they agree, which is what makes the table
	// authoritative without rewiring the switch. This project has already paid for the
	// alternative: internal/weblang exists because seven places decided a file's language
	// independently and two had silently diverged.
	const agentDir = "AGENT"
	for _, goos := range supportedGOOS {
		reg := probeRegistryIn(agentDir, goos, "", "")
		for _, s := range probeSpecs {
			if !s.appliesTo(goos) {
				continue
			}
			p, ok := reg[s.View]
			if !ok {
				// Optional components vanish when their binary is absent from this dev tree, which
				// is expected and not a declaration problem. What that absence must NOT do is go
				// unreported at scan time -- see the third-state tests in registry_test.go.
				continue
			}
			declared := s.componentsFor(goos)
			for _, arg := range p.Args {
				if !strings.HasPrefix(arg, agentDir) {
					continue // a flag or a literal, not a path into the agent
				}
				rel := strings.TrimPrefix(strings.TrimPrefix(arg, agentDir), string(filepath.Separator))
				rel = filepath.ToSlash(rel)
				// artifacts/ is a runtime OUTPUT directory -- the probes write decompiled classes and
				// dumps into it -- not a component a generator has to stage. A build ships without
				// it and the probe creates it, so declaring it would put a scan's own output in the
				// list of things the package must carry.
				if rel == "artifacts" {
					continue
				}
				if !declaresPath(declared, rel) {
					t.Errorf("%s on %s is invoked with %q but does not declare it: declared=%v",
						s.View, goos, rel, declared)
				}
			}
		}
	}
}

func TestOnlyTheDiskViewNeedsARuleSet(t *testing.T) {
	// Measured: a memory-only agent carries neither yr nor a single YARA rule, so the whole
	// compiled-rule-set architecture is irrelevant to it. The console's form reads this flag to
	// decide whether asking for a rule set means anything.
	//
	// mem-contracts.json is not a counter-example. It lives in the rules DIRECTORY and the memory
	// views declare it as Data, but it is a contract list rather than a YARA rule set: no compiled
	// blob can carry it and -rules-blob does not relocate it (see probeRegistryIn).
	for _, s := range probeSpecs {
		if s.View == "disk" && !s.NeedsRules {
			t.Error("disk does not declare NeedsRules")
		}
		if s.View != "disk" && s.NeedsRules {
			t.Errorf("%s declares NeedsRules; only the disk view scans with YARA", s.View)
		}
	}
}

func TestWindowsJavaMemDeclaresItsHostRequirement(t *testing.T) {
	// registry.go warns and drops the view when no JRE is found. That warning appears on a
	// customer's server; the console has to say it at generate time instead, which means the
	// requirement must be data rather than a message printed at exec time.
	for _, s := range probeSpecs {
		if s.View != "java-mem" {
			continue
		}
		if s.HostRequiresOn["windows"] == "" {
			t.Error("java-mem declares no host requirement on windows, but it runs through " +
				"javamem.jar and needs a JRE on the target")
		}
		if s.HostRequiresOn["linux"] != "" {
			t.Errorf("java-mem declares a host requirement on linux (%q), but the native jvmprobe "+
				"embeds its agent and needs nothing", s.HostRequiresOn["linux"])
		}
	}
}

func TestLinuxJavaMemDeclaresNoContractFile(t *testing.T) {
	// Read from the code rather than copied from the design's table, which says java-mem needs
	// kb/rules/mem-contracts.json on BOTH platforms. cmd/jvmprobe never reads it: its contract set
	// is the compiled-in pipelineContracts map in cmd/jvmprobe/fuse.go, staged to the embedded agent
	// over the handoff in main_linux.go -- which is why probeRegistryIn's Linux branch passes no
	// --mem-contracts at all. The file still ships in the Linux archive for the `rules` subcommands;
	// the VIEW does not depend on it, and declaring otherwise would tell a generator to stage a
	// dependency that is not one.
	for _, s := range probeSpecs {
		if s.View != "java-mem" {
			continue
		}
		for _, d := range s.dataFor("linux") {
			t.Errorf("linux java-mem declares the data file %q; the native probe reads none", d)
		}
	}
}

// declaresPath reports whether rel is covered by a declared component.
//
// Three shapes count, and the third is not slack. An argument may be the declared path itself
// (--mem-contracts kb/rules/mem-contracts.json), a file BENEATH a declared directory, or the
// directory a declared component sits INSIDE: diskprobe is handed the rules root (--rules kb/rules)
// and reads the layers under it, while the declaration names those layers (kb/rules/foundation,
// kb/rules/own) because that is what a generator stages -- a disk-only agent carries no
// mem-contracts.json, the third thing in that directory. Both spellings describe the same tree, so
// neither is drift. An empty rel matches nothing, so an argument naming the agent directory itself
// is still caught.
func declaresPath(declared []string, rel string) bool {
	if rel == "" {
		return false
	}
	for _, d := range declared {
		d = filepath.ToSlash(d)
		if d == rel || strings.HasPrefix(rel, d+"/") || strings.HasPrefix(d, rel+"/") {
			return true
		}
	}
	return false
}

// The document `shellsight components` emits: the declaration a generator assembles an agent from.
//
// Every assertion below reads the table rather than a copy of it. A test that restated the component
// lists would pass while the emitter and the registry disagreed, which is the single failure this
// whole file exists to make impossible (G5).

func TestComponentsDocumentCoversEveryViewForTheTarget(t *testing.T) {
	doc := componentsDoc("linux-amd64", "linux", "v1.0.0-test")
	if doc.SchemaVersion != componentsSchemaVersion {
		t.Errorf("SchemaVersion = %q", doc.SchemaVersion)
	}
	if doc.Target != "linux-amd64" || doc.Release != "v1.0.0-test" {
		t.Errorf("doc = %+v", doc)
	}
	// Every view the platform supports, and nothing it does not.
	for _, s := range probeSpecs {
		_, present := doc.Views[s.View]
		if s.appliesTo("linux") && !present {
			t.Errorf("%s applies to linux but is missing from the document", s.View)
		}
		if !s.appliesTo("linux") && present {
			t.Errorf("%s does not apply to linux but is in the document", s.View)
		}
	}
}

func TestComponentsDocumentCarriesTheRulesFlagAndHostRequirement(t *testing.T) {
	win := componentsDoc("windows-amd64", "windows", "v1")
	if !win.Views["disk"].Rules {
		t.Error("disk does not carry rules=true")
	}
	if win.Views["java-mem"].Rules {
		t.Error("java-mem carries rules=true; a memory view scans with no YARA rules at all")
	}
	if win.Views["java-mem"].HostRequires == "" {
		t.Error("windows java-mem carries no host requirement")
	}
	lin := componentsDoc("linux-amd64", "linux", "v1")
	if lin.Views["java-mem"].HostRequires != "" {
		t.Errorf("linux java-mem carries a host requirement %q; the native probe needs nothing",
			lin.Views["java-mem"].HostRequires)
	}
}

func TestComponentsDocumentAlwaysCarriesTheOrchestrator(t *testing.T) {
	// shellsight itself is in every build regardless of view, so it belongs in `always` rather
	// than being repeated per view -- and a generator that omitted it would produce an agent with
	// nothing to run the probes.
	for _, target := range []struct{ name, goos string }{
		{"windows-amd64", "windows"}, {"linux-amd64", "linux"}, {"linux-arm64", "linux"},
	} {
		doc := componentsDoc(target.name, target.goos, "v1")
		if len(doc.Always) == 0 {
			t.Errorf("%s: Always is empty", target.name)
			continue
		}
		want := "shellsight"
		if target.goos == "windows" {
			want = "shellsight.exe"
		}
		var found bool
		for _, a := range doc.Always {
			if a == want {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: Always = %v, want it to include %q", target.name, doc.Always, want)
		}
	}
}

func TestComponentsDocumentSplitsBinariesFromDataAsTheTableDoes(t *testing.T) {
	// The document keeps the table's OWN split rather than re-deriving it from the path text.
	//
	// Not a stylistic preference. A second classifier -- "anything under kb/ is data" -- is a second
	// opinion about the same fact, and a data file declared anywhere else, or a binary that ever
	// lived under kb/, would be filed under the wrong heading with nothing to catch it. That is the
	// shape of the drift internal/weblang exists because of, and Task 7 split binariesFor from
	// dataFor so this emitter would never have to guess.
	for _, goos := range supportedGOOS {
		doc := componentsDoc(goos+"-amd64", goos, "v1")
		for _, s := range probeSpecs {
			if !s.appliesTo(goos) {
				continue
			}
			view, present := doc.Views[s.View]
			if !present {
				t.Errorf("%s applies to %s but the document has no row for it", s.View, goos)
				continue
			}
			if want := s.binariesFor(goos); !equalStrings(view.Binaries, want) {
				t.Errorf("%s on %s: document binaries %v, table declares %v",
					s.View, goos, view.Binaries, want)
			}
			if want := s.dataFor(goos); !equalStrings(view.Data, want) {
				t.Errorf("%s on %s: document data %v, table declares %v",
					s.View, goos, view.Data, want)
			}
		}
	}
}

func TestComponentsDocumentFilesDataByDeclarationNotByPath(t *testing.T) {
	// A SYNTHETIC row, because the live table cannot tell the two rules apart: every data file it
	// declares sits under kb/ and every binary does not, so "the table's own split" and "anything
	// under kb/ is data" render byte-identical documents today. Measured -- before this test, a
	// mutant that re-derived the split from the path text survived every other test in this file.
	//
	// This row declares a data file that is NOT under kb/, which is the only case where the two
	// disagree, and it is not a hypothetical shape: dotnetmem.exe.config is already a non-executable
	// declared outside kb/, and the ~137 .NET runtime DLLs the table deliberately omits are another.
	spec := probeSpec{
		View:       "synthetic",
		Bin:        "syntheticprobe",
		BinariesOn: map[string][]string{"linux": {"syntheticprobe"}},
		DataOn:     map[string][]string{"linux": {"third_party/synthetic/contracts.dat"}},
	}
	doc := componentsDocFrom([]probeSpec{spec}, "linux-amd64", "linux", "v1")
	view, present := doc.Views["synthetic"]
	if !present {
		t.Fatalf("the synthetic view is missing from the document: %+v", doc.Views)
	}
	if want := []string{"syntheticprobe"}; !equalStrings(view.Binaries, want) {
		t.Errorf("binaries = %v, want %v", view.Binaries, want)
	}
	if want := []string{"third_party/synthetic/contracts.dat"}; !equalStrings(view.Data, want) {
		t.Errorf("data = %v, want %v; a data file outside kb/ was filed by its PATH rather than by "+
			"the field that declares it", view.Data, want)
	}
}

func TestComponentsJSONIsDeterministic(t *testing.T) {
	// The document is a contract another program reads, and packaging verifies the release against
	// the copy it shipped. If map iteration leaked into the output, two renders of one build would
	// disagree about what the archive must contain and that verification would mean nothing.
	//
	// Not "the committed copy would differ": no components.json is tracked (it is staged into bin/
	// and dist/, both gitignored), so there is nothing committed to differ from.
	a, err := componentsJSON("linux-amd64", "linux", "v1")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		b, err := componentsJSON("linux-amd64", "linux", "v1")
		if err != nil {
			t.Fatal(err)
		}
		if string(a) != string(b) {
			t.Fatalf("run %d differs from the first; the output is not deterministic", i)
		}
	}
}

func TestComponentsJSONRoundTrips(t *testing.T) {
	// What this command writes, a parser must read back to the same thing. The console is a Go
	// program too, so this type is the type on both ends -- and this repository has already paid for
	// the alternative once: agentcfg.Choice had an UnmarshalJSON with no MarshalJSON, so a Config
	// marshalled to a shape it could not read back, and nothing noticed until something marshalled
	// one. DisallowUnknownFields makes the check two-way: a field the writer emits and the reader
	// has no home for is a failure here rather than data silently dropped on the floor.
	for _, target := range []struct{ name, goos string }{
		{"windows-amd64", "windows"}, {"linux-amd64", "linux"},
	} {
		raw, err := componentsJSON(target.name, target.goos, "v1")
		if err != nil {
			t.Fatal(err)
		}
		var back componentsDocument
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&back); err != nil {
			t.Fatalf("%s: reading back what we wrote: %v", target.name, err)
		}
		if want := componentsDoc(target.name, target.goos, "v1"); !reflect.DeepEqual(back, want) {
			t.Errorf("%s: the round trip changed the document\n wrote %+v\n read  %+v",
				target.name, want, back)
		}
	}
}

// specExampleSection62 is the components.json example from
// docs/superpowers/specs/2026-09-03-agent-generation-design.md section 6.2, copied verbatim. It is
// the shape the console is written against, so "the emitted document matches the spec" is asserted
// against the spec's own text rather than against this package's idea of it -- including the ORDER
// of each list, which is the table's declaration order and not sorted.
//
// It is ABRIDGED: windows carries six views, not two. So the two rows it documents are compared
// exactly and the others only have to exist. The one row that does not generalise is Linux
// java-mem, which carries no data at all -- the spec says so in the note beneath this block, and
// TestLinuxJavaMemDeclaresNoContractFile covers it.
const specExampleSection62 = `{
  "schema_version": "1",
  "target": "windows-amd64",
  "release": "v1.0.0-384-gd4bcc6b",
  "always": ["shellsight.exe"],
  "views": {
    "disk":     { "binaries": ["diskprobe.exe", "third_party/yara-x/yr.exe"],
                  "data": ["kb/rules/foundation", "kb/rules/own"],
                  "rules": true },
    "java-mem": { "binaries": ["javamem.jar", "javamem-agent.jar"],
                  "data": ["kb/rules/mem-contracts.json"],
                  "rules": false,
                  "host_requires": "a Java runtime on the target host" }
  }
}`

func TestComponentsJSONMatchesTheDocumentedShape(t *testing.T) {
	var want, got map[string]any
	if err := json.Unmarshal([]byte(specExampleSection62), &want); err != nil {
		t.Fatal(err)
	}
	raw, err := componentsJSON("windows-amd64", "windows", "v1.0.0-384-gd4bcc6b")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"schema_version", "target", "release", "always"} {
		if !reflect.DeepEqual(want[field], got[field]) {
			t.Errorf("%s: spec has %#v, emitted %#v", field, want[field], got[field])
		}
	}
	if !equalStrings(sortedKeys(want), sortedKeys(got)) {
		t.Errorf("top-level fields: spec has %v, emitted %v", sortedKeys(want), sortedKeys(got))
	}
	wantViews, ok := want["views"].(map[string]any)
	if !ok {
		t.Fatalf("the spec example's views is %T, not an object", want["views"])
	}
	gotViews, ok := got["views"].(map[string]any)
	if !ok {
		t.Fatalf("the emitted views is %T, not an object", got["views"])
	}
	for view, row := range wantViews {
		emitted, present := gotViews[view]
		if !present {
			t.Errorf("the spec documents a %q row; the emitted document has no such view", view)
			continue
		}
		if !reflect.DeepEqual(row, emitted) {
			t.Errorf("%s row:\n spec    %#v\n emitted %#v", view, row, emitted)
		}
	}
}

func TestComponentsConfigRefusesAnIncompleteOrInconsistentTarget(t *testing.T) {
	// -target and -goos are two spellings of one fact, and nothing downstream can tell when they
	// disagree: the document would be LABELLED windows-amd64 while holding Linux components, and a
	// console that picks components by target name would assemble an agent out of the other
	// platform's files. Caught here, where both values are still in the same place.
	for name, args := range map[string][]string{
		"no target":       {"-goos", "linux", "-release", "v1"},
		"no goos":         {"-target", "linux-amd64", "-release", "v1"},
		"no release":      {"-target", "linux-amd64", "-goos", "linux"},
		"unknown goos":    {"-target", "darwin-amd64", "-goos", "darwin", "-release", "v1"},
		"target mismatch": {"-target", "windows-amd64", "-goos", "linux", "-release", "v1"},
	} {
		if _, err := parseComponentsConfig(args); err == nil {
			t.Errorf("%s: accepted %v", name, args)
		}
	}
	cfg, err := parseComponentsConfig([]string{"-target", "linux-arm64", "-goos", "linux", "-release", "v1"})
	if err != nil {
		t.Fatalf("a well-formed invocation was refused: %v", err)
	}
	if cfg.Target != "linux-arm64" || cfg.GOOS != "linux" || cfg.Release != "v1" {
		t.Errorf("cfg = %+v", cfg)
	}
}

func TestComponentsWritesTheFileItIsPointedAt(t *testing.T) {
	out := filepath.Join(t.TempDir(), "components.json")
	if err := runComponents(componentsConfig{
		Target: "linux-amd64", GOOS: "linux", Release: "v1", Out: out,
	}); err != nil {
		t.Fatal(err)
	}
	written, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	want, err := componentsJSON("linux-amd64", "linux", "v1")
	if err != nil {
		t.Fatal(err)
	}
	if string(written) != string(want) {
		t.Errorf("the file on disk is not what the renderer produced\n file %s\n want %s", written, want)
	}
	if !strings.HasSuffix(string(written), "\n") {
		t.Error("the file does not end in a newline; it is committed to a repository and diffed")
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func sortedKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ------------------------------------------------------------------------------------------------
// The declaration versus what the release actually holds.
//
// componentsDoc is pure and renders every view the table declares for a platform, OPTIONAL ones
// included -- so java-mem and dotnet-mem-x86 are in every document for their platform whether or not
// the build that carried it produced them. Nothing above this line can notice. These tests cover the
// half that can: the document read back out of a release and checked against the release.
// ------------------------------------------------------------------------------------------------

func TestPackageScriptEmitsAndVerifiesTheDeclaration(t *testing.T) {
	// A release whose archive lacks components.json cannot be generated from: the console reads it to
	// know what each view needs. And one that carries a document nobody checked is worse than none --
	// it is a promise, in writing, that the archive holds files it may not.
	//
	// Asserted against the script's TEXT because packaging is a bash script that needs a populated
	// SHELLSIGHT_PREBUILT_DIR, a real cross-compile and PowerShell to run; a Go test that shelled out
	// to it would either be an integration test inside a unit suite or -- worse, and this repo has
	// the case on record -- a skip that still reports ok. The behaviour the script drives is covered
	// below, against the same code path it invokes.
	body, err := os.ReadFile(filepath.Join("..", "..", "scripts", "package.sh"))
	if err != nil {
		t.Fatalf("reading package.sh: %v", err)
	}
	src := string(body)

	if !strings.Contains(src, componentsManifestName) {
		t.Fatalf("package.sh never mentions %s; a release would ship without the declaration",
			componentsManifestName)
	}
	for _, literal := range []string{
		"-out \"$BIN/" + componentsManifestName + "\"",
		"./cmd/shellsight components",
		"components -verify",
		"verify_release_declaration \"$VERIFY_DIR\"",
	} {
		if !strings.Contains(src, literal) {
			t.Errorf("package.sh does not %q; the declaration is not emitted from the table and checked against the archive", literal)
		}
	}

	// One populated REQUIRED_ARCHIVE per target, and both must name it -- that list is what the
	// extract-and-re-verify pass reads, so a file absent from it is a file nothing confirms shipped.
	populated := 0
	for rest := src; ; {
		opened := strings.Index(rest, "REQUIRED_ARCHIVE=(")
		if opened < 0 {
			break
		}
		rest = rest[opened+len("REQUIRED_ARCHIVE=("):]
		closed := strings.Index(rest, ")")
		if closed < 0 {
			t.Fatal("unterminated REQUIRED_ARCHIVE array in package.sh")
		}
		block := rest[:closed]
		rest = rest[closed:]
		if strings.TrimSpace(block) == "" {
			continue // the `declare -a REQUIRED_ARCHIVE=()` up top, not a target's list
		}
		populated++
		if !strings.Contains(block, componentsManifestName) {
			t.Errorf("REQUIRED_ARCHIVE list %d does not require %s:%s", populated, componentsManifestName, block)
		}
	}
	if populated != len(supportedGOOS) {
		t.Errorf("found %d populated REQUIRED_ARCHIVE lists; one per target, so %d expected",
			populated, len(supportedGOOS))
	}

	// Order is the whole gate. Emitting after the archive is built ships an archive without it;
	// checking after bin/ is replaced installs the release and then complains about it.
	emit := strings.Index(src, "-out \"$BIN/"+componentsManifestName+"\"")
	archive := strings.Index(src, "Compress-Archive")
	verify := strings.Index(src, "verify_release_declaration \"$VERIFY_DIR\"")
	extract := strings.Index(src, "Expand-Archive")
	install := strings.Index(src, "mv \"$BIN\" \"$FINAL_BIN\"")
	if emit < 0 || archive < 0 || verify < 0 || extract < 0 || install < 0 {
		t.Fatal("package.sh is missing one of emit / archive / verify / extract / install")
	}
	if emit > archive {
		t.Error("the declaration is emitted after the archive is created; it would not be in it")
	}
	if verify < extract {
		t.Error("the declaration is checked before extraction, so it is not checking the archive")
	}
	if verify > install {
		t.Error("the declaration is checked after bin/ is replaced; the release is already installed")
	}
}

func TestReleaseVerificationFailsWhenADeclaredComponentIsAbsent(t *testing.T) {
	// The requirement, on the real table: take the document a Windows release carries, build the tree
	// it describes, remove one file, and packaging must refuse.
	doc := componentsDoc("windows-amd64", "windows", "v1")
	root := t.TempDir()
	materialiseDeclaration(t, root, doc)
	if err := verifyComponents(doc, root); err != nil {
		t.Fatalf("a tree holding everything the document declares was rejected: %v", err)
	}

	// dotnet-mem-x86 is the live case: Optional, declared unconditionally, and built only on a
	// NuGet-enabled box.
	absent := doc.Views["dotnet-mem-x86"].Binaries[0]
	if err := os.Remove(filepath.Join(root, filepath.FromSlash(absent))); err != nil {
		t.Fatal(err)
	}
	err := verifyComponents(doc, root)
	if err == nil {
		t.Fatalf("a release missing %s was certified as complete", absent)
	}
	if !strings.Contains(err.Error(), absent) {
		t.Errorf("the failure does not name the missing component %q: %v", absent, err)
	}
	if !strings.Contains(err.Error(), "dotnet-mem-x86") {
		t.Errorf("the failure does not name the view that would be generated broken: %v", err)
	}
}

func TestReleaseVerificationReadsTheDocumentAndNotTheTable(t *testing.T) {
	// The discriminator, and the reason this reads the shipped document instead of walking probeSpecs
	// a second time. Task 8's surviving mutant was a redundant classifier that agreed with the real
	// one on every value the table happens to hold today; a second derivation here would agree with
	// componentsDoc by construction and could never disagree with it about a file. Neither document
	// below is one the table would produce, so only a reader of the document passes both halves.
	root := t.TempDir()

	invented := componentsDocument{
		SchemaVersion: componentsSchemaVersion,
		Always:        []string{"invented-orchestrator.bin"},
		Views: map[string]componentsView{
			"nowhere": {Binaries: []string{"invented/component.bin"}},
		},
	}
	err := verifyComponents(invented, root)
	if err == nil {
		t.Fatal("a document declaring components no table knows was certified against an empty tree")
	}
	for _, want := range []string{"invented-orchestrator.bin", "invented/component.bin"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the failure does not name %q, so it is not reading the document: %v", want, err)
		}
	}

	// The converse, and the half a table-derived check cannot pass: a document that declares LESS
	// than the table must be satisfied by a tree holding only what it declares. diskprobe.exe is
	// absent here and must not be complained about, because this document does not promise it.
	writeDeclaredFile(t, root, "only-this.txt")
	spare := componentsDocument{
		SchemaVersion: componentsSchemaVersion,
		Always:        []string{"only-this.txt"},
	}
	if err := verifyComponents(spare, root); err != nil {
		t.Errorf("a tree holding everything its own document declares was rejected: %v", err)
	}
}

func TestReleaseVerificationRejectsAnEmptyDeclaredDirectory(t *testing.T) {
	// kb/rules/foundation holding no rules is still a declaration that this agent carries a rule
	// tree, and it is the stricter question for a Windows release: Compress-Archive writes no entry
	// at all for a directory with no files under it, so an empty declared directory does not reach
	// the responder.
	root := t.TempDir()
	doc := componentsDocument{
		SchemaVersion: componentsSchemaVersion,
		Views:         map[string]componentsView{"disk": {Data: []string{"kb/rules/foundation"}}},
	}
	if err := os.MkdirAll(filepath.Join(root, "kb", "rules", "foundation"), 0o755); err != nil {
		t.Fatal(err)
	}
	err := verifyComponents(doc, root)
	if err == nil {
		t.Fatal("an empty declared rule tree was certified as present")
	}
	if !strings.Contains(err.Error(), "empty") {
		t.Errorf("the failure does not say the declared directory is empty: %v", err)
	}
	writeDeclaredFile(t, root, "kb/rules/foundation/a.yar")
	if err := verifyComponents(doc, root); err != nil {
		t.Errorf("a populated rule tree was rejected: %v", err)
	}
}

func TestReleaseVerificationWillNotLookOutsideTheRelease(t *testing.T) {
	// A declared path that escapes the tree would be answered by a file the archive does not carry,
	// which is the one answer this check exists to make impossible.
	outer := t.TempDir()
	root := filepath.Join(outer, "release")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	writeDeclaredFile(t, outer, "yr.exe") // beside the release, not in it
	escapes := []string{"../yr.exe", "third_party/../../yr.exe", "/yr.exe", "", "./yr.exe", "..\\yr.exe"}
	for _, declared := range escapes {
		doc := componentsDocument{
			SchemaVersion: componentsSchemaVersion,
			Views:         map[string]componentsView{"disk": {Binaries: []string{declared}}},
		}
		if err := verifyComponents(doc, root); err == nil {
			t.Errorf("%q was accepted as a component of the release", declared)
		}
	}
}

func TestReleaseVerificationRefusesADocumentItCannotTrust(t *testing.T) {
	// Every tree below actually HOLDS shellsight.exe, and that is the point. The first version of
	// this test built the trees empty, so removing the schema check changed nothing: the document was
	// still rejected, just for a missing component instead. It survived the mutation round. A case
	// whose only remaining reason to fail is the property under test is the only kind that evidences
	// it.
	for name, content := range map[string]string{
		"not json":         "{",
		"another schema":   "{\"schema_version\":\"99\",\"always\":[\"shellsight.exe\"]}",
		"declares nothing": "{\"schema_version\":\"" + componentsSchemaVersion + "\"}",
	} {
		root := t.TempDir()
		writeDeclaredFile(t, root, "shellsight.exe")
		if err := os.WriteFile(filepath.Join(root, componentsManifestName), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := verifyComponentsTree(root); err == nil {
			t.Errorf("%s: a release carrying %s was certified", name, content)
		}
	}
	// And a release with no declaration at all is not silently fine.
	if err := verifyComponentsTree(t.TempDir()); err == nil {
		t.Error("a release carrying no declaration at all was certified")
	}
}

func TestComponentsVerifyIsExclusiveOfRendering(t *testing.T) {
	// -verify reads a document out of a tree; the render flags write one. An invocation carrying both
	// reads as though the rendered document had been checked, when what was checked is whatever the
	// tree already held.
	for name, args := range map[string][]string{
		"verify with a target":  {"-verify", "rel", "-target", "windows-amd64"},
		"verify with a goos":    {"-verify", "rel", "-goos", "windows"},
		"verify with a release": {"-verify", "rel", "-release", "v1"},
		"verify with an out":    {"-verify", "rel", "-out", "x.json"},
	} {
		if _, err := parseComponentsConfig(args); err == nil {
			t.Errorf("%s: accepted %v", name, args)
		}
	}
	cfg, err := parseComponentsConfig([]string{"-verify", "rel"})
	if err != nil {
		t.Fatalf("-verify alone was refused: %v", err)
	}
	if cfg.Verify != "rel" {
		t.Errorf("cfg = %+v", cfg)
	}
}

func TestComponentsCommandVerifiesAnUnpackedRelease(t *testing.T) {
	// End to end through the exact CLI path package.sh drives: render into a tree, then check the
	// tree against the document it now carries. Exit codes, not just errors -- the script reads those.
	root := t.TempDir()
	if code := runComponentsCmd([]string{
		"-target", "linux-amd64", "-goos", "linux", "-release", "v1",
		"-out", filepath.Join(root, componentsManifestName),
	}); code != 0 {
		t.Fatalf("rendering exited %d", code)
	}
	if code := runComponentsCmd([]string{"-verify", root}); code == 0 {
		t.Fatal("a tree holding only the declaration was certified as a complete release")
	}
	materialiseDeclaration(t, root, componentsDoc("linux-amd64", "linux", "v1"))
	if code := runComponentsCmd([]string{"-verify", root}); code != 0 {
		t.Fatalf("a complete release was rejected, exit %d", code)
	}
}

// materialiseDeclaration creates every path a document declares, as a regular file.
//
// A file rather than a directory even for kb/rules/foundation, deliberately: the document does not
// say which of its entries are trees and the check does not require it to. What it asserts is that
// something is there, with a directory additionally having to be non-empty.
func materialiseDeclaration(t *testing.T, root string, doc componentsDocument) {
	t.Helper()
	for _, rel := range doc.Always {
		writeDeclaredFile(t, root, rel)
	}
	for _, view := range doc.Views {
		for _, rel := range append(append([]string{}, view.Binaries...), view.Data...) {
			writeDeclaredFile(t, root, rel)
		}
	}
}

func writeDeclaredFile(t *testing.T, root, rel string) {
	t.Helper()
	full := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte("staged\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}
