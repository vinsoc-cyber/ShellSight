package main

// components.json -- the declaration a generator assembles an agent from.
//
// WHY IT IS EMITTED RATHER THAN ASKED FOR
//
// A console that wanted this could not simply run the binary and ask. It runs on one platform and
// must build agents for three, and it cannot execute a linux-arm64 binary to interrogate it. So the
// declaration is rendered at PACKAGE time, once per target, and carried in the release.
//
// WHY IT IS EMITTED FROM probeSpecs
//
// G5 of the agent-generation design: the generator must not keep its own list. This project has
// already paid for the alternative -- internal/weblang exists because seven places decided a file's
// language independently and two had silently diverged. Every value below is read from the table; a
// component that is not declared there cannot appear here, and one that is cannot be forgotten.
//
// Pure, like registryFor: no filesystem access and no environment reads, so the linux-arm64 document
// is rendered and asserted from a Windows development host.

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// componentsSchemaVersion is the format the console reads. Bump it only when a consumer would
// misinterpret the old shape.
const componentsSchemaVersion = "1"

// componentsManifestName is the file the declaration is carried as -- in the release archive, and
// in an unpacked copy of one.
const componentsManifestName = "components.json"

// componentsView is what one view needs in a generated agent.
type componentsView struct {
	Binaries []string `json:"binaries,omitempty"`
	Data     []string `json:"data,omitempty"`
	// Rules reports whether this view scans with YARA. Only disk does, so a memory-only agent
	// carries neither yr nor a single rule, and a console form asking it for a rule set would be
	// asking a question with no meaning.
	//
	// No omitempty, deliberately. `"rules": false` is in the spec's documented shape, and a consumer
	// that must distinguish "this view needs no rules" from "this document predates the field"
	// cannot do it from an absence.
	Rules bool `json:"rules"`
	// HostRequires states what the TARGET host must already have. Empty for everything
	// self-contained, and omitted rather than emitted empty: the string is prose meant to be shown
	// to an analyst, and an empty one is not a requirement worth rendering.
	HostRequires string `json:"host_requires,omitempty"`
}

// componentsDocument is what a generator reads to assemble an agent.
type componentsDocument struct {
	SchemaVersion string                    `json:"schema_version"`
	Target        string                    `json:"target"`
	Release       string                    `json:"release"`
	Always        []string                  `json:"always"`
	Views         map[string]componentsView `json:"views"`
}

// componentsDoc builds the document for one target.
//
// target is the release's own name for the platform+architecture pair (windows-amd64, linux-arm64);
// goos is what the table is keyed by. Architecture never reaches the table because no component
// list differs by it -- linux-amd64 and linux-arm64 carry the same file NAMES, built for different
// machines -- so the two arguments are not redundant: one labels the document, the other selects
// its contents. parseComponentsConfig refuses a pair that disagrees.
func componentsDoc(target, goos, release string) componentsDocument {
	return componentsDocFrom(probeSpecs, target, goos, release)
}

// componentsDocFrom is componentsDoc over an arbitrary table.
//
// The seam registryForSpecs and naProbeForSpecs exist for, and for the same reason: a mechanism that
// can only be exercised against the live table can only be tested on the values that table happens
// to hold today. Measured while building this -- a mutant that re-derived the binary/data split from
// the path text ("anything under kb/ is data", which is what the plan's snippet did) passed every
// other test in this package, because every data file the table currently declares IS under kb/ and
// every binary is not. The two rules agree on today's values and would disagree on tomorrow's; only
// a synthetic row can tell them apart.
func componentsDocFrom(specs []probeSpec, target, goos, release string) componentsDocument {
	doc := componentsDocument{
		SchemaVersion: componentsSchemaVersion,
		Target:        target,
		Release:       release,
		// shellsight itself is in every build regardless of view, so it is stated once here rather
		// than repeated in every row. A generator that omitted it would produce an agent with
		// nothing to run the probes.
		Always: []string{exeName("shellsight", goos)},
		Views:  map[string]componentsView{},
	}
	for _, s := range registryForSpecs(specs, goos) {
		doc.Views[s.View] = componentsView{
			// The table's own split, not a second opinion derived from the path text. Task 7
			// separated binariesFor from dataFor for exactly this call site; re-deriving the
			// division here -- "anything under kb/ is data" -- would be a classifier that can
			// disagree with the declaration it is reading, which is the drift G5 exists to prevent.
			//
			// Declaration order, not sorted. It is already deterministic (a slice, never a map
			// iteration), it is what the spec's documented example shows, and it is meaningful:
			// each view's own executable comes before the things it loads.
			Binaries:     nilIfEmpty(s.binariesFor(goos)),
			Data:         nilIfEmpty(s.dataFor(goos)),
			Rules:        s.NeedsRules,
			HostRequires: s.HostRequiresOn[goos],
		}
	}
	return doc
}

// nilIfEmpty collapses an empty list to nil.
//
// Found by the round-trip test, not by reading the code. binariesFor and dataFor always allocate, so
// a view with no data carries []string{}; omitempty renders that as an absent field, and a parser
// reads the absence back as nil. Identical JSON, two different Go values -- so a consumer that
// compared the document it parsed against one it built would see a difference that is not there.
// The writer's value is made to equal the reader's, rather than the comparison being taught to
// forgive it.
func nilIfEmpty(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	return s
}

// componentsJSON renders the document.
//
// Deterministic: encoding/json sorts map keys, and every slice comes from the table in declaration
// order, so nothing here can vary between two runs of the same build. A test renders it twenty
// times and compares.
//
// That matters because the document is a CONTRACT another program reads, and because packaging
// verifies the release against the copy it shipped: a rendering that churned would let two runs of
// the same build disagree about what the archive must contain, and the verification would be
// checking the archive against a coin flip.
//
// It is NOT because a copy is committed. Nothing named components.json is tracked -- it is staged
// into bin/ and dist/, both gitignored (.gitignore:16 and :85) -- so there is no committed artefact
// to diff against and no freshness gate of the bundle's shape.
func componentsJSON(target, goos, release string) ([]byte, error) {
	b, err := json.MarshalIndent(componentsDoc(target, goos, release), "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// ---------------------------------------------------------------------------------------------
// The other half: does the release actually CONTAIN what its declaration promises.
//
// componentsDoc above is pure and knows nothing about any filesystem, which is what lets a
// linux-arm64 document be rendered on this Windows box -- and is also exactly why it cannot answer
// this question. It renders every view the table declares for a platform, including the OPTIONAL
// ones, so java-mem and dotnet-mem-x86 appear in every document for their platform whether or not
// the build that carried it produced them. A release assembled on a box with no .NET toolchain
// would ship a declaration promising a dotnetmem-x86.exe the archive does not hold, and the console
// would generate an agent that cannot run a view it was told it had.
//
// So the declaration is checked against the tree it ships in, at package time, and a disagreement
// fails the packaging rather than reaching a responder.
// ---------------------------------------------------------------------------------------------

// verifyComponents reports every component the document declares that root does not carry.
//
// It reads the DOCUMENT, never probeSpecs, and that is the whole design.
//
// This is the only thing standing between what a release SAYS and what it HOLDS, so it must not be
// a second derivation of the table componentsDoc renders from. Two derivations of one table agree
// by construction -- they would agree cheerfully about a file that neither of them can see. Task 8
// measured that failure exactly: a redundant "anything under kb/ is data" classifier passed every
// test in this package because it happened to agree with the real split on today's values.
//
// The input here is therefore the DOCUMENT AS SHIPPED, parsed back off disk, and the question asked
// of it is one no amount of reading the table can answer: is the file there. A view the table
// gained yesterday and a view it lost are both handled without this function knowing about either.
func verifyComponents(doc componentsDocument, root string) error {
	var problems []string
	check := func(owner, declared string) {
		if problem := componentProblem(root, declared); problem != "" {
			problems = append(problems, owner+": "+problem)
		}
	}
	for _, binary := range doc.Always {
		check("always", binary)
	}
	// Sorted, and here it earns it -- unlike the slices inside a row, doc.Views is a MAP, so an
	// unsorted walk would name the same set of missing components in a different order every run and
	// two identical failures would not diff.
	views := make([]string, 0, len(doc.Views))
	for view := range doc.Views {
		views = append(views, view)
	}
	sort.Strings(views)
	for _, view := range views {
		row := doc.Views[view]
		for _, binary := range row.Binaries {
			check(view, binary)
		}
		for _, data := range row.Data {
			check(view, data)
		}
	}
	if len(problems) == 0 {
		return nil
	}
	// Every problem, not the first. A build host missing a whole toolchain is short several
	// components at once, and reporting them one packaging run at a time is a slow way to learn it.
	return fmt.Errorf("%s promises %d component(s) this release does not carry:\n  %s",
		componentsManifestName, len(problems), strings.Join(problems, "\n  "))
}

// componentProblem says why root does not satisfy a declared path, or returns "" when it does.
func componentProblem(root, declared string) string {
	if declared == "" {
		return "an empty path is declared"
	}
	// A declared component is a slash-relative path INSIDE the release. Refusing anything else is
	// not fastidiousness about our own output: filepath.Join(root, "../yr.exe") would stat a file
	// outside the release and report a component present that the archive does not carry, which is
	// the single answer this check exists to make impossible.
	if strings.ContainsRune(declared, '\\') || filepath.IsAbs(declared) {
		return declared + " is not a relative path inside the release"
	}
	for _, segment := range strings.Split(declared, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return declared + " is not a relative path inside the release"
		}
	}
	full := filepath.Join(root, filepath.FromSlash(declared))
	info, err := os.Stat(full)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return declared + " is declared and absent"
	case err != nil:
		return declared + " cannot be examined: " + err.Error()
	case !info.IsDir():
		return ""
	}
	// A declared directory with nothing in it is the same lie as an absent one: kb/rules/foundation
	// holding no rules is still a declaration that this agent carries a rule tree. It is also the
	// stricter question for a Windows release -- Compress-Archive writes no entry at all for a
	// directory with no files beneath it, so an empty declared directory does not survive into the
	// zip a responder unpacks.
	entries, err := os.ReadDir(full)
	if err != nil {
		return declared + " cannot be examined: " + err.Error()
	}
	if len(entries) == 0 {
		return declared + " is declared and empty"
	}
	return ""
}

// verifyComponentsTree checks an unpacked release against the declaration it carries.
//
// The document is READ FROM THE TREE, never re-rendered for it. Re-rendering would answer a
// different question -- whether this source tree's table agrees with that directory -- and would
// leave the one file a responder actually receives, the components.json inside the archive,
// unexamined. It also means an analyst can point this at an unpacked release and get the same
// answer packaging got.
func verifyComponentsTree(root string) error {
	manifest := filepath.Join(root, componentsManifestName)
	raw, err := os.ReadFile(manifest)
	if err != nil {
		return fmt.Errorf("reading the release declaration: %w", err)
	}
	var doc componentsDocument
	if err := json.Unmarshal(raw, &doc); err != nil {
		return fmt.Errorf("%s is not a component declaration: %w", componentsManifestName, err)
	}
	if doc.SchemaVersion != componentsSchemaVersion {
		return fmt.Errorf("%s declares schema_version %q; this build reads %q",
			componentsManifestName, doc.SchemaVersion, componentsSchemaVersion)
	}
	// A document that declares nothing passes every per-component check there is, because there is
	// nothing to check -- so an empty one would certify a release holding no components at all.
	if len(doc.Always) == 0 && len(doc.Views) == 0 {
		return fmt.Errorf("%s declares no components at all", componentsManifestName)
	}
	return verifyComponents(doc, root)
}

type componentsConfig struct {
	Target  string
	GOOS    string
	Release string
	Out     string
	// Verify names an unpacked release to CHECK rather than a target to render. Two modes of one
	// subcommand because they are two halves of one contract, and packaging performs both: it
	// renders the declaration into the stage, and after the archive has been built and extracted it
	// asks whether the thing it is about to ship agrees with the document inside it.
	Verify string
}

const componentsUsage = "usage: shellsight components -target <os-arch> -goos <windows|linux> " +
	"-release <version> [-out <file>]\n" +
	"       shellsight components -verify <unpacked release directory>"

func parseComponentsConfig(args []string) (componentsConfig, error) {
	var cfg componentsConfig
	fs := flag.NewFlagSet("components", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&cfg.Target, "target", "", "release target, e.g. windows-amd64 (required)")
	fs.StringVar(&cfg.GOOS, "goos", "", "the target's GOOS: windows or linux (required)")
	fs.StringVar(&cfg.Release, "release", "", "release version string (required)")
	fs.StringVar(&cfg.Out, "out", "", "write here instead of stdout")
	fs.StringVar(&cfg.Verify, "verify", "",
		"check an unpacked release against the "+componentsManifestName+" it carries")
	if err := fs.Parse(args); err != nil {
		return cfg, err
	}
	if cfg.Verify != "" {
		// Exclusive, and not for tidiness. -verify READS a document out of a tree; -target/-goos/
		// -release/-out RENDER one. An invocation carrying both reads as though the rendered
		// document had been checked, when what was checked is whatever the tree already held.
		if cfg.Target != "" || cfg.GOOS != "" || cfg.Release != "" || cfg.Out != "" {
			return cfg, fmt.Errorf("-verify takes no other flags: it reads the %s the tree already "+
				"carries rather than rendering one", componentsManifestName)
		}
		return cfg, nil
	}
	switch {
	case cfg.Target == "":
		return cfg, fmt.Errorf("-target is required")
	case cfg.GOOS != "windows" && cfg.GOOS != "linux":
		return cfg, fmt.Errorf("-goos must be windows or linux, got %q", cfg.GOOS)
	case cfg.Release == "":
		return cfg, fmt.Errorf("-release is required")
	case !strings.HasPrefix(cfg.Target, cfg.GOOS+"-"):
		// The two name one platform, and nothing downstream can tell when they disagree: the
		// document would be LABELLED windows-amd64 and hold Linux components, and a console picking
		// components by target name would assemble an agent out of the other platform's files.
		return cfg, fmt.Errorf("-target %q does not name the -goos %q it was rendered for; a "+
			"document labelled for one platform carrying another's components cannot be detected "+
			"by anything that reads it", cfg.Target, cfg.GOOS)
	}
	return cfg, nil
}

// runComponents emits the component declaration for one target, or verifies one already emitted.
func runComponents(cfg componentsConfig) error {
	if cfg.Verify != "" {
		return verifyComponentsTree(cfg.Verify)
	}
	b, err := componentsJSON(cfg.Target, cfg.GOOS, cfg.Release)
	if err != nil {
		return err
	}
	if cfg.Out == "" {
		_, err = os.Stdout.Write(b)
		return err
	}
	return os.WriteFile(cfg.Out, b, 0o644)
}

// runComponentsCmd is the subcommand entry point. It returns the exit code rather than calling
// os.Exit, the same shape runScan uses, so the dispatch in main stays a one-liner.
//
// 2 for a usage error -- the flag package's own convention, and what `scan` produces for one through
// flag.ExitOnError -- and 1 for a failure to render or write. Never one of the scan verdict codes
// (0 and 2-5 mean something specific about a host that was examined); this command examines nothing.
func runComponentsCmd(args []string) int {
	cfg, err := parseComponentsConfig(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "shellsight components: %v\n%s\n", err, componentsUsage)
		return 2
	}
	if err := runComponents(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "shellsight components: %v\n", err)
		return 1
	}
	return 0
}
