package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"shellsight/internal/finding"
	"shellsight/internal/javadisk"
)

func TestFindingSurfacesRuleAuthor(t *testing.T) {
	r := yaraxRuleMatch{Identifier: "webshell_x", Meta: map[string]string{"author": "Florian Roth", "score": "80"}}
	f := findingFromRule(`C:\web\x.php`, "deadbeefdeadbeef", r, "WEB01")
	if f.Context["rule_author"] != "Florian Roth" {
		t.Fatalf("DRL attribution: Context[rule_author] must name the author, got %q", f.Context["rule_author"])
	}
	// Author must NOT be in evidence — evidence is in the dedup fingerprint, so author churn there
	// would break cross-rescan suppression (F9).
	if strings.Contains(f.Detection.Evidence, "Florian Roth") {
		t.Fatalf("author must not be in evidence (dedup stability), got %q", f.Detection.Evidence)
	}
}

func TestJavaDiskSemanticRunsWhenDeobfDisabled(t *testing.T) {
	yr := yrPath()
	if yr == "" {
		t.Skip("yr binary not found")
	}
	root := t.TempDir()
	jsp := filepath.Join(root, "semantic.jsp")
	if err := os.WriteFile(jsp, []byte(`<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>`), 0o600); err != nil {
		t.Fatal(err)
	}
	spec, err := json.Marshal(finding.TargetSpec{Host: "host", Webroots: []string{root}})
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := runDiskProbe(context.Background(), []string{"--yr", yr, "--rules", rulesDir(), "--deobf=false"}, bytes.NewReader(spec), &stdout, &stderr)
	if code != exitOK {
		if strings.Contains(stderr.String(), "yr on") {
			t.Skip("yr scan blocked (AV/OS) on temp files - covered by cmd/measure")
		}
		t.Fatalf("runDiskProbe exit=%d stderr=%s", code, stderr.String())
	}
	var output finding.ProbeOutput
	if err := json.Unmarshal(stdout.Bytes(), &output); err != nil {
		t.Fatal(err)
	}
	if findingForRule(output.Findings, "javadisk:request-exec") == nil {
		t.Fatalf("--deobf=false suppressed Java semantics: %+v", output)
	}
}

func TestFindingFromRuleWithMetaFamily(t *testing.T) {
	r := yaraxRuleMatch{
		Identifier: "test_rule",
		Meta: map[string]string{
			"family": "Behinder",
			"score":  "90",
		},
	}
	f := findingFromRule("/tmp/shell.php", "abc123", r, "testhost")
	if f.Classification.Family == nil || *f.Classification.Family != "Behinder" {
		t.Errorf("expected Classification.Family=Behinder, got %v", f.Classification.Family)
	}
	if f.Score != 90 {
		t.Errorf("expected Score=90 from meta.score, got %d", f.Score)
	}
	if f.Tier != finding.TierConfirmed {
		t.Errorf("expected TierConfirmed for score 90, got %v", f.Tier)
	}
}

// A `reference` meta is provenance, not identity. It used to overwrite KnowledgeRef, which
// destroyed the rule name for 88.6% of shipped rules and collapsed 2,773 of them onto 215
// shared strings — so an analyst read "Internal Research" instead of a rule they could look
// up, and dedupByOriginRule (which keys on the ref) merged independent rules into one finding.
func TestFindingFromRuleKeepsIdentityWhenReferenceMetaPresent(t *testing.T) {
	r := yaraxRuleMatch{
		Identifier: "ditekshen_webshell_x",
		Meta: map[string]string{
			"reference": "https://github.com/ditekshen/detection",
			"author":    "ditekSHen",
			"score":     "75",
		},
	}
	f := findingFromRule("/tmp/shell.php", "abc123", r, "testhost")
	if f.Detection.KnowledgeRef != "kb:yara/ditekshen_webshell_x" {
		t.Errorf("reference meta overwrote rule identity: got KnowledgeRef=%q", f.Detection.KnowledgeRef)
	}
	if got := f.Context["rule_reference"]; got != "https://github.com/ditekshen/detection" {
		t.Errorf("expected reference preserved in Context, got %q", got)
	}
	if got := f.Context["rule_author"]; got != "ditekSHen" {
		t.Errorf("author must survive alongside reference, got %q", got)
	}
}

// Two rules sharing one `reference` must remain two distinct findings on the same file —
// this is the corroboration that fusion needs and that the overwrite silently deleted.
func TestSharedReferenceMetaDoesNotCollapseDistinctRules(t *testing.T) {
	meta := map[string]string{"reference": "https://github.com/SEKOIA-IO/Community", "score": "70"}
	a := findingFromRule("/tmp/shell.php", "abc123", yaraxRuleMatch{Identifier: "sekoia_rule_a", Meta: meta}, "h")
	b := findingFromRule("/tmp/shell.php", "abc123", yaraxRuleMatch{Identifier: "sekoia_rule_b", Meta: meta}, "h")
	if got := len(dedupByOriginRule([]finding.Finding{a, b})); got != 2 {
		t.Errorf("expected 2 findings from 2 distinct rules sharing a reference, got %d", got)
	}
}

func TestFindingFromRuleWithoutMeta(t *testing.T) {
	r := yaraxRuleMatch{Identifier: "generic_rule", Meta: nil}
	f := findingFromRule("/tmp/shell.php", "abc123", r, "testhost")
	if f.Score != 70 {
		t.Errorf("expected fallback Score=70, got %d", f.Score)
	}
	if f.Tier != finding.TierLikely {
		t.Errorf("expected fallback TierLikely, got %v", f.Tier)
	}
}

// javaArtifactFixtures lays down the inert Java inputs the artifact-coverage contract has to
// describe: a source file with no diagnostics, a malformed class, a valid compiled class, and an
// archive that will trip the caller-supplied entry budget.
func javaArtifactFixtures(t *testing.T) (root string, clean, malformed, valid, archive string) {
	t.Helper()
	root = t.TempDir()
	clean = filepath.Join(root, "inert.jsp")
	malformed = filepath.Join(root, "malformed.class")
	valid = filepath.Join(root, "valid.class")
	archive = filepath.Join(root, "bounded.jar")
	if err := os.WriteFile(clean, []byte("<html><body>inert page</body></html>"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(malformed, []byte("not a class file at all"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(valid, requestExecClass(t), 0o600); err != nil {
		t.Fatal(err)
	}
	writeZip(t, archive, map[string][]byte{
		"a/One.class":   requestExecClass(t),
		"b/Two.class":   requestExecClass(t),
		"c/Three.class": requestExecClass(t),
	})
	return root, clean, malformed, valid, archive
}

// boundedJavaOptions squeezes the archive-entry budget so the fixture archive is provably
// incompletely analyzed (the "budgeted" case the contract must never call complete).
func boundedJavaOptions() javadisk.Options {
	opts := javadisk.DefaultOptions()
	opts.Limits.MaxArchiveEntries = 1
	return opts
}

func artifactCoverageFor(t *testing.T, coverage []finding.ArtifactCoverage, path string) finding.ArtifactCoverage {
	t.Helper()
	for _, entry := range coverage {
		if entry.Path == path {
			return entry
		}
	}
	t.Fatalf("no artifact coverage for %q in %+v", path, coverage)
	return finding.ArtifactCoverage{}
}

func TestArtifactCoverageDescribesEveryEnumeratedJavaArtifact(t *testing.T) {
	root, clean, malformed, valid, archive := javaArtifactFixtures(t)
	scan := javadiskScan(context.Background(), []string{root}, "host", boundedJavaOptions(), true, newSignCache())
	coverage := javaArtifactCoverage(scan)

	if len(coverage) != 4 {
		t.Fatalf("want coverage for 4 enumerated artifacts, got %+v", coverage)
	}
	for i, entry := range coverage {
		if entry.Path == "" || entry.SHA256 == "" || entry.Bytes <= 0 || !finding.ValidArtifactCovStatus(entry.Status) {
			t.Fatalf("artifact %d incompletely described: %+v", i, entry)
		}
		if i > 0 && coverage[i-1].Path >= entry.Path {
			t.Fatalf("artifact coverage is not sorted by path: %+v", coverage)
		}
		if !sort.StringsAreSorted(entry.DiagnosticCodes) {
			t.Fatalf("diagnostic codes not sorted for %+v", entry)
		}
		seen := map[string]bool{}
		for _, code := range entry.DiagnosticCodes {
			if seen[code] {
				t.Fatalf("duplicate diagnostic code in %+v", entry)
			}
			seen[code] = true
			if _, ok := javaDiagnosticSeverity[code]; !ok {
				t.Fatalf("diagnostic code %q is outside the stable set: %+v", code, entry)
			}
		}
	}

	// Byte counts must be the real on-disk sizes.
	for _, path := range []string{clean, malformed, valid, archive} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := artifactCoverageFor(t, coverage, path); got.Bytes != info.Size() {
			t.Fatalf("%s: want %d bytes, got %d", path, info.Size(), got.Bytes)
		}
	}

	if got := artifactCoverageFor(t, coverage, clean).Status; got != finding.ArtifactCovComplete {
		t.Fatalf("an inert source file with no diagnostics must be complete, got %s", got)
	}
	if got := artifactCoverageFor(t, coverage, valid).Status; got != finding.ArtifactCovComplete {
		t.Fatalf("a fully parsed class must be complete, got %s", got)
	}
	for _, path := range []string{malformed, archive} {
		got := artifactCoverageFor(t, coverage, path)
		if got.Status == finding.ArtifactCovComplete {
			t.Fatalf("%s was not fully analyzed but is reported complete: %+v", path, got)
		}
		if len(got.DiagnosticCodes) == 0 {
			t.Fatalf("%s degraded without a diagnostic code: %+v", path, got)
		}
	}
	if got := artifactCoverageFor(t, coverage, malformed); got.Status != finding.ArtifactCovDegraded ||
		got.DiagnosticCodes[0] != "java-class-malformed" {
		t.Fatalf("malformed class coverage: %+v", got)
	}
	if got := artifactCoverageFor(t, coverage, archive); got.DiagnosticCodes[0] != "java-archive-budget-exhausted" {
		t.Fatalf("budgeted archive coverage: %+v", got)
	}
}

// javaClassGroupRoot lays down the canonical Java web-app layout — loose classes under
// WEB-INF/classes — which javadisk analyses as ONE group. Two facts about that group break naive
// per-artifact attribution: javadisk collapses diagnostics BY CODE (keeping a single example
// artifact plus a total count), and its group-phase diagnostics are named after the WEB-INF/classes
// DIRECTORY, which is not an enumerated artifact at all.
func javaClassGroupRoot(t *testing.T, files map[string][]byte) (root string, paths []string) {
	t.Helper()
	root = t.TempDir()
	classes := filepath.Join(root, "WEB-INF", "classes")
	if err := os.MkdirAll(classes, 0o755); err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		path := filepath.Join(classes, name)
		if err := os.WriteFile(path, files[name], 0o600); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, path)
	}
	return root, paths
}

// A diagnostic javadisk could not pin to exactly one artifact must never leave a sibling in the same
// analysis group reporting "complete" — "complete" would then mean "no diagnostic was ATTRIBUTABLE",
// not "no diagnostic applied". Both collapse mechanisms are exercised here.
func TestArtifactCoverageNeverReportsCompleteForAnUnattributedDiagnostic(t *testing.T) {
	t.Run("collapsed-by-code", func(t *testing.T) {
		malformed := []byte("not a class file at all")
		root, paths := javaClassGroupRoot(t, map[string][]byte{
			"AlphaBroken.class": malformed,
			"BetaBroken.class":  malformed,
			"DeltaValid.class":  requestExecClass(t),
			"GammaValid.class":  requestExecClass(t),
		})
		opts := javadisk.DefaultOptions()
		opts.Limits.MaxClasses = 2 // the first two classes are read, the rest are budgeted out
		scan := javadiskScan(context.Background(), []string{root}, "host", opts, true, newSignCache())

		// The fixture must actually exercise the collapse: one diagnostic per code, counting more
		// occurrences than the single artifact it names.
		for _, code := range []string{"java-class-malformed", "java-analysis-budget-exhausted"} {
			seen, count := 0, 0
			for _, diagnostic := range scan.Diagnostics {
				if diagnostic.Code == code {
					seen++
					count += max(1, diagnostic.Count)
				}
			}
			if seen != 1 || count < 2 {
				t.Fatalf("fixture did not collapse %s (seen=%d count=%d): %+v", code, seen, count, scan.Diagnostics)
			}
		}

		coverage := javaArtifactCoverage(scan)
		if len(coverage) != len(paths) {
			t.Fatalf("want coverage for %d artifacts, got %+v", len(paths), coverage)
		}
		for _, path := range paths {
			if got := artifactCoverageFor(t, coverage, path); got.Status == finding.ArtifactCovComplete {
				t.Errorf("%s was malformed or budgeted out but reports complete: %+v", filepath.Base(path), got)
			}
		}
	})

	t.Run("group-scoped-diagnostic", func(t *testing.T) {
		duplicate := requestExecClass(t)
		root, paths := javaClassGroupRoot(t, map[string][]byte{
			"CopyOne.class": duplicate,
			"CopyTwo.class": duplicate,
		})
		scan := javadiskScan(context.Background(), []string{root}, "host", javadisk.DefaultOptions(), true, newSignCache())

		// The duplicate-name diagnostic is named after the WEB-INF/classes DIRECTORY, not a file.
		group := filepath.Join(root, "WEB-INF", "classes")
		var groupScoped bool
		for _, diagnostic := range scan.Diagnostics {
			if diagnostic.Code == "java-class-duplicate-name" && filepath.Clean(diagnostic.Artifact) == group {
				groupScoped = true
			}
		}
		if !groupScoped {
			t.Fatalf("fixture produced no group-scoped diagnostic: %+v", scan.Diagnostics)
		}

		coverage := javaArtifactCoverage(scan)
		if len(coverage) != len(paths) {
			t.Fatalf("want coverage for %d artifacts, got %+v", len(paths), coverage)
		}
		for _, path := range paths {
			if got := artifactCoverageFor(t, coverage, path); got.Status == finding.ArtifactCovComplete {
				t.Errorf("%s is in a group whose analysis was degraded but reports complete: %+v", filepath.Base(path), got)
			}
		}
	})
}

// A logical archive-member diagnostic ("<archive>!/<member>") must be attributed to the physical
// outer archive, never to a path that does not exist on disk.
func TestArtifactCoverageMapsLogicalArchiveMembersToOuterArchive(t *testing.T) {
	root := t.TempDir()
	archive := filepath.Join(root, "members.jar")
	writeZip(t, archive, map[string][]byte{"nested/Broken.class": []byte("not a class")})

	scan := javadiskScan(context.Background(), []string{root}, "host", javadisk.DefaultOptions(), true, newSignCache())
	var logical bool
	for _, diagnostic := range scan.Diagnostics {
		if strings.Contains(diagnostic.Artifact, "!/") {
			logical = true
		}
	}
	if !logical {
		t.Fatalf("fixture produced no logical member diagnostic: %+v", scan.Diagnostics)
	}
	coverage := javaArtifactCoverage(scan)
	if len(coverage) != 1 {
		t.Fatalf("want one physical artifact, got %+v", coverage)
	}
	if coverage[0].Path != archive {
		t.Fatalf("logical member leaked into the coverage path: %+v", coverage[0])
	}
	if coverage[0].Status != finding.ArtifactCovDegraded || len(coverage[0].DiagnosticCodes) == 0 {
		t.Fatalf("member parse failure must degrade the outer archive: %+v", coverage[0])
	}
}

func TestArtifactCoverageUnreadableArtifactIsFailed(t *testing.T) {
	scan := javaArtifactScan{Artifacts: []javaArtifact{
		{Path: "gone.class", Bytes: 0, ReadOK: false},
		{Path: "here.class", SHA: "aa", Bytes: 4, ReadOK: true},
	}}
	coverage := javaArtifactCoverage(scan)
	if len(coverage) != 2 {
		t.Fatalf("want 2 entries, got %+v", coverage)
	}
	if got := artifactCoverageFor(t, coverage, "gone.class").Status; got != finding.ArtifactCovFailed {
		t.Fatalf("a read/hash failure must be failed, got %s", got)
	}
	// A failed read outranks any degradation.
	scan.Diagnostics = []javadisk.Diagnostic{
		{Artifact: "gone.class", Code: "java-class-malformed", Count: 1},
		{Artifact: "here.class", Code: "java-artifact-read-failed", Count: 1},
	}
	coverage = javaArtifactCoverage(scan)
	if got := artifactCoverageFor(t, coverage, "gone.class").Status; got != finding.ArtifactCovFailed {
		t.Fatalf("degradation must not soften a failed read: %s", got)
	}
	if got := artifactCoverageFor(t, coverage, "here.class").Status; got != finding.ArtifactCovFailed {
		t.Fatalf("a read-failed diagnostic must fail the artifact, got %s", got)
	}
}

// Diagnostic codes outside javadisk's stable set (and any free-text detail) must never reach the
// coverage channel.
func TestArtifactCoverageBoundsDiagnosticCodesToTheStableSet(t *testing.T) {
	scan := javaArtifactScan{
		Artifacts: []javaArtifact{{Path: "one.jar", SHA: "aa", Bytes: 8, ReadOK: true}},
		Diagnostics: []javadisk.Diagnostic{
			{Artifact: "one.jar", Code: "java-class-malformed", Detail: "<?php system($_GET[c]); ?>", Count: 1},
			{Artifact: "one.jar", Code: "java-class-malformed", Detail: "another detail", Count: 3},
			{Artifact: "one.jar", Code: "java-bytecode-unsupported", Count: 1},
			{Artifact: "one.jar", Code: "attacker-invented-code", Count: 1},
		},
	}
	coverage := javaArtifactCoverage(scan)
	if len(coverage) != 1 {
		t.Fatalf("want 1 entry, got %+v", coverage)
	}
	got := coverage[0]
	want := []string{"java-bytecode-unsupported", "java-class-malformed"}
	if len(got.DiagnosticCodes) != len(want) {
		t.Fatalf("codes must be deduped and filtered: %+v", got)
	}
	for i := range want {
		if got.DiagnosticCodes[i] != want[i] {
			t.Fatalf("want sorted %v, got %v", want, got.DiagnosticCodes)
		}
	}
	for _, code := range got.DiagnosticCodes {
		if strings.ContainsAny(code, "<>$") {
			t.Fatalf("diagnostic detail text leaked: %q", code)
		}
	}
}

// The severity table must cover javadisk's canonical vocabulary EXACTLY. It is built from
// javadisk.StableDiagnosticCodes() rather than re-declared, and this pins that: a code the analyzer
// adds fails here instead of silently changing what the channel reports.
func TestArtifactCoverageSeverityTableCoversJavadiskVocabulary(t *testing.T) {
	stable := javadisk.StableDiagnosticCodes()
	if len(stable) == 0 || !sort.StringsAreSorted(stable) {
		t.Fatalf("javadisk vocabulary must be non-empty and sorted: %v", stable)
	}
	for _, code := range stable {
		if _, ok := javaDiagnosticSeverity[code]; !ok {
			t.Errorf("javadisk emits %q but the severity table does not map it", code)
		}
	}
	if len(javaDiagnosticSeverity) != len(stable) {
		t.Errorf("severity table maps %d codes, javadisk's vocabulary has %d", len(javaDiagnosticSeverity), len(stable))
	}
	if got := javaDiagnosticSeverity[javadisk.DiagCodeArtifactRead]; got != finding.ArtifactCovFailed {
		t.Errorf("a read/hash failure must imply failed, got %q", got)
	}
	// Fail closed: an unrecognized code degrades the artifact and is not emitted.
	if status, emit := impliedArtifactStatus("java-limit-invented-later"); status != finding.ArtifactCovDegraded || emit {
		t.Errorf("unknown code must degrade without being emitted, got (%q, %v)", status, emit)
	}
}

// Widening is bounded by javadisk's real aggregation scopes: each archive is analyzed as its OWN
// Result, so a repeated diagnostic inside one archive (several over-budget nested jars, say) must not
// smear onto unrelated loose artifacts.
func TestArtifactCoverageRepeatedArchiveDiagnosticStaysOnThatArchive(t *testing.T) {
	scan := javaArtifactScan{
		Artifacts: []javaArtifact{
			{Path: filepath.Join("app", "bundle.war"), SHA: "aa", Bytes: 64, ReadOK: true},
			{Path: filepath.Join("app", "Sibling.class"), SHA: "bb", Bytes: 32, ReadOK: true},
		},
		Diagnostics: []javadisk.Diagnostic{
			{Artifact: filepath.Join("app", "bundle.war"), Code: javadisk.DiagCodeArchiveBudget, Count: 3},
		},
	}
	coverage := javaArtifactCoverage(scan)
	if got := artifactCoverageFor(t, coverage, filepath.Join("app", "bundle.war")).Status; got != finding.ArtifactCovDegraded {
		t.Fatalf("the budgeted archive must be degraded, got %s", got)
	}
	if got := artifactCoverageFor(t, coverage, filepath.Join("app", "Sibling.class")); got.Status != finding.ArtifactCovComplete {
		t.Fatalf("an archive's own diagnostics must not smear onto a loose sibling: %+v", got)
	}
}

// A diagnostic code this build does not recognize — a newer javadisk's, say — must never leave the
// artifact it applied to reported as covered.
func TestArtifactCoverageUnknownDiagnosticCodeStillDegrades(t *testing.T) {
	scan := javaArtifactScan{
		Artifacts:   []javaArtifact{{Path: "one.jar", SHA: "aa", Bytes: 8, ReadOK: true}},
		Diagnostics: []javadisk.Diagnostic{{Artifact: "one.jar", Code: "java-limit-invented-later", Count: 1}},
	}
	coverage := javaArtifactCoverage(scan)
	if len(coverage) != 1 || coverage[0].Status != finding.ArtifactCovDegraded {
		t.Fatalf("an unrecognized diagnostic must degrade, not be dropped: %+v", coverage)
	}
	if len(coverage[0].DiagnosticCodes) != 0 {
		t.Fatalf("an unrecognized code must not ride the channel: %+v", coverage[0])
	}
}

// A FAILED hash must not be memoized: the finding path treats a cached empty digest as fatal, so
// caching a transient read error at enumeration would drop a finding the flag-off path keeps.
func TestCachedSHA256FileNeverMemoizesAFailure(t *testing.T) {
	hashes := map[string]string{}
	present := filepath.Join(t.TempDir(), "present.class")
	if err := os.WriteFile(present, []byte("bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	first := cachedSHA256File(present, hashes)
	if first == "" || cachedSHA256File(present, hashes) != first {
		t.Fatalf("a successful digest must be stable and cached: %q", first)
	}
	missing := filepath.Join(t.TempDir(), "gone.class")
	if got := cachedSHA256File(missing, hashes); got != "" {
		t.Fatalf("unreadable artifact must have no digest, got %q", got)
	}
	if _, cached := hashes[filepath.Clean(missing)]; cached {
		t.Fatalf("a failed hash was memoized: %+v", hashes)
	}
}

// Without --artifact-coverage nothing about the shipped JSON may change; with it the channel
// appears. This is the production-compatibility gate at the probe's own output boundary.
func TestArtifactCoverageOnlyEmittedWhenRequested(t *testing.T) {
	findings := []finding.Finding{}
	cov := &finding.ProbeCoverage{Status: finding.CovRan, TargetsScanned: 2}
	artifacts := []finding.ArtifactCoverage{{Path: "one.jar", SHA256: "aa", Status: finding.ArtifactCovComplete, Bytes: 8}}

	off, err := marshalProbeOutput(findings, cov, nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(off) != `{"findings":[],"coverage":{"status":"ran","targets_scanned":2}}` {
		t.Fatalf("production output changed: %s", off)
	}
	on, err := marshalProbeOutput(findings, cov, artifacts)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(on), `"artifact_coverage":[{"path":"one.jar"`) {
		t.Fatalf("requested artifact coverage missing: %s", on)
	}
}

// Collection is gated too: production must not pay to hash artifacts it will not report.
func TestArtifactCoverageNotCollectedUnlessRequested(t *testing.T) {
	root, _, _, _, _ := javaArtifactFixtures(t)
	scan := javadiskScan(context.Background(), []string{root}, "host", javadisk.DefaultOptions(), false, newSignCache())
	if len(scan.Artifacts) != 0 {
		t.Fatalf("artifacts enumerated without being requested: %+v", scan.Artifacts)
	}
	if javaArtifactCoverage(scan) != nil {
		t.Fatal("coverage produced without collection")
	}
}

// A root-level YARA failure stays an aggregate coverage failure (non-zero exit, no stdout) even
// when artifact coverage is requested — cmd/measure must keep failing every sample in that unit.
func TestArtifactCoverageDoesNotSoftenRootScanFailure(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "page.php"), []byte("<?php echo 1; ?>"), 0o600); err != nil {
		t.Fatal(err)
	}
	spec, err := json.Marshal(finding.TargetSpec{Host: "host", Webroots: []string{root}})
	if err != nil {
		t.Fatal(err)
	}
	missingYR := filepath.Join(t.TempDir(), "no-such-yr.exe")
	var stdout, stderr bytes.Buffer
	code := runDiskProbe(context.Background(), []string{"--yr", missingYR, "--rules", rulesDir(), "--artifact-coverage"},
		bytes.NewReader(spec), &stdout, &stderr)
	if code != exitCoverage {
		t.Fatalf("want exitCoverage, got %d (stderr=%s)", code, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("a failed scan unit must emit no output: %s", stdout.String())
	}
}

func TestArtifactCoverageEndToEndThroughDiskProbe(t *testing.T) {
	yr := yrPath()
	if yr == "" {
		t.Skip("yr binary not found")
	}
	root, _, malformed, _, _ := javaArtifactFixtures(t)
	spec, err := json.Marshal(finding.TargetSpec{Host: "host", Webroots: []string{root}})
	if err != nil {
		t.Fatal(err)
	}

	run := func(extra ...string) finding.ProbeOutput {
		t.Helper()
		args := append([]string{"--yr", yr, "--rules", rulesDir(), "--deobf=false"}, extra...)
		var stdout, stderr bytes.Buffer
		code := runDiskProbe(context.Background(), args, bytes.NewReader(spec), &stdout, &stderr)
		if code != exitOK {
			if strings.Contains(stderr.String(), "yr on") {
				t.Skip("yr scan blocked (AV/OS) on temp files - covered by cmd/measure")
			}
			t.Fatalf("runDiskProbe exit=%d stderr=%s", code, stderr.String())
		}
		if !strings.Contains(stdout.String(), "artifact_coverage") && len(extra) > 0 {
			t.Fatalf("--artifact-coverage produced no channel: %s", stdout.String())
		}
		if strings.Contains(stdout.String(), "artifact_coverage") && len(extra) == 0 {
			t.Fatalf("artifact coverage emitted without the flag: %s", stdout.String())
		}
		var output finding.ProbeOutput
		if err := json.Unmarshal(stdout.Bytes(), &output); err != nil {
			t.Fatal(err)
		}
		return output
	}

	plain := run()
	if len(plain.ArtifactCoverage) != 0 {
		t.Fatalf("un-requested artifact coverage: %+v", plain.ArtifactCoverage)
	}
	withCoverage := run("--artifact-coverage")
	if len(withCoverage.ArtifactCoverage) != 4 {
		t.Fatalf("want 4 artifacts, got %+v", withCoverage.ArtifactCoverage)
	}
	if got := artifactCoverageFor(t, withCoverage.ArtifactCoverage, malformed).Status; got != finding.ArtifactCovDegraded {
		t.Fatalf("malformed class status through the probe: %s", got)
	}
	// The detection surface must be identical with and without the observation channel.
	if len(plain.Findings) != len(withCoverage.Findings) {
		t.Fatalf("artifact coverage changed the findings: %d vs %d", len(plain.Findings), len(withCoverage.Findings))
	}
	for i := range plain.Findings {
		if plain.Findings[i].ID != withCoverage.Findings[i].ID || plain.Findings[i].Score != withCoverage.Findings[i].Score ||
			plain.Findings[i].Tier != withCoverage.Findings[i].Tier {
			t.Fatalf("finding %d changed: %+v vs %+v", i, plain.Findings[i], withCoverage.Findings[i])
		}
	}
	if plain.Coverage == nil || withCoverage.Coverage == nil || !reflect.DeepEqual(*plain.Coverage, *withCoverage.Coverage) {
		t.Fatalf("aggregate coverage changed: %+v vs %+v", plain.Coverage, withCoverage.Coverage)
	}
}

// The DEFAULT production path is --deobf=true, where the Java pass runs inside
// scanWithDeobfDetailed rather than being called directly. The observation channel must behave
// identically there and must still leave the detection surface untouched.
func TestArtifactCoverageOnTheDefaultDeobfPath(t *testing.T) {
	yr := yrPath()
	if yr == "" {
		t.Skip("yr binary not found")
	}
	root, _, malformed, _, _ := javaArtifactFixtures(t)
	spec, err := json.Marshal(finding.TargetSpec{Host: "host", Webroots: []string{root}})
	if err != nil {
		t.Fatal(err)
	}
	run := func(extra ...string) finding.ProbeOutput {
		t.Helper()
		args := append([]string{"--yr", yr, "--rules", rulesDir()}, extra...) // --deobf defaults to true
		var stdout, stderr bytes.Buffer
		if code := runDiskProbe(context.Background(), args, bytes.NewReader(spec), &stdout, &stderr); code != exitOK {
			if strings.Contains(stderr.String(), "yr on") {
				t.Skip("yr scan blocked (AV/OS) on temp files - covered by cmd/measure")
			}
			t.Fatalf("runDiskProbe exit=%d stderr=%s", code, stderr.String())
		}
		var output finding.ProbeOutput
		if err := json.Unmarshal(stdout.Bytes(), &output); err != nil {
			t.Fatal(err)
		}
		return output
	}

	plain := run()
	if len(plain.ArtifactCoverage) != 0 {
		t.Fatalf("un-requested artifact coverage on the default path: %+v", plain.ArtifactCoverage)
	}
	withCoverage := run("--artifact-coverage")
	if len(withCoverage.ArtifactCoverage) != 4 {
		t.Fatalf("want 4 artifacts, got %+v", withCoverage.ArtifactCoverage)
	}
	if got := artifactCoverageFor(t, withCoverage.ArtifactCoverage, malformed).Status; got != finding.ArtifactCovDegraded {
		t.Fatalf("malformed class status on the default path: %s", got)
	}
	if len(plain.Findings) != len(withCoverage.Findings) {
		t.Fatalf("artifact coverage changed the findings: %d vs %d", len(plain.Findings), len(withCoverage.Findings))
	}
	if plain.Coverage == nil || withCoverage.Coverage == nil || !reflect.DeepEqual(*plain.Coverage, *withCoverage.Coverage) {
		t.Fatalf("aggregate coverage changed: %+v vs %+v", plain.Coverage, withCoverage.Coverage)
	}
}
