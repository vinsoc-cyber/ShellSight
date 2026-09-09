package agentgen

import (
	"strings"
	"testing"
)

func mustLoad(t *testing.T, doc string) Components {
	t.Helper()
	c, err := LoadComponents(fakeFiles{"components.json": []byte(doc)})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestADiskBuildCarriesTheOrchestratorTheProbeAndYr(t *testing.T) {
	got, err := Resolve(mustLoad(t, linuxComponents), []string{"disk"})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	want := []string{"diskprobe", "shellsight", "third_party/yara-x/yr"}
	if strings.Join(got.Files, ",") != strings.Join(want, ",") {
		t.Errorf("Files = %v, want %v (sorted, deduplicated)", got.Files, want)
	}
	if !got.NeedsRules {
		t.Error("a disk build needs a compiled rule set")
	}
}

// The test that makes G8 a fact rather than a claim. disk declares
// data: ["kb/rules/foundation","kb/rules/own"] -- the YARA rule TEXT -- and rules:true means the
// compiled blob replaces it. Staging it would ship rule source in a customer-bound agent.
func TestARulesViewNeverStagesItsRuleText(t *testing.T) {
	got, err := Resolve(mustLoad(t, linuxComponents), []string{"disk"})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range got.Files {
		if strings.HasPrefix(f, "kb/rules/") {
			t.Errorf("resolved %q: a rules:true view's data is what the .yarc REPLACES, and shipping "+
				"rule text violates G8/D5", f)
		}
	}
}

// The test that makes G3 a fact: the split is real, not a claim about the future.
func TestAMemoryOnlyBuildCarriesNoScannerRulesAtAll(t *testing.T) {
	got, err := Resolve(mustLoad(t, linuxComponents), []string{"java-mem"})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	want := []string{"jvmprobe", "shellsight"}
	if strings.Join(got.Files, ",") != strings.Join(want, ",") {
		t.Errorf("Files = %v, want %v", got.Files, want)
	}
	if got.NeedsRules {
		t.Error("a memory-only build must not ask for a rule set: it carries no YARA at all")
	}
	for _, f := range got.Files {
		if strings.Contains(f, "yara-x") || strings.HasPrefix(f, "kb/rules/") {
			t.Errorf("memory-only build resolved %q", f)
		}
	}
}

func TestAViewTheTargetDoesNotSupportIsRefusedByName(t *testing.T) {
	_, err := Resolve(mustLoad(t, linuxComponents), []string{"disk", "dotnet-mem"})
	if err == nil {
		t.Fatal("a view absent from this target's declaration must be refused")
	}
	if !strings.Contains(err.Error(), "dotnet-mem") || !strings.Contains(err.Error(), "linux-amd64") {
		t.Errorf("the error must name the view and the target: %v", err)
	}
}

func TestSelectingNoViewsIsRefused(t *testing.T) {
	if _, err := Resolve(mustLoad(t, linuxComponents), nil); err == nil {
		t.Fatal("a build with no views would examine nothing and must be refused")
	}
}

// windowsComponents is the windows-amd64 declaration, transcribed from the real document
// (`shellsight components -target windows-amd64 -goos windows`, run 2026-09-04) and cut to the
// views that share a file.
//
// It exists because the linux document has no shared component to measure. Measured 2026-09-04:
// replacing the dedup map with a slice append killed no test, because the only file two selected
// linux views have in common is the orchestrator -- and that comes from `always`, which is visited
// once whether or not anything dedupes. Real releases DO share between views: all three of the
// windows memory views declare the same kb/rules/mem-contracts.json.
const windowsComponents = `{
  "schema_version": "1",
  "target": "windows-amd64",
  "release": "v1.0.0-488-gdd02888",
  "always": ["shellsight.exe"],
  "views": {
    "dotnet-mem": {"binaries": ["dotnetmem.exe", "dotnetmem.exe.config"],
                   "data": ["kb/rules/mem-contracts.json"], "rules": false},
    "dotnet-mem-x86": {"binaries": ["dotnetmem-x86.exe", "dotnetmem-x86.exe.config"],
                       "data": ["kb/rules/mem-contracts.json"], "rules": false},
    "java-mem": {"binaries": ["javamem.jar", "javamem-agent.jar"],
                 "data": ["kb/rules/mem-contracts.json"], "rules": false,
                 "host_requires": "a Java runtime on the target host"}
  }
}`

func tally(files []string) map[string]int {
	seen := map[string]int{}
	for _, f := range files {
		seen[f]++
	}
	return seen
}

// Two views sharing a component must not stage it twice: a duplicate zip entry is a corrupt
// archive on some extractors and a silent overwrite on others.
func TestASharedComponentIsStagedOnce(t *testing.T) {
	got, err := Resolve(mustLoad(t, linuxComponents), []string{"disk", "java-mem"})
	if err != nil {
		t.Fatal(err)
	}
	if n := tally(got.Files)["shellsight"]; n != 1 {
		t.Errorf("shellsight staged %d times", n)
	}
	if !got.NeedsRules {
		t.Error("a selection containing disk still needs rules")
	}
	// The check above is necessary but not sufficient, and only the mutation showed it: the
	// orchestrator is in `always`, read once, so it stays single-copy even with the dedup gone.
	// The file two VIEWS both declare is what the dedup is actually for.
	shared, err := Resolve(mustLoad(t, windowsComponents), []string{"dotnet-mem", "java-mem"})
	if err != nil {
		t.Fatal(err)
	}
	if n := tally(shared.Files)["kb/rules/mem-contracts.json"]; n != 1 {
		t.Errorf("kb/rules/mem-contracts.json staged %d times: both selected views declare it, and "+
			"one path twice in a zip is a corrupt archive on some extractors", n)
	}
	if shared.NeedsRules {
		t.Error("two memory views scan with no YARA and must not ask for a compiled rule set")
	}
}

// Views is written verbatim into agent.json and joined with a comma to build -views. The scanner
// rejects a blank name, a comma-bearing name and duplicate JSON keys -- but NOT a repeated array
// element, so an undeduplicated list becomes `-views disk,disk`.
func TestARepeatedViewIsNamedOnce(t *testing.T) {
	got, err := Resolve(mustLoad(t, linuxComponents), []string{"disk", "disk", "java-mem"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"disk", "java-mem"}
	if strings.Join(got.Views, ",") != strings.Join(want, ",") {
		t.Errorf("Views = %v, want %v", got.Views, want)
	}
}
