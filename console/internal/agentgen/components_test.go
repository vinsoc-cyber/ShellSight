package agentgen

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// fakeFiles is the release index and the blob store together, which is all resolution needs.
type fakeFiles map[string][]byte

func (f fakeFiles) File(path string) ([]byte, bool) {
	b, ok := f[path]
	return b, ok
}

const linuxComponents = `{
  "schema_version": "1",
  "target": "linux-amd64",
  "release": "v1.0.0-488-gdd02888",
  "always": ["shellsight"],
  "views": {
    "disk": {"binaries": ["diskprobe", "third_party/yara-x/yr"],
             "data": ["kb/rules/foundation", "kb/rules/own"], "rules": true},
    "java-mem": {"binaries": ["jvmprobe"], "rules": false}
  }
}`

func TestComponentsComeOutOfTheRelease(t *testing.T) {
	doc, err := LoadComponents(fakeFiles{"components.json": []byte(linuxComponents)})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if doc.Target != "linux-amd64" {
		t.Errorf("Target = %q", doc.Target)
	}
	if len(doc.Always) != 1 || doc.Always[0] != "shellsight" {
		t.Errorf("Always = %v", doc.Always)
	}
	if !doc.Views["disk"].Rules {
		t.Error("disk must declare rules:true")
	}
	if doc.Views["java-mem"].Rules {
		t.Error("java-mem must declare rules:false")
	}
}

// A release published before components.json existed has no declaration. That is not something to
// paper over with a default: a generator that invents a component list is the exact thing G5 exists
// to prevent.
func TestAReleaseWithNoDeclarationIsRefused(t *testing.T) {
	_, err := LoadComponents(fakeFiles{})
	if err == nil {
		t.Fatal("a release carrying no components.json must be refused")
	}
	if !strings.Contains(err.Error(), "components.json") {
		t.Errorf("the error must name the missing file: %v", err)
	}
	// And it must be refused AS MISSING, not as unparseable bytes. Measured, not assumed: with the
	// !ok branch deleted, raw is nil, json.Unmarshal(nil) returns "unexpected end of JSON input",
	// and the wrapper's own text still contains "components.json" -- so the two assertions above
	// both passed with the gate gone and the mutation killed no test at all. The refusal an analyst
	// reads has to say the release predates the feature, not that its JSON is broken.
	var syntax *json.SyntaxError
	if errors.As(err, &syntax) {
		t.Errorf("a release with no declaration must not be reported as a parse failure: %v", err)
	}
}

// Asserting the error WRAPS the parse failure, not merely that one came back. A malformed-JSON test
// that checks only err != nil passes even when the parse error is swallowed and a later gate
// happens to reject the zero value -- that exact test passed while proving nothing in Plan 1.
func TestAnUnreadableDeclarationIsRefusedLoudly(t *testing.T) {
	_, err := LoadComponents(fakeFiles{"components.json": []byte("{not json")})
	if err == nil {
		t.Fatal("malformed components.json must be refused")
	}
	var syntax *json.SyntaxError
	if !errors.As(err, &syntax) {
		t.Errorf("the error must wrap the parse failure, got %v", err)
	}
}

// A schema this console does not know is refused rather than read optimistically. The document is a
// contract; a newer one may mean something different by the same field name.
func TestAnUnknownSchemaVersionIsRefused(t *testing.T) {
	doc := strings.Replace(linuxComponents, `"schema_version": "1"`, `"schema_version": "2"`, 1)
	if _, err := LoadComponents(fakeFiles{"components.json": []byte(doc)}); err == nil {
		t.Fatal("schema_version 2 must be refused by a console that only knows 1")
	}
}

// The plan named two gates to mutation-check and LoadComponents has three. Measured 2026-09-04:
// deleting the len(doc.Views)==0 gate killed no test in this file, so it was not a gate. A document
// declaring no views passes every other check there is -- there is nothing left to disagree with --
// and would hand Resolve an empty map, where every view an analyst can pick is then "unsupported by
// this target". The refusal belongs at the document, which is where the fault is.
func TestADeclarationWithNoViewsIsRefused(t *testing.T) {
	const noViews = `{"schema_version": "1", "target": "linux-amd64", "release": "v1.0.0",
                     "always": ["shellsight"], "views": {}}`
	_, err := LoadComponents(fakeFiles{"components.json": []byte(noViews)})
	if err == nil {
		t.Fatal("a declaration naming no views must be refused")
	}
	if !strings.Contains(err.Error(), "views") {
		t.Errorf("the error must say what is wrong with the document: %v", err)
	}
}

// The orchestrator is what runs the probes, so a declaration naming no always-present component
// resolves to an agent carrying detectors nothing can launch.
//
// Nothing upstream catches this alone: the scanner's package-time verification gates the
// CONJUNCTION (len(Always)==0 && len(Views)==0), so views-plus-empty-always passes there, and the
// release_files cross-check cannot see it either -- nothing is missing, the orchestrator is simply
// undeclared.
func TestADeclarationNamingNoAlwaysPresentComponentIsRefused(t *testing.T) {
	doc := strings.Replace(linuxComponents, `"always": ["shellsight"],`, `"always": [],`, 1)
	if doc == linuxComponents {
		t.Fatal("fixture did not change; the always key is not where this test thinks it is")
	}
	_, err := LoadComponents(fakeFiles{"components.json": []byte(doc)})
	if err == nil {
		t.Fatal("a declaration with no always-present component must be refused")
	}
	if !strings.Contains(err.Error(), "orchestrator") {
		t.Errorf("the error must say what is missing and why it matters: %v", err)
	}
}
