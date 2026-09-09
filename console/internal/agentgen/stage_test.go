package agentgen

import (
	"strconv"
	"strings"
	"testing"
)

// diskRelease is a linux-amd64 release that actually holds everything its declaration names.
func diskRelease() fakeFiles {
	return fakeFiles{
		"components.json":       []byte(linuxComponents),
		"shellsight":            []byte("orchestrator bytes"),
		"diskprobe":             []byte("probe bytes"),
		"third_party/yara-x/yr": []byte("yr bytes"),
	}
}

func names(fs []StagedFile) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.Path)
	}
	return out
}

func TestStageReturnsTheBytesOfEveryResolvedComponent(t *testing.T) {
	files := diskRelease()
	sel, err := Resolve(mustLoad(t, linuxComponents), []string{"disk"})
	if err != nil {
		t.Fatal(err)
	}
	staged, err := Stage(files, sel)
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	if len(staged) != 3 {
		t.Fatalf("staged %d entries, want 3: %v", len(staged), names(staged))
	}
	// Order is the resolved order, which is sorted -- the zip depends on it.
	want := []string{"diskprobe", "shellsight", "third_party/yara-x/yr"}
	if strings.Join(names(staged), ",") != strings.Join(want, ",") {
		t.Errorf("staged %v, want %v", names(staged), want)
	}
	if string(staged[1].Body) != "orchestrator bytes" {
		t.Errorf("shellsight body = %q", staged[1].Body)
	}
}

// The guard for a release nobody verified. A declaration that promises a component the release does
// not hold must stop the build, not produce an agent missing a probe it claims to carry.
func TestAComponentMissingFromTheReleaseRefusesTheBuild(t *testing.T) {
	files := diskRelease()
	delete(files, "diskprobe")
	sel, err := Resolve(mustLoad(t, linuxComponents), []string{"disk"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = Stage(files, sel)
	if err == nil {
		t.Fatal("a declared component absent from the release must refuse the build")
	}
	if !strings.Contains(err.Error(), "diskprobe") {
		t.Errorf("the error must name the missing component so an operator can act: %v", err)
	}
}

// A path that is not the shape a release path may take is refused AS MALFORMED, and that is the
// distinction this test is built around.
//
// The membership check alone would appear to cover this: "../../etc/passwd" is not in release_files
// either, so Stage refuses it whatever the shape rules say. But it refuses it as ABSENT, which reads
// to an operator as "this release is incomplete" when the truth is "this declaration is malformed"
// -- and, worse, means deleting the shape check kills no test. That trap already fired twice in this
// plan (Task 1's missing-declaration branch, Task 2's dedup map).
//
// So each malformed path is PUT INTO the release first. Membership then succeeds, and the only thing
// left that can refuse it is its shape. Delete checkReleasePath and every case here stages happily
// and this test fails, which is what a gate's test has to do.
func TestADeclaredPathThatIsNotAReleasePathIsRefusedAsMalformed(t *testing.T) {
	for _, bad := range []string{
		"../../etc/passwd",      // climbs out from the front
		"a/../../b",             // climbs out from the middle
		"/etc/x",                // posix-absolute
		`third_party\yara-x\yr`, // OS-native rather than slash-separated
		`C:\x`,                  // windows drive-absolute, backslashed
		"C:/x",                  // windows drive-absolute, slashed -- see checkReleasePath
		"",                      // no path at all
	} {
		files := diskRelease()
		files[bad] = []byte("bytes the release really does hold")
		_, err := Stage(files, Selection{Files: []string{bad}})
		if err == nil {
			t.Errorf("Stage(%q) was accepted; that path is not a component of any release", bad)
			continue
		}
		if strings.Contains(err.Error(), "does not hold") {
			t.Errorf("Stage(%q) was refused as absent, but the release holds it: the fault is the "+
				"path's SHAPE and the refusal has to say so, or an operator goes looking for a "+
				"missing file that is not missing: %v", bad, err)
		}
		if bad != "" && !strings.Contains(err.Error(), strconv.Quote(bad)) &&
			!strings.Contains(err.Error(), bad) {
			t.Errorf("Stage(%q) refused without naming the offending path: %v", bad, err)
		}
	}
}

// The control. Rejecting path shapes is only useful if the shapes a real release uses survive, and
// third_party/yara-x/yr is the one every disk build carries.
func TestALegitimatelyNestedPathStillStages(t *testing.T) {
	staged, err := Stage(diskRelease(), Selection{Files: []string{"third_party/yara-x/yr"}})
	if err != nil {
		t.Fatalf("a nested release path must stage: %v", err)
	}
	if len(staged) != 1 || staged[0].Path != "third_party/yara-x/yr" {
		t.Fatalf("staged %v", names(staged))
	}
	if string(staged[0].Body) != "yr bytes" {
		t.Errorf("body = %q", staged[0].Body)
	}
}

// The malformed path arrives from the declaration, not from a hand-built Selection, because that is
// the route a real one takes. Resolve deliberately does not check path shape -- the scanner enforces
// it at package time -- so nothing between the document and the archive checks it except Stage.
func TestAMalformedPathInTheDeclarationItselfIsRefused(t *testing.T) {
	doc := strings.Replace(linuxComponents,
		`"always": ["shellsight"],`, `"always": ["../../../etc/shadow"],`, 1)
	if doc == linuxComponents {
		t.Fatal("fixture did not change; the always key is not where this test thinks it is")
	}
	files := diskRelease()
	files["../../../etc/shadow"] = []byte("held, so only the shape can refuse it")
	sel, err := Resolve(mustLoad(t, doc), []string{"disk"})
	if err != nil {
		t.Fatalf("Resolve does not check path shape and must not start: %v", err)
	}
	if _, err := Stage(files, sel); err == nil {
		t.Fatal("a declaration naming a path outside the release root must refuse the build")
	}
}
