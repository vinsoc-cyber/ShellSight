package release

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// mkRelease writes a fake release directory: files plus a manifest naming their real hashes.
func mkRelease(t *testing.T, files map[string]string, corrupt string) string {
	t.Helper()
	root := t.TempDir()
	var manifest strings.Builder
	for path, body := range files {
		full := filepath.Join(root, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		manifest.WriteString(Sum([]byte(body)) + "  " + path + "\n")
	}
	if err := os.WriteFile(filepath.Join(root, ManifestName), []byte(manifest.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	if corrupt != "" {
		full := filepath.Join(root, filepath.FromSlash(corrupt))
		if err := os.WriteFile(full, []byte("tampered"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestVerifyAcceptsAnIntactRelease(t *testing.T) {
	dir := mkRelease(t, map[string]string{
		"shellsight.exe":            "scanner bytes",
		"third_party/yara-x/yr.exe": "engine bytes",
		"kb/rules/own/r.yar":        "rule x { condition: true }",
	}, "")

	got, err := Verify(dir)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d files, want 3", len(got))
	}
	for _, f := range got {
		if len(f.SHA256) != 64 {
			t.Errorf("%s: hash %q is not 64 chars", f.Path, f.SHA256)
		}
	}
}

func TestVerifyRejectsATamperedFile(t *testing.T) {
	dir := mkRelease(t, map[string]string{
		"shellsight.exe":     "scanner bytes",
		"kb/rules/own/r.yar": "rule x { condition: true }",
	}, "shellsight.exe")

	_, err := Verify(dir)
	if err == nil {
		t.Fatal("expected verification to fail on a tampered file, got nil")
	}
	if !strings.Contains(err.Error(), "shellsight.exe") {
		t.Fatalf("error must name the offending file, got: %v", err)
	}
}

func TestVerifyRejectsAFileMissingFromDisk(t *testing.T) {
	dir := mkRelease(t, map[string]string{"shellsight.exe": "scanner bytes"}, "")
	if err := os.Remove(filepath.Join(dir, "shellsight.exe")); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(dir); err == nil {
		t.Fatal("expected verification to fail when a manifested file is absent, got nil")
	}
}

func TestVerifyRejectsAFileOnDiskThatTheManifestDoesNotName(t *testing.T) {
	dir := mkRelease(t, map[string]string{"shellsight.exe": "scanner bytes"}, "")
	if err := os.WriteFile(filepath.Join(dir, "extra.dll"), []byte("smuggled"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Verify(dir)
	if err == nil {
		t.Fatal("expected verification to fail on an unmanifested file, got nil")
	}
	if !strings.Contains(err.Error(), "extra.dll") {
		t.Fatalf("error must name the extra file, got: %v", err)
	}
}

func TestVerifyRejectsAManifestPathThatEscapesTheRoot(t *testing.T) {
	root := t.TempDir()
	body := Sum([]byte("x")) + "  ../escaped.exe\n"
	if err := os.WriteFile(filepath.Join(root, ManifestName), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(root); err == nil {
		t.Fatal("expected verification to reject a path escaping the release root, got nil")
	}
}

// TestVerifyAcceptsARealPackagedRelease verifies an actual scripts/package.sh output.
//
// Every other test here builds its fixture with mkRelease, which writes a manifest line for each
// file it creates -- so the fixture is complete BY CONSTRUCTION and cannot express the defect that
// actually shipped: a release whose manifest named 144 of its 164 files. The suite was green
// throughout, and `console publish` refused every real release for eight weeks.
//
// This is the cross-module check, and it skips when no release directory is given because the
// archives are gitignored and ~34 MB. The skip is not the guard: scripts/package.sh's own
// verify_extracted_release_manifest asserts the same property on the producer side, over the
// extracted archive, and cannot be skipped. This test is what lets a developer confirm it locally:
//
//	unzip -q shellsight-<ver>-win.zip -d /tmp/rel
//	SHELLSIGHT_RELEASE_DIR=/tmp/rel go test ./internal/release/ -run RealPackagedRelease -v
func TestVerifyAcceptsARealPackagedRelease(t *testing.T) {
	root := os.Getenv("SHELLSIGHT_RELEASE_DIR")
	if root == "" {
		t.Skip("SHELLSIGHT_RELEASE_DIR not set; see the comment for how to point this at a real release")
	}
	files, err := Verify(root)
	if err != nil {
		t.Fatalf("a real packaged release must verify, got: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("verification returned no files, which cannot describe a real release")
	}
	// The scanner and its declaration are what generation reads; a release missing either would
	// verify and then be useless to agentgen.
	need := []string{"components.json"}
	have := map[string]bool{}
	for _, f := range files {
		have[f.Path] = true
	}
	for _, p := range need {
		if !have[p] {
			t.Errorf("the verified file set does not include %s", p)
		}
	}
	t.Logf("verified %d files under %s", len(files), root)
}
