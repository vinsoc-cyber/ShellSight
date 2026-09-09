package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// mkRun builds a run folder: report.json plus a manifest naming its real hash.
func mkRun(t *testing.T, tamper bool, withManifest bool) string {
	t.Helper()
	dir := t.TempDir()
	body := loadFixture(t)
	if err := os.WriteFile(filepath.Join(dir, "report.json"), body, 0o644); err != nil {
		t.Fatal(err)
	}
	if withManifest {
		m := map[string]string{"report.json": Sum(body)}
		raw, _ := json.Marshal(m)
		if err := os.WriteFile(filepath.Join(dir, "manifest.json"), raw, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if tamper {
		if err := os.WriteFile(filepath.Join(dir, "report.json"), append(body, ' '), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestLoadRunFolderReportsVerifiedWhenTheManifestMatches(t *testing.T) {
	got, err := LoadRunFolder(mkRun(t, false, true))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got.Integrity != IntegrityVerified {
		t.Fatalf("integrity = %q, want %q", got.Integrity, IntegrityVerified)
	}
	if len(got.Report.Findings) == 0 {
		t.Fatal("findings were not parsed")
	}
}

func TestLoadRunFolderReportsAlteredWhenTheHashDisagrees(t *testing.T) {
	got, err := LoadRunFolder(mkRun(t, true, true))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got.Integrity != IntegrityAltered {
		t.Fatalf("integrity = %q, want %q", got.Integrity, IntegrityAltered)
	}
	// A tampered report is still LOADED. Refusing it would lose the evidence; the analyst needs
	// to see what it says AND that it does not match its manifest.
	if len(got.Report.Findings) == 0 {
		t.Fatal("an altered report must still be readable")
	}
}

func TestLoadRunFolderReportsUnverifiedWithNoManifest(t *testing.T) {
	got, err := LoadRunFolder(mkRun(t, false, false))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got.Integrity != IntegrityUnverified {
		t.Fatalf("integrity = %q, want %q", got.Integrity, IntegrityUnverified)
	}
}

func TestLoadRunFolderFailsWithNoReport(t *testing.T) {
	if _, err := LoadRunFolder(t.TempDir()); err == nil {
		t.Fatal("expected a folder with no report.json to fail")
	}
}
