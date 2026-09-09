package reports

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"shellsightconsole/internal/report"
	"shellsightconsole/internal/store"
)

type fakeStore struct {
	saved   []store.ScanRecord
	created bool
	nextID  int64
}

func (f *fakeStore) SaveScan(_ context.Context, _ int64, s store.ScanRecord) (int64, bool, error) {
	f.saved = append(f.saved, s)
	f.nextID++
	return f.nextID, f.created, nil
}

func fixtureFolder(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	body, err := os.ReadFile(filepath.Join("..", "report", "testdata", "report.json"))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "report.json"), body, 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestIngestMapsAReportOntoAScanRecord(t *testing.T) {
	f := &fakeStore{created: true}
	svc := NewService(f)

	res, err := svc.IngestFolder(context.Background(), 1, fixtureFolder(t))
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if !res.Created {
		t.Fatal("expected Created")
	}
	if len(f.saved) != 1 {
		t.Fatalf("saved %d scans, want 1", len(f.saved))
	}
	got := f.saved[0]
	if got.RunID == "" || got.Host == "" {
		t.Fatalf("scan identity not mapped: %+v", got)
	}
	if len(got.Findings) == 0 {
		t.Fatal("findings not mapped")
	}
	if len(got.Coverage) == 0 {
		t.Fatal("coverage not mapped")
	}
	if got.Integrity != report.IntegrityUnverified {
		t.Fatalf("integrity = %q, want unverified (fixture has no manifest)", got.Integrity)
	}
}

func TestEveryMappedFindingCarriesAContentKey(t *testing.T) {
	// A finding stored without one can never be grouped or carry a decision.
	f := &fakeStore{created: true}
	svc := NewService(f)
	if _, err := svc.IngestFolder(context.Background(), 1, fixtureFolder(t)); err != nil {
		t.Fatal(err)
	}
	for _, fr := range f.saved[0].Findings {
		if fr.ContentKey == "" {
			t.Fatalf("finding %s has no content key", fr.Ref)
		}
	}
}

func TestIngestReportsWhenAScanWasAlreadyPresent(t *testing.T) {
	f := &fakeStore{created: false}
	svc := NewService(f)
	res, err := svc.IngestFolder(context.Background(), 1, fixtureFolder(t))
	if err != nil {
		t.Fatalf("re-ingest must not error: %v", err)
	}
	if res.Created {
		t.Fatal("expected Created=false for an already-present run")
	}
}

func TestIngestRejectsAFolderWithNoReport(t *testing.T) {
	svc := NewService(&fakeStore{})
	if _, err := svc.IngestFolder(context.Background(), 1, t.TempDir()); err == nil {
		t.Fatal("expected a folder with no report.json to fail")
	}
}
