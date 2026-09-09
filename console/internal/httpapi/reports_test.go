package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"shellsightconsole/internal/report"
	"shellsightconsole/internal/reports"
	"shellsightconsole/internal/store"
	"shellsightconsole/internal/triage"
)

var errNoScan = errors.New("no such scan")

type fakeReports struct {
	cases     []store.Case
	scans     []store.ScanRecord
	findings  []store.FindingRecord
	coverage  []store.CoverageRecord
	decisions map[string][]store.Decision
	recorded  []store.Decision

	ingested       []ingested
	ingestErr      error
	alreadyPresent bool
}

type ingested struct {
	caseID   int64
	body     []byte
	manifest []byte
	source   string
}

func (f *fakeReports) CreateCase(context.Context, string, string) (int64, error) { return 1, nil }
func (f *fakeReports) ListCases(context.Context) ([]store.Case, error)           { return f.cases, nil }
func (f *fakeReports) ListScans(context.Context, int64) ([]store.ScanRecord, error) {
	return f.scans, nil
}
func (f *fakeReports) GetScan(_ context.Context, id int64) (store.ScanRecord, error) {
	for _, s := range f.scans {
		if s.ID == id {
			return s, nil
		}
	}
	return store.ScanRecord{}, errNoScan
}
func (f *fakeReports) FindingsForScan(context.Context, int64) ([]store.FindingRecord, error) {
	return f.findings, nil
}
func (f *fakeReports) CoverageForScan(context.Context, int64) ([]store.CoverageRecord, error) {
	return f.coverage, nil
}
func (f *fakeReports) DecisionsFor(_ context.Context, keys []string) (map[string][]store.Decision, error) {
	return f.decisions, nil
}
func (f *fakeReports) RecordDecision(_ context.Context, d store.Decision) (int64, error) {
	f.recorded = append(f.recorded, d)
	return 7, nil
}

// Ingest records what the endpoint handed it, so a test can assert on the BYTES that arrived
// rather than only on the response. ingestErr makes the rejection path reachable.
func (f *fakeReports) Ingest(_ context.Context, caseID int64, body, manifest []byte, source string) (reports.Result, error) {
	f.ingested = append(f.ingested, ingested{caseID: caseID, body: body, manifest: manifest, source: source})
	if f.ingestErr != nil {
		return reports.Result{}, f.ingestErr
	}
	// Mirror the real service closely enough to be worth asserting on: the integrity state is
	// decided by report.Load, which is the one implementation both paths share.
	loaded, err := report.Load(body, manifest, source)
	if err != nil {
		return reports.Result{}, err
	}
	return reports.Result{
		ScanID: 11, RunID: loaded.Report.Scan.RunID, Host: loaded.Report.Scan.Host,
		Created: !f.alreadyPresent, Findings: len(loaded.Report.Findings),
		Integrity: loaded.Integrity,
	}, nil
}

func reportServer(t *testing.T, f *fakeReports) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(NewReportAPI(f, f).Routes())
	t.Cleanup(s.Close)
	return s
}

func TestScanViewReturnsVerdictAndCoverageTogether(t *testing.T) {
	// The design's central reporting rule: a verdict rendered without its coverage is how a
	// scanner tells a comfortable lie.
	f := &fakeReports{
		scans:    []store.ScanRecord{{ID: 5, RunID: "r1", Host: "web-03", Tier: "clean", Score: 0}},
		coverage: []store.CoverageRecord{{View: "disk", Status: "ran", TargetsScanned: 38492, Unreadable: 398}},
	}
	srv := reportServer(t, f)

	resp, err := http.Get(srv.URL + "/api/scans/5")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var got map[string]json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if _, ok := got["verdict"]; !ok {
		t.Fatal("no verdict in the scan view")
	}
	if _, ok := got["coverage"]; !ok {
		t.Fatal("coverage must accompany the verdict, always")
	}
}

func TestFindingsAreReturnedGroupedByContent(t *testing.T) {
	f := &fakeReports{findings: []store.FindingRecord{
		{Ref: "aa-r1", ContentKey: "sha256:aa", Host: "h", FilePath: "/a", Score: 70, Tier: "likely-malicious"},
		{Ref: "aa-r2", ContentKey: "sha256:aa", Host: "h", FilePath: "/b", Score: 90, Tier: "confirmed"},
	}}
	srv := reportServer(t, f)

	resp, err := http.Get(srv.URL + "/api/scans/5/findings")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var got []triage.Group
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d groups, want 1", len(got))
	}
	if got[0].Tier != "confirmed" {
		t.Fatalf("group tier = %q, want the worst of its findings", got[0].Tier)
	}
}

func TestPriorDecisionsAreAttachedToGroups(t *testing.T) {
	f := &fakeReports{
		findings: []store.FindingRecord{{Ref: "a", ContentKey: "sha256:aa", Tier: "confirmed", Score: 90}},
		decisions: map[string][]store.Decision{
			"sha256:aa": {{Verdict: "malicious", Author: "a-teammate", CaseName: "IR-contoso"}},
		},
	}
	srv := reportServer(t, f)

	// The plan wrote this `resp, _ := http.Get(...)`, which `go vet`'s httpresponse analyzer
	// rejects -- on an error `resp` is nil and the deferred Close panics. Checked like the
	// package's other tests do.
	resp, err := http.Get(srv.URL + "/api/scans/5/findings")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "IR-contoso") {
		t.Fatalf("prior decision not surfaced: %s", body)
	}
}

func TestRecordingADecisionKeysItOnContent(t *testing.T) {
	f := &fakeReports{}
	srv := reportServer(t, f)

	resp, err := http.Post(srv.URL+"/api/decisions", "application/json",
		strings.NewReader(`{"content_key":"sha256:aa","verdict":"false-positive","note":"legit uploader","case_id":1}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status %d, want 201", resp.StatusCode)
	}
	if len(f.recorded) != 1 || f.recorded[0].ContentKey != "sha256:aa" {
		t.Fatalf("decision not recorded against content: %+v", f.recorded)
	}
}

func TestAnUnknownVerdictIs400(t *testing.T) {
	srv := reportServer(t, &fakeReports{})
	resp, err := http.Post(srv.URL+"/api/decisions", "application/json",
		strings.NewReader(`{"content_key":"sha256:aa","verdict":"probably-fine"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status %d, want 400", resp.StatusCode)
	}
}
