package httpapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"shellsightconsole/internal/report"
)

// A minimal report.json, in the scanner's own shape. Kept small on purpose: what is under test is
// the endpoint, and report parsing has its own tests.
const uploadReportJSON = `{
  "schema_version": "1.0",
  "scan": {"run_id": "20260904_101500", "host": "WEB-IIS-07", "tool_version": "1.4.2"},
  "verdict": {"tier": "likely-malicious", "score": 70, "incomplete": false},
  "coverage": [{"view": "disk", "status": "ran", "targets_scanned": 1200}],
  "findings": [
    {"id": "74ddb246d1fc-ObfuscatedPhp", "host": "WEB-IIS-07", "view": "disk",
     "target": {"kind": "file", "file": {"path": "/var/www/x.php", "sha256": "74ddb246d1fc"}},
     "detection": {"basis": "signature", "knowledge_ref": "kb:yara/ObfuscatedPhp"},
     "score": 70, "tier": "likely-malicious"}
  ]
}`

// upload posts a multipart body the way the browser does. parts maps a field name to its content;
// a nil value omits the part entirely, which is how the no-manifest case is expressed.
func upload(t *testing.T, url string, parts map[string]string) *http.Response {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for field, content := range parts {
		w, err := mw.CreateFormFile(field, field+".json")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, url, &buf)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = res.Body.Close() })
	return res
}

func decodeResult(t *testing.T, res *http.Response) map[string]any {
	t.Helper()
	var got map[string]any
	if err := json.NewDecoder(res.Body).Decode(&got); err != nil {
		t.Fatalf("decoding the response: %v", err)
	}
	return got
}

func TestUploadStoresTheReportUnderTheCaseInThePath(t *testing.T) {
	f := &fakeReports{}
	srv := reportServer(t, f)

	res := upload(t, srv.URL+"/api/cases/42/reports", map[string]string{"report": uploadReportJSON})
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d, want 201", res.StatusCode)
	}
	if len(f.ingested) != 1 {
		t.Fatalf("ingested %d reports, want 1", len(f.ingested))
	}
	if f.ingested[0].caseID != 42 {
		t.Errorf("caseID = %d, want 42 -- the case comes from the path", f.ingested[0].caseID)
	}
	got := decodeResult(t, res)
	if got["host"] != "WEB-IIS-07" {
		t.Errorf("host = %v, want WEB-IIS-07", got["host"])
	}
	if got["findings"] != float64(1) {
		t.Errorf("findings = %v, want 1", got["findings"])
	}
}

func TestUploadWithoutAManifestIsUnverifiedAndNotAnError(t *testing.T) {
	// The CLI treats an absent manifest as unverified rather than as a failure, and an upload has
	// to agree: a browser can only send what the analyst selected, and the manifest is the file
	// they are most likely to leave behind.
	srv := reportServer(t, &fakeReports{})
	res := upload(t, srv.URL+"/api/cases/1/reports", map[string]string{"report": uploadReportJSON})
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d, want 201", res.StatusCode)
	}
	if got := decodeResult(t, res); got["integrity"] != report.IntegrityUnverified {
		t.Errorf("integrity = %v, want %q", got["integrity"], report.IntegrityUnverified)
	}
}

func TestUploadWithAMatchingManifestIsVerified(t *testing.T) {
	srv := reportServer(t, &fakeReports{})
	manifest := fmt.Sprintf(`{"report.json": %q}`, report.Sum([]byte(uploadReportJSON)))

	res := upload(t, srv.URL+"/api/cases/1/reports", map[string]string{
		"report": uploadReportJSON, "manifest": manifest,
	})
	if got := decodeResult(t, res); got["integrity"] != report.IntegrityVerified {
		t.Errorf("integrity = %v, want %q", got["integrity"], report.IntegrityVerified)
	}
}

func TestUploadWithADisagreeingManifestIsStoredAndMarkedAltered(t *testing.T) {
	// The design's rule: a report that does not match its manifest is KEPT, because refusing it
	// would discard evidence from a live engagement. What the analyst needs is to read it and to
	// know it does not match.
	srv := reportServer(t, &fakeReports{})
	res := upload(t, srv.URL+"/api/cases/1/reports", map[string]string{
		"report":   uploadReportJSON,
		"manifest": `{"report.json": "0000000000000000000000000000000000000000000000000000000000000000"}`,
	})
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d, want 201 -- an altered report is stored, not refused", res.StatusCode)
	}
	if got := decodeResult(t, res); got["integrity"] != report.IntegrityAltered {
		t.Errorf("integrity = %v, want %q", got["integrity"], report.IntegrityAltered)
	}
}

func TestUploadWithoutTheReportPartSaysWhatToAttach(t *testing.T) {
	srv := reportServer(t, &fakeReports{})
	res := upload(t, srv.URL+"/api/cases/1/reports", map[string]string{"manifest": `{}`})
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", res.StatusCode)
	}
	if body := decodeResult(t, res); !strings.Contains(fmt.Sprint(body["error"]), "report.json") {
		t.Errorf("error = %v, want it to name report.json", body["error"])
	}
}

func TestUploadOfSomethingThatIsNotAReportIsRejectedAsContent(t *testing.T) {
	// 422, not 400: the request was well-formed and the DOCUMENT was refused. The console already
	// draws this line for rule text, and an analyst who picked summary.txt by mistake needs to be
	// told their file was wrong, not that their console is broken.
	srv := reportServer(t, &fakeReports{})
	res := upload(t, srv.URL+"/api/cases/1/reports", map[string]string{"report": "not json at all"})
	if res.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422", res.StatusCode)
	}
}

func TestReUploadingTheSameRunIsNotAFailure(t *testing.T) {
	// Bulk import is the primary import and an analyst re-sending a folder is ordinary. 200 says
	// the run is filed under this case, which is true; `created` says whether it was new.
	srv := reportServer(t, &fakeReports{alreadyPresent: true})
	res := upload(t, srv.URL+"/api/cases/1/reports", map[string]string{"report": uploadReportJSON})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 for a run already present", res.StatusCode)
	}
	if got := decodeResult(t, res); got["created"] != false {
		t.Errorf("created = %v, want false", got["created"])
	}
}

func TestUploadReportsTheStoreFailureRatherThanClaimingSuccess(t *testing.T) {
	srv := reportServer(t, &fakeReports{ingestErr: errors.New("storing scan r1: connection refused")})
	res := upload(t, srv.URL+"/api/cases/1/reports", map[string]string{"report": uploadReportJSON})
	if res.StatusCode == http.StatusOK || res.StatusCode == http.StatusCreated {
		t.Fatalf("status = %d, want a failure", res.StatusCode)
	}
	if body := decodeResult(t, res); !strings.Contains(fmt.Sprint(body["error"]), "connection refused") {
		t.Errorf("error = %v, want the store's own message", body["error"])
	}
}

func TestUploadRecordsWhereTheBytesCameFrom(t *testing.T) {
	// The CLI records the run folder path as the source. An upload has no path, so it records the
	// filename the browser declared -- the audit trail should not go blank because the route in
	// changed.
	f := &fakeReports{}
	srv := reportServer(t, f)
	upload(t, srv.URL+"/api/cases/1/reports", map[string]string{"report": uploadReportJSON})
	if len(f.ingested) != 1 || !strings.HasPrefix(f.ingested[0].source, "upload:") {
		t.Fatalf("source = %q, want it to declare the upload", f.ingested[0].source)
	}
}

func TestUploadIsRefusedWhenTheConsoleHasNoIngester(t *testing.T) {
	// A nil ingester is a console built without intake. Saying so beats a nil dereference.
	//
	// The nil is passed as a literal rather than as a nil *fakeReports: a typed nil pointer in an
	// interface is NOT equal to nil, so the latter would sail past the guard and prove nothing.
	srv := httptest.NewServer(NewReportAPI(&fakeReports{}, nil).Routes())
	t.Cleanup(srv.Close)

	res := upload(t, srv.URL+"/api/cases/1/reports", map[string]string{"report": uploadReportJSON})
	if res.StatusCode != http.StatusNotImplemented {
		t.Fatalf("status = %d, want 501", res.StatusCode)
	}
}
