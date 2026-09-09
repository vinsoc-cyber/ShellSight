package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path/filepath"

	"shellsightconsole/internal/reports"
	"shellsightconsole/internal/store"
	"shellsightconsole/internal/triage"
)

type ReportStore interface {
	CreateCase(ctx context.Context, name, createdBy string) (int64, error)
	ListCases(ctx context.Context) ([]store.Case, error)
	ListScans(ctx context.Context, caseID int64) ([]store.ScanRecord, error)
	GetScan(ctx context.Context, scanID int64) (store.ScanRecord, error)
	FindingsForScan(ctx context.Context, scanID int64) ([]store.FindingRecord, error)
	CoverageForScan(ctx context.Context, scanID int64) ([]store.CoverageRecord, error)
	DecisionsFor(ctx context.Context, contentKeys []string) (map[string][]store.Decision, error)
	RecordDecision(ctx context.Context, d store.Decision) (int64, error)
}

// Ingester stores one uploaded report. Satisfied by *reports.Service, and kept as an interface
// here so this package does not depend on the ingest service to be constructed or tested.
type Ingester interface {
	Ingest(ctx context.Context, caseID int64, report, manifest []byte, source string) (reports.Result, error)
}

type ReportAPI struct {
	store ReportStore
	// May be nil: an API constructed without an ingester still serves every read. Upload then
	// answers 501 saying so, which is a truthful account of a console built without it rather
	// than a nil dereference.
	ingest Ingester
}

func NewReportAPI(s ReportStore, ing Ingester) *ReportAPI {
	return &ReportAPI{store: s, ingest: ing}
}

func (a *ReportAPI) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/cases", a.listCases)
	mux.HandleFunc("POST /api/cases", a.createCase)
	mux.HandleFunc("GET /api/cases/{id}/scans", a.listScans)
	mux.HandleFunc("POST /api/cases/{id}/reports", a.uploadReport)
	mux.HandleFunc("GET /api/scans/{id}", a.scanView)
	mux.HandleFunc("GET /api/scans/{id}/findings", a.findings)
	mux.HandleFunc("POST /api/decisions", a.recordDecision)
	mux.HandleFunc("/", notFound)
	return mux
}

// maxUploadBytes caps one uploaded report.
//
// A report is JSON with one object per finding; the largest observed in this repo's own runs is
// well under a megabyte, and 64 MiB is roughly a quarter of a million findings. The cap exists so
// an unbounded read cannot exhaust the console's memory, not because a real report approaches it.
const maxUploadBytes = 64 << 20

// uploadReport ingests one run's report.json, posted as multipart/form-data.
//
// Two parts: `report` (required) and `manifest` (optional). The manifest is what makes the
// difference between "verified" and "unverified", so it is offered rather than assumed -- and its
// absence is not an error, exactly as it is not an error for the CLI.
//
// Multipart rather than a JSON body carrying both: report.json is already JSON, and nesting it
// inside another JSON document would mean base64 or escaping a document that can be megabytes.
func (a *ReportAPI) uploadReport(w http.ResponseWriter, r *http.Request) {
	caseID, ok := pathID(w, r)
	if !ok {
		return
	}
	if a.ingest == nil {
		writeError(w, http.StatusNotImplemented, "this console was built without report ingest")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxUploadBytes)
	if err := r.ParseMultipartForm(8 << 20); err != nil {
		// MaxBytesReader's error arrives here, so say which limit was hit rather than the
		// generic parse failure an analyst cannot act on.
		writeError(w, http.StatusBadRequest,
			fmt.Sprintf("could not read the upload (the limit is %d MiB per report): %v",
				maxUploadBytes>>20, err))
		return
	}
	defer func() { _ = r.MultipartForm.RemoveAll() }()

	body, name, err := formFile(r, "report")
	if err != nil {
		writeError(w, http.StatusBadRequest, "attach the run folder's report.json as `report`")
		return
	}
	// An absent manifest is the unverified case and must not fail the upload.
	manifest, _, _ := formFile(r, "manifest")

	res, err := a.ingest.Ingest(r.Context(), caseID, body, manifest, "upload:"+name)
	if err != nil {
		// A report that will not parse is a REJECTED DOCUMENT, not a broken request: the analyst
		// picked the wrong file, and 422 is what the console already uses to say so.
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	// Re-uploading a run is ordinary -- bulk import is the primary import, and an analyst
	// dragging the same folder twice must not look like a failure. 200 says "this run is filed
	// under this case", which is true either way; res.created says whether it was new.
	code := http.StatusOK
	if res.Created {
		code = http.StatusCreated
	}
	writeJSON(w, code, res)
}

// formFile reads one multipart part whole, and reports its declared filename for the audit trail.
func formFile(r *http.Request, field string) ([]byte, string, error) {
	f, hdr, err := r.FormFile(field)
	if err != nil {
		return nil, "", err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(f)
	if err != nil {
		return nil, "", err
	}
	return b, filepath.Base(hdr.Filename), nil
}

func (a *ReportAPI) listCases(w http.ResponseWriter, r *http.Request) {
	got, err := a.store.ListCases(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if got == nil {
		got = []store.Case{}
	}
	writeJSON(w, http.StatusOK, got)
}

func (a *ReportAPI) createCase(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil || b.Name == "" {
		writeError(w, http.StatusBadRequest, "a case needs a name")
		return
	}
	id, err := a.store.CreateCase(r.Context(), b.Name, actor(r))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]int64{"id": id})
}

func (a *ReportAPI) listScans(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	got, err := a.store.ListScans(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if got == nil {
		got = []store.ScanRecord{}
	}
	writeJSON(w, http.StatusOK, got)
}

// scanView returns the verdict and the coverage TOGETHER, in one response, deliberately.
//
// A verdict rendered without its coverage is how a scanner tells a comfortable lie: "clean" over a
// webroot where 398 files were unreadable is not clean. Making them separate endpoints would let a
// client show one without the other.
func (a *ReportAPI) scanView(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	cov, err := a.store.CoverageForScan(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if cov == nil {
		cov = []store.CoverageRecord{}
	}
	sc, err := a.store.GetScan(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "no such scan")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"scan": sc,
		"verdict": map[string]any{
			"tier": sc.Tier, "score": sc.Score, "incomplete": sc.Incomplete,
		},
		"coverage": cov,
	})
}

// findings returns groups, not rows: one item per piece of content, worst first, each carrying any
// prior judgement the team has already made about that content.
func (a *ReportAPI) findings(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	rows, err := a.store.FindingsForScan(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	groups := triage.Groups(rows)

	keys := make([]string, 0, len(groups))
	for _, g := range groups {
		keys = append(keys, g.ContentKey)
	}
	priors, err := a.store.DecisionsFor(r.Context(), keys)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	out := make([]map[string]any, 0, len(groups))
	for _, g := range groups {
		p := priors[g.ContentKey]
		if p == nil {
			p = []store.Decision{}
		}
		out = append(out, map[string]any{
			"content_key": g.ContentKey, "tier": g.Tier, "score": g.Score,
			"locations": g.Locations, "hosts": g.Hosts, "rules": g.Rules,
			"findings": g.Findings, "prior_decisions": p,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

var validVerdicts = map[string]bool{
	"malicious": true, "false-positive": true, "benign-noteworthy": true, "undecided": true,
}

func (a *ReportAPI) recordDecision(w http.ResponseWriter, r *http.Request) {
	var b struct {
		ContentKey string `json:"content_key"`
		Verdict    string `json:"verdict"`
		Note       string `json:"note"`
		CaseID     *int64 `json:"case_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		writeError(w, http.StatusBadRequest, "request body is not valid JSON")
		return
	}
	if b.ContentKey == "" {
		writeError(w, http.StatusBadRequest, "a decision needs a content_key")
		return
	}
	if !validVerdicts[b.Verdict] {
		writeError(w, http.StatusBadRequest,
			"verdict must be malicious, false-positive, benign-noteworthy or undecided")
		return
	}
	id, err := a.store.RecordDecision(r.Context(), store.Decision{
		ContentKey: b.ContentKey, Verdict: b.Verdict, Note: b.Note,
		Author: actor(r), CaseID: b.CaseID,
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]int64{"id": id})
}
