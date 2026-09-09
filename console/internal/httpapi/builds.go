// Agent generation over HTTP.
//
// The console assembles an agent from bytes it already holds and never compiles scanner code (G2).
// Everything about WHICH bytes lives in internal/agentgen; this file is the transport, the
// database, and the refusals that need a database to detect.
package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"shellsightconsole/internal/agentgen"
	"shellsightconsole/internal/store"
)

// BuildReader is the slice of the store this API needs. Narrow, so the test can fake it without a
// database -- the pattern rulesets_test.go uses.
//
// The method names are the store's own. GetRelease and ResolvedCount were added to the store for
// this API rather than named differently here: an interface method the concrete *store.PG cannot
// satisfy would compile in the test, against the fake, and fail only when main.go wires the real
// thing in.
type BuildReader interface {
	GetRelease(ctx context.Context, id int64) (store.Release, error)
	ReleaseFiles(ctx context.Context, releaseID int64) ([]store.ReleaseFile, error)
	GetRuleSet(ctx context.Context, id int64) (store.RuleSet, error)
	ResolvedCount(ctx context.Context, ruleSetID int64) (int, error)
	RecordBuild(ctx context.Context, b store.Build) (store.Build, error)
	ListBuilds(ctx context.Context) ([]store.Build, error)
	BuildByID(ctx context.Context, id int64) (store.Build, error)
	Audit(ctx context.Context, actor, action, subject string, detail any) error
}

// BlobReader is the read half of the blob store. Split out because a route that only fetches
// release bytes should not be handed the ability to write new ones: /api/releases/{id}/components
// takes this, and only generation takes Blobs.
type BlobReader interface {
	Get(key string) ([]byte, error)
}

// Blobs is the blob store, as agent generation uses it.
type Blobs interface {
	BlobReader
	Put(data []byte) (string, error)
}

// BuildAPI serves agent generation.
type BuildAPI struct {
	reader BuildReader
	blobs  Blobs
	// now is a field, not a call to time.Now inline, so a test can pin it.
	//
	// It has to be replaceable rather than merely named: agent.json carries generated_at, agent.json
	// is INSIDE the archive, and the build id is derived from the archive's inputs -- so the clock
	// is an input to the bytes. G6's "identical inputs produce identical bytes" is only checkable
	// from out here if the clock can be held still, and a plain function could not be substituted.
	now func() time.Time
}

func NewBuildAPI(reader BuildReader, blobs Blobs) *BuildAPI {
	return NewBuildAPIWithClock(reader, blobs, func() time.Time { return time.Now().UTC() })
}

// NewBuildAPIWithClock is NewBuildAPI with the clock supplied. Only tests pass anything but the
// real one.
//
// It is exported for a reason the in-package `now` field could not serve. generated_at is stamped
// from this clock, it is an input to deriveBuildID, and agent.json is INSIDE the archive -- so two
// identical POSTs produce the same build id and the same bytes only when they land in the same
// clock SECOND, which is the resolution create formats at. An end-to-end test in another package
// asserting G6 without holding the clock still would pass because two requests happened to be a
// few milliseconds apart, and fail whenever they straddled a second boundary: the same coin toss
// already recorded once for the time.Now mutation, at 1 Hz instead of 200 Hz.
func NewBuildAPIWithClock(reader BuildReader, blobs Blobs, now func() time.Time) *BuildAPI {
	return &BuildAPI{reader: reader, blobs: blobs, now: now}
}

func (a *BuildAPI) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/builds", a.create)
	mux.HandleFunc("GET /api/builds", a.list)
	mux.HandleFunc("GET /api/builds/{id}/download", a.download)
	mux.HandleFunc("/", notFound)
	return mux
}

type buildRequest struct {
	ReleaseID       int64    `json:"release_id"`
	RuleSetID       *int64   `json:"rule_set_id"`
	Views           []string `json:"views"`
	ScanScope       []string `json:"scan_scope"`
	OutputFormat    string   `json:"output_format"`
	ProcessPriority string   `json:"process_priority"`
}

// releaseFiles adapts a release into agentgen.Files, verifying as it goes.
//
// The verification is the generation-time stand-in for internal/release.Verify, which needs an
// extracted directory and so cannot be used here. Publish already refused a file whose content
// disagreed with the manifest, so a disagreement now means the blob store changed underneath a
// recorded hash -- which is exactly the case that must not be assembled into an agent.
//
// File reports only "found" or "not found" because that is all agentgen.Files can say. The reason
// is kept in err, and the handler prefers it: Stage's own message is "this release does not hold
// it", which is the wrong diagnosis when the release holds the path and the bytes moved.
type releaseFiles struct {
	index map[string]string // path -> recorded sha256
	blobs BlobReader
	err   error
}

func (r *releaseFiles) File(path string) ([]byte, bool) {
	key, ok := r.index[path]
	if !ok {
		return nil, false
	}
	body, err := r.blobs.Get(key)
	if err != nil {
		r.err = fmt.Errorf("this release records %s but its content is not in the blob store", path)
		return nil, false
	}
	sum := sha256.Sum256(body)
	if got := hex.EncodeToString(sum[:]); got != key {
		r.err = fmt.Errorf(
			"%s does not match the hash this release recorded for it (recorded %s, content hashes "+
				"to %s), so the release cannot be built from", path, key, got)
		return nil, false
	}
	return body, true
}

func (a *BuildAPI) create(w http.ResponseWriter, r *http.Request) {
	var req buildRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "the request body is not valid JSON")
		return
	}
	ctx := r.Context()

	release, err := a.reader.GetRelease(ctx, req.ReleaseID)
	if err != nil {
		writeError(w, http.StatusNotFound, "no such release")
		return
	}
	rows, err := a.reader.ReleaseFiles(ctx, req.ReleaseID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "cannot read the release's files")
		return
	}
	files := &releaseFiles{index: map[string]string{}, blobs: a.blobs}
	for _, f := range rows {
		files.index[f.Path] = f.SHA256
	}

	gen := agentgen.Request{
		Files:        files,
		Views:        req.Views,
		ScanScope:    req.ScanScope,
		Release:      release.Version,
		OutputFormat: req.OutputFormat,
		Priority:     req.ProcessPriority,
		GeneratedAt:  a.now().Format("2006-01-02T15:04:05Z"),
		GeneratedBy:  actor(r),
	}

	if req.RuleSetID != nil {
		set, err := a.reader.GetRuleSet(ctx, *req.RuleSetID)
		if err != nil {
			writeError(w, http.StatusNotFound, "no such rule set")
			return
		}
		if set.YarcSHA256 == "" {
			writeError(w, http.StatusUnprocessableEntity,
				"this rule set is not frozen and has no compiled blob")
			return
		}
		count, err := a.reader.ResolvedCount(ctx, *req.RuleSetID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "cannot resolve the rule set")
			return
		}
		yarc, err := a.blobs.Get(set.YarcSHA256)
		if err != nil {
			writeError(w, http.StatusUnprocessableEntity,
				"this rule set's compiled blob is not in the blob store")
			return
		}
		gen.RuleSetName, gen.ResolvedRules, gen.Yarc = set.Name, count, yarc
		if set.Version != nil {
			gen.RuleSetVer = *set.Version
		}
	}

	result, err := agentgen.Build(gen)
	if err != nil {
		// files.err, when set, is the more specific cause: Build saw "the release does not hold it"
		// where the real reason was a hash disagreement.
		if files.err != nil {
			writeError(w, http.StatusUnprocessableEntity, files.err.Error())
			return
		}
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}

	key, err := a.blobs.Put(result.Archive)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "cannot store the generated archive")
		return
	}
	if key != result.SHA256 {
		writeError(w, http.StatusInternalServerError,
			"the stored archive hashes differently from the one just built")
		return
	}

	rec := store.Build{
		BuildID:     result.BuildID,
		ReleaseID:   req.ReleaseID,
		RuleSetID:   req.RuleSetID,
		Views:       result.Views,
		SHA256:      result.SHA256,
		SizeBytes:   int64(len(result.Archive)),
		AgentJSON:   result.AgentJSON,
		GeneratedBy: actor(r),
	}
	saved, err := a.reader.RecordBuild(ctx, rec)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "cannot record the build")
		return
	}
	_ = a.reader.Audit(ctx, actor(r), "agent.generate", result.BuildID, map[string]any{
		"release": release.Version, "target": release.Target,
		"views": result.Views, "sha256": result.SHA256,
	})
	writeJSON(w, http.StatusCreated, saved)
}

func (a *BuildAPI) list(w http.ResponseWriter, r *http.Request) {
	got, err := a.reader.ListBuilds(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "cannot list builds")
		return
	}
	if got == nil {
		got = []store.Build{}
	}
	writeJSON(w, http.StatusOK, got)
}

// download serves a recorded build's archive.
//
// Straight from the blob store, keyed by the sha256 the build row recorded -- the same arrangement
// the frozen .yarc download uses. The hash goes out in a header so a responder can verify what they
// were handed without asking again, and the filename identifies the build without being opened.
func (a *BuildAPI) download(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	b, err := a.reader.BuildByID(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "no such build")
		return
	}
	body, err := a.blobs.Get(b.SHA256)
	if err != nil {
		// Saying so is the only honest answer. Serving nothing with a 200 would hand the analyst a
		// zero-byte file called an agent.
		writeError(w, http.StatusGone,
			"this build's archive is no longer in the blob store; regenerate it")
		return
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("X-Agent-SHA256", b.SHA256)
	w.Header().Set("Content-Disposition",
		fmt.Sprintf("attachment; filename=%q", "agent-"+b.BuildID+".zip"))
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	if _, err := w.Write(body); err != nil {
		return
	}
}
