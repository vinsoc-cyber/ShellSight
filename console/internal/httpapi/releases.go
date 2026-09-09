package httpapi

import (
	"context"
	"net/http"

	"shellsightconsole/internal/agentgen"
	"shellsightconsole/internal/store"
)

type ReleaseStore interface {
	PublishRelease(ctx context.Context, r store.Release, files []store.ReleaseFile) (int64, error)
	ListReleases(ctx context.Context) ([]store.Release, error)
	// GetRelease is here so /components can tell an unpublished release from a published one that
	// carries no declaration. ReleaseFiles reports no error for an unknown id -- it selects zero
	// rows -- so without this the two are indistinguishable.
	GetRelease(ctx context.Context, id int64) (store.Release, error)
	ReleaseFiles(ctx context.Context, releaseID int64) ([]store.ReleaseFile, error)
	Audit(ctx context.Context, actor, action, subject string, detail any) error
}

type ReleaseAPI struct {
	store ReleaseStore
	blobs BlobReader
}

func NewReleaseAPI(s ReleaseStore, blobs BlobReader) *ReleaseAPI {
	return &ReleaseAPI{store: s, blobs: blobs}
}

func (a *ReleaseAPI) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/releases", a.list)
	mux.HandleFunc("GET /api/releases/{id}/files", a.files)
	mux.HandleFunc("GET /api/releases/{id}/components", a.components)
	mux.HandleFunc("/", notFound)
	return mux
}

func (a *ReleaseAPI) list(w http.ResponseWriter, r *http.Request) {
	rels, err := a.store.ListReleases(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if rels == nil {
		rels = []store.Release{}
	}
	writeJSON(w, http.StatusOK, rels)
}

// files lists what a release holds: every path and the sha256 recorded for it.
//
// This existed in the store and in the interface above with no route serving it -- mounted at the
// exact path only, so nothing could reach it. The generate form needs it to learn a release's
// components.json, which is what says which views the release can even build.
//
// It reports the recorded hashes, not the blob contents. A path here is data that arrived from
// outside the console and is never echoed into a filesystem operation.
func (a *ReleaseAPI) files(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	got, err := a.store.ReleaseFiles(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "no such release")
		return
	}
	if got == nil {
		got = []store.ReleaseFile{}
	}
	writeJSON(w, http.StatusOK, got)
}

// components serves the scanner's own declaration of what each view needs, read out of the
// release's blobs and returned parsed.
//
// Parsed rather than as the stored bytes, and served here rather than left to the browser to
// assemble from /files plus a blob fetch, for four reasons:
//
//  1. Nothing serves a blob by hash, and nothing should. A generic /api/blobs/{sha256} would hand
//     out every release binary, every compiled rule set and every stored report to anyone holding
//     a hash -- a far wider surface than one parsed document, for one caller's convenience.
//  2. The schema check belongs on the server. A declaration this console does not understand is
//     refused once here, rather than rendered by a form that reads `rules` and `host_requires` as
//     if a newer document still meant the same thing by them.
//  3. api/http.ts always calls res.json(), so raw blob bytes could not come back through the
//     frontend's wrapper anyway.
//  4. It is one round trip, and the recorded hash is verified on the way past.
//
// Re-marshalling through agentgen.Components also means the response states what the console
// UNDERSTOOD, not what the document happened to contain: an unknown field is dropped rather than
// forwarded to a client that would have to decide what to do with it.
func (a *ReleaseAPI) components(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	if _, err := a.store.GetRelease(ctx, id); err != nil {
		writeError(w, http.StatusNotFound, "no such release")
		return
	}
	rows, err := a.store.ReleaseFiles(ctx, id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "cannot read the release's files")
		return
	}
	// The same adapter POST /api/builds resolves a release through, so the declaration the form
	// reads is verified exactly as the one the build is assembled from -- and a hash disagreement
	// is reported the same way in both places.
	files := &releaseFiles{index: map[string]string{}, blobs: a.blobs}
	for _, f := range rows {
		files.index[f.Path] = f.SHA256
	}
	doc, err := agentgen.LoadComponents(files)
	if err != nil {
		// files.err is the more specific cause when it is set: LoadComponents can only say the
		// release carries no declaration, which is the wrong diagnosis when it records the path
		// and the bytes underneath it moved.
		if files.err != nil {
			writeError(w, http.StatusUnprocessableEntity, files.err.Error())
			return
		}
		// 422, not 404: the release exists. It cannot be generated from, which is a fact about its
		// contents rather than about whether it was published.
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, doc)
}
