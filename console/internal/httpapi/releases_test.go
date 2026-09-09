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

	"shellsightconsole/internal/agentgen"
	"shellsightconsole/internal/store"
)

type fakeReleases struct {
	published []store.Release
	files     []store.ReleaseFile
	blobs     map[string][]byte
}

func (f *fakeReleases) PublishRelease(_ context.Context, r store.Release, files []store.ReleaseFile) (int64, error) {
	r.ID = int64(len(f.published) + 1)
	f.published = append(f.published, r)
	f.files = files
	return r.ID, nil
}
func (f *fakeReleases) ListReleases(context.Context) ([]store.Release, error) {
	return f.published, nil
}
func (f *fakeReleases) ReleaseFiles(context.Context, int64) ([]store.ReleaseFile, error) {
	return f.files, nil
}

// Mirrors the real store: an id with no row is an error, which is how the route tells "not
// published" from "published and carrying nothing".
func (f *fakeReleases) GetRelease(_ context.Context, id int64) (store.Release, error) {
	for _, r := range f.published {
		if r.ID == id {
			return r, nil
		}
	}
	return store.Release{}, errors.New("no rows in result set")
}

func (f *fakeReleases) Get(key string) ([]byte, error) {
	b, ok := f.blobs[key]
	if !ok {
		return nil, errors.New("no such blob")
	}
	return b, nil
}
func (f *fakeReleases) Audit(context.Context, string, string, string, any) error { return nil }

func TestListReleasesReturnsJSON(t *testing.T) {
	f := &fakeReleases{published: []store.Release{
		{ID: 1, Version: "v1.0.0-231", Target: "linux-amd64", PublishedBy: "a"},
	}}
	srv := httptest.NewServer(NewReleaseAPI(f, f).Routes())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/api/releases")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d, want 200", resp.StatusCode)
	}
	var got []store.Release
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Target != "linux-amd64" {
		t.Fatalf("got %+v", got)
	}
}

func TestUnknownRouteIs404AndNotAnHTMLErrorPage(t *testing.T) {
	f := &fakeReleases{}
	srv := httptest.NewServer(NewReleaseAPI(f, f).Routes())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/api/nope")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status %d, want 404", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content type %q, want application/json", ct)
	}
}

func TestErrorsAreJSONWithAMessage(t *testing.T) {
	rec := httptest.NewRecorder()
	writeError(rec, http.StatusBadRequest, "rule set 3 is already frozen")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code %d", rec.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("error body is not JSON: %v", err)
	}
	if body["error"] != "rule set 3 is already frozen" {
		t.Fatalf("got %+v", body)
	}
}

func TestReleaseFilesListsEveryPathAndItsHash(t *testing.T) {
	f := &fakeReleases{files: []store.ReleaseFile{
		{Path: "components.json", SHA256: "aa"},
		{Path: "shellsight", SHA256: "bb"},
	}}
	srv := httptest.NewServer(NewReleaseAPI(f, f).Routes())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/api/releases/7/files")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d, want 200", resp.StatusCode)
	}
	var got []store.ReleaseFile
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Path != "components.json" || got[0].SHA256 != "aa" {
		t.Fatalf("got %+v", got)
	}
}

// A release holding nothing must list as [], not null: the form iterates this to find
// components.json, and a null would be a crash rather than an empty list.
func TestReleaseFilesReturnsAnArrayNotNull(t *testing.T) {
	f := &fakeReleases{}
	srv := httptest.NewServer(NewReleaseAPI(f, f).Routes())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/api/releases/7/files")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var raw json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		t.Fatal(err)
	}
	if string(raw) != "[]" {
		t.Errorf("body = %s, want []", raw)
	}
}

// The id is parsed, not pasted: a non-numeric id is a 400 from pathID rather than a lookup with
// whatever the caller sent.
func TestReleaseFilesRejectsANonNumericID(t *testing.T) {
	f := &fakeReleases{}
	srv := httptest.NewServer(NewReleaseAPI(f, f).Routes())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/api/releases/notanumber/files")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status %d, want 400", resp.StatusCode)
	}
}

// --- GET /api/releases/{id}/components ---------------------------------------------------------

// A declaration good enough to answer the form's questions: one rules view and one memory view,
// the second carrying a host requirement, which is the string the form must show as its reason.
const releaseComponents = `{"schema_version":"1","target":"windows-amd64","release":"v1.0.0-231",
  "always":["shellsight.exe"],
  "views":{"disk":{"binaries":["diskprobe.exe"],"data":["kb/rules/own"],"rules":true},
           "java-mem":{"binaries":["javamem.jar"],"rules":false,
                       "host_requires":"a Java runtime on the target host"}}}`

// withComponents returns a fake release holding the declaration above, stored under its real hash.
func withComponents(doc string) *fakeReleases {
	key := store.Sum64(doc)
	return &fakeReleases{
		published: []store.Release{{ID: 1, Version: "v1.0.0-231", Target: "windows-amd64"}},
		files:     []store.ReleaseFile{{Path: "components.json", SHA256: key}},
		blobs:     map[string][]byte{key: []byte(doc)},
	}
}

func getComponents(t *testing.T, f *fakeReleases, path string) (*http.Response, []byte) {
	t.Helper()
	srv := httptest.NewServer(NewReleaseAPI(f, f).Routes())
	t.Cleanup(srv.Close)
	resp, err := http.Get(srv.URL + path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp, body
}

func TestReleaseComponentsReturnsTheParsedDeclaration(t *testing.T) {
	resp, body := getComponents(t, withComponents(releaseComponents), "/api/releases/1/components")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d, want 200: %s", resp.StatusCode, body)
	}
	var got agentgen.Components
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	if got.Target != "windows-amd64" || got.SchemaVersion != "1" {
		t.Fatalf("got %+v", got)
	}
	if len(got.Views) != 2 {
		t.Fatalf("views = %+v, want disk and java-mem", got.Views)
	}
	// The two facts the form cannot get anywhere else: which views scan with YARA, and why a view
	// it may not offer is unavailable.
	if !got.Views["disk"].Rules {
		t.Error(`disk.rules is false; the form derives "not applicable" from this flag`)
	}
	if got.Views["java-mem"].HostRequires != "a Java runtime on the target host" {
		t.Errorf("java-mem.host_requires = %q", got.Views["java-mem"].HostRequires)
	}
}

// A release that does not exist is a 404, not an empty declaration. ReleaseFiles returns no error
// for an unknown id -- it selects zero rows -- so without a lookup of the release itself this
// answers "this release carries no components.json", which sends an analyst looking for a
// packaging bug in a release that was never published.
func TestReleaseComponentsIs404ForAReleaseThatDoesNotExist(t *testing.T) {
	resp, body := getComponents(t, &fakeReleases{}, "/api/releases/99/components")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status %d, want 404: %s", resp.StatusCode, body)
	}
}

// A published release with no declaration in it predates agent generation. It exists, so it is not
// a 404; it cannot be built from, so it is not a 200 either.
func TestReleaseComponentsRefusesAReleaseWithNoDeclaration(t *testing.T) {
	f := &fakeReleases{
		published: []store.Release{{ID: 1, Version: "v0.9", Target: "linux-amd64"}},
		files:     []store.ReleaseFile{{Path: "shellsight", SHA256: store.Sum64("x")}},
		blobs:     map[string][]byte{},
	}
	resp, body := getComponents(t, f, "/api/releases/1/components")
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("status %d, want 422: %s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "components.json") {
		t.Errorf("body does not name the missing document: %s", body)
	}
}

// The generation-time stand-in for release.Verify, on this route too: the recorded hash and the
// stored bytes must still agree. The message has to be the SPECIFIC one -- "carries no
// components.json" is the wrong diagnosis when the release records the path and the bytes moved.
func TestReleaseComponentsRefusesADeclarationWhoseBytesMoved(t *testing.T) {
	f := withComponents(releaseComponents)
	for k := range f.blobs {
		f.blobs[k] = []byte(`{"schema_version":"1","target":"linux-amd64","release":"v1",` +
			`"always":["shellsight"],"views":{"disk":{"rules":true}}}`)
	}
	resp, body := getComponents(t, f, "/api/releases/1/components")
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("status %d, want 422: %s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "does not match the hash") {
		t.Errorf("body = %s, want the hash disagreement rather than a missing-document message", body)
	}
}

// A newer schema is refused by the server rather than handed to the browser to guess at. The form
// reads `rules` and `host_requires`; a document that means something else by those names would be
// rendered as if it did not.
func TestReleaseComponentsRefusesANewerSchema(t *testing.T) {
	resp, body := getComponents(t,
		withComponents(`{"schema_version":"2","target":"linux-amd64","release":"v1",`+
			`"always":["shellsight"],"views":{"disk":{"rules":true}}}`),
		"/api/releases/1/components")
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("status %d, want 422: %s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "schema_version") {
		t.Errorf("body = %s, want the schema refusal", body)
	}
}

func TestReleaseComponentsRejectsANonNumericID(t *testing.T) {
	resp, _ := getComponents(t, withComponents(releaseComponents), "/api/releases/x/components")
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status %d, want 400", resp.StatusCode)
	}
}
