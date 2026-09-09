package httpapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"shellsightconsole/internal/store"
)

var errNoBlob = errors.New("no such blob")

type fakeBuildDeps struct {
	files     []store.ReleaseFile
	release   store.Release
	set       store.RuleSet
	resolved  int
	blobs     map[string][]byte
	recorded  []store.Build
	recordErr error
}

func (f *fakeBuildDeps) GetRelease(_ context.Context, id int64) (store.Release, error) {
	return f.release, nil
}
func (f *fakeBuildDeps) ReleaseFiles(_ context.Context, id int64) ([]store.ReleaseFile, error) {
	return f.files, nil
}
func (f *fakeBuildDeps) GetRuleSet(_ context.Context, id int64) (store.RuleSet, error) {
	return f.set, nil
}
func (f *fakeBuildDeps) ResolvedCount(_ context.Context, id int64) (int, error) {
	return f.resolved, nil
}
func (f *fakeBuildDeps) RecordBuild(_ context.Context, b store.Build) (store.Build, error) {
	if f.recordErr != nil {
		return store.Build{}, f.recordErr
	}
	// Match RecordBuild's real contract: an identical build id is the same artefact, and the
	// recorded row comes back rather than a second one being made.
	for _, existing := range f.recorded {
		if existing.BuildID == b.BuildID {
			return existing, nil
		}
	}
	b.ID = int64(len(f.recorded) + 1)
	f.recorded = append(f.recorded, b)
	return b, nil
}
func (f *fakeBuildDeps) ListBuilds(_ context.Context) ([]store.Build, error) {
	return f.recorded, nil
}
func (f *fakeBuildDeps) BuildByID(_ context.Context, id int64) (store.Build, error) {
	for _, b := range f.recorded {
		if b.ID == id {
			return b, nil
		}
	}
	return store.Build{}, errNoBlob
}
func (f *fakeBuildDeps) Audit(_ context.Context, actor, action, subject string, detail any) error {
	return nil
}
func (f *fakeBuildDeps) Get(key string) ([]byte, error) {
	b, ok := f.blobs[key]
	if !ok {
		return nil, errNoBlob
	}
	return b, nil
}
func (f *fakeBuildDeps) Put(data []byte) (string, error) {
	key := store.Sum64(string(data))
	f.blobs[key] = data
	return key, nil
}

const componentsForTest = `{"schema_version":"1","target":"linux-amd64","release":"v1",
  "always":["shellsight"],
  "views":{"disk":{"binaries":["diskprobe","third_party/yara-x/yr"],
                   "data":["kb/rules/foundation"],"rules":true},
           "java-mem":{"binaries":["jvmprobe"],"rules":false}}}`

func buildDeps() *fakeBuildDeps {
	yarc := []byte("compiled")
	blobs := map[string][]byte{}
	add := func(body string) string {
		k := store.Sum64(body)
		blobs[k] = []byte(body)
		return k
	}
	files := []store.ReleaseFile{
		{Path: "components.json", SHA256: add(componentsForTest)},
		{Path: "shellsight", SHA256: add("orchestrator")},
		{Path: "diskprobe", SHA256: add("probe")},
		{Path: "third_party/yara-x/yr", SHA256: add("yr")},
		{Path: "jvmprobe", SHA256: add("jvm")},
	}
	blobs[store.Sum64(string(yarc))] = yarc
	ver := 3
	return &fakeBuildDeps{
		files:    files,
		release:  store.Release{ID: 1, Version: "v1", Target: "linux-amd64"},
		set:      store.RuleSet{ID: 9, Name: "sweep-acme", Version: &ver, YarcSHA256: store.Sum64(string(yarc))},
		resolved: 5872,
		blobs:    blobs,
		recorded: []store.Build{},
	}
}

func buildServer(t *testing.T, deps *fakeBuildDeps) *httptest.Server {
	t.Helper()
	api := NewBuildAPI(deps, deps)
	// Pin the clock. agent.json carries generated_at and agent.json is INSIDE the archive, so an
	// unpinned clock makes the archive's bytes -- and the id derived from them -- a function of
	// when the test ran. G6 is the reason this is injectable at all.
	api.now = func() time.Time { return time.Date(2026, 9, 4, 11, 22, 33, 0, time.UTC) }
	srv := httptest.NewServer(api.Routes())
	t.Cleanup(srv.Close)
	return srv
}

func postBuild(t *testing.T, srv *httptest.Server, body string) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest("POST", srv.URL+"/api/builds", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Console-Actor", "v.quannh67")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(res.Body); err != nil {
		t.Fatal(err)
	}
	return res, buf.String()
}

func TestPostBuildGeneratesRecordsAndReturnsTheBuild(t *testing.T) {
	deps := buildDeps()
	srv := buildServer(t, deps)
	res, body := postBuild(t, srv,
		`{"release_id":1,"rule_set_id":9,"views":["disk"],"output_format":"json","process_priority":"low"}`)
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body = %s", res.StatusCode, body)
	}
	var got store.Build
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(got.BuildID, "b-") {
		t.Errorf("BuildID = %q", got.BuildID)
	}
	if len(got.SHA256) != 64 {
		t.Errorf("SHA256 = %q", got.SHA256)
	}
	if got.SizeBytes == 0 {
		t.Error("SizeBytes is zero")
	}
	if len(deps.recorded) != 1 {
		t.Fatalf("recorded %d builds", len(deps.recorded))
	}
	if deps.recorded[0].GeneratedBy != "v.quannh67" {
		t.Errorf("GeneratedBy = %q; the actor header must reach the record",
			deps.recorded[0].GeneratedBy)
	}
	// The record must name the rule set it was built from, or "what was this agent" cannot be
	// answered from the row months later.
	if deps.recorded[0].RuleSetID == nil || *deps.recorded[0].RuleSetID != 9 {
		t.Errorf("RuleSetID = %v, want 9", deps.recorded[0].RuleSetID)
	}
	// The archive must be in the blob store, keyed by its own hash, or the download route has
	// nothing to serve.
	if _, ok := deps.blobs[got.SHA256]; !ok {
		t.Error("the generated archive was not stored under its own hash")
	}
	// agent_json is recorded verbatim, and it is what the scanner reads on the host. Asserting on
	// it here is what makes the record's claim about the artefact checkable.
	var cfg struct {
		BuildID      string  `json:"build_id"`
		GeneratedAt  string  `json:"generated_at"`
		GeneratedBy  string  `json:"generated_by"`
		Release      string  `json:"release"`
		OutputFormat *string `json:"output_format"`
	}
	if err := json.Unmarshal(deps.recorded[0].AgentJSON, &cfg); err != nil {
		t.Fatalf("the recorded agent_json is not JSON: %v", err)
	}
	if cfg.BuildID != got.BuildID {
		t.Errorf("agent_json build_id %q is not the recorded one %q", cfg.BuildID, got.BuildID)
	}
	if cfg.Release != "v1" {
		t.Errorf("agent_json release = %q, want v1", cfg.Release)
	}
	if cfg.GeneratedBy != "v.quannh67" {
		t.Errorf("agent_json generated_by = %q", cfg.GeneratedBy)
	}
	if cfg.GeneratedAt != "2026-09-04T11:22:33Z" {
		t.Errorf("agent_json generated_at = %q; the handler clock must reach it", cfg.GeneratedAt)
	}
	if cfg.OutputFormat == nil || *cfg.OutputFormat != "json" {
		t.Errorf("agent_json output_format = %v; the request choice must reach it", cfg.OutputFormat)
	}
}

// G6 through the transport, not only inside agentgen. The clock and the operator are what the
// HANDLER injects, so the handler is where a reproducible build can be broken without any test in
// agentgen noticing.
func TestPostingTheSameBuildTwiceProducesTheSameArchive(t *testing.T) {
	deps := buildDeps()
	srv := buildServer(t, deps)
	req := `{"release_id":1,"rule_set_id":9,"views":["disk"],"output_format":"json"}`
	_, first := postBuild(t, srv, req)
	_, second := postBuild(t, srv, req)
	var a, b store.Build
	if err := json.Unmarshal([]byte(first), &a); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(second), &b); err != nil {
		t.Fatal(err)
	}
	if a.BuildID == "" || a.BuildID != b.BuildID {
		t.Errorf("the same request produced two build ids: %q then %q", a.BuildID, b.BuildID)
	}
	if a.SHA256 == "" || a.SHA256 != b.SHA256 {
		t.Errorf("the same request produced two archives: %s then %s", a.SHA256, b.SHA256)
	}
	if len(deps.recorded) != 1 {
		t.Errorf("recorded %d rows for one repeated build", len(deps.recorded))
	}
}

func TestPostBuildRefusesARuleSetThatIsNotFrozen(t *testing.T) {
	deps := buildDeps()
	deps.set.YarcSHA256 = ""
	deps.set.Version = nil
	res, body := postBuild(t, buildServer(t, deps),
		`{"release_id":1,"rule_set_id":9,"views":["disk"]}`)
	if res.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422; body = %s", res.StatusCode, body)
	}
	if !strings.Contains(body, "frozen") {
		t.Errorf("the message must say the set is not frozen: %s", body)
	}
	if len(deps.recorded) != 0 {
		t.Error("a refused build was recorded")
	}
}

func TestPostBuildRefusesARuleSetResolvingToZeroRules(t *testing.T) {
	deps := buildDeps()
	deps.resolved = 0
	res, body := postBuild(t, buildServer(t, deps),
		`{"release_id":1,"rule_set_id":9,"views":["disk"]}`)
	if res.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422; body = %s", res.StatusCode, body)
	}
	if !strings.Contains(body, "no rules") {
		t.Errorf("the message must say why: %s", body)
	}
}

func TestPostBuildRefusesAViewTheTargetDoesNotSupport(t *testing.T) {
	res, body := postBuild(t, buildServer(t, buildDeps()),
		`{"release_id":1,"rule_set_id":9,"views":["dotnet-mem"]}`)
	if res.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422; body = %s", res.StatusCode, body)
	}
	if !strings.Contains(body, "dotnet-mem") {
		t.Errorf("the message must name the view: %s", body)
	}
}

// The generation-time equivalent of release verification. release.Verify needs an extracted
// directory and there is none here, so the check is that a blob's content still hashes to what
// release_files recorded.
func TestPostBuildRefusesAReleaseWhoseBlobDisagreesWithItsRecordedHash(t *testing.T) {
	deps := buildDeps()
	// Corrupt the stored bytes without changing the recorded hash.
	for _, f := range deps.files {
		if f.Path == "diskprobe" {
			deps.blobs[f.SHA256] = []byte("tampered")
		}
	}
	res, body := postBuild(t, buildServer(t, deps),
		`{"release_id":1,"rule_set_id":9,"views":["disk"]}`)
	if res.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422; body = %s", res.StatusCode, body)
	}
	if !strings.Contains(body, "diskprobe") {
		t.Errorf("the message must name the file: %s", body)
	}
	// And it must not read as "the release does not hold it", which is the message Stage produces
	// and the wrong diagnosis: the release holds the file, the bytes changed underneath the
	// recorded hash. Without this the test passes on Stage's message alone and the whole
	// re-hashing check could be deleted unnoticed.
	if strings.Contains(body, "does not hold") {
		t.Errorf("a hash disagreement was reported as a missing file: %s", body)
	}
	if len(deps.recorded) != 0 {
		t.Error("a build over a tampered release was recorded")
	}
}

// A blob that is entirely absent is a different fault from one whose content changed, and the
// message has to distinguish them or an operator cannot tell a pruned store from a tampered one.
func TestPostBuildRefusesAReleaseWhoseBlobIsAbsent(t *testing.T) {
	deps := buildDeps()
	for _, f := range deps.files {
		if f.Path == "diskprobe" {
			delete(deps.blobs, f.SHA256)
		}
	}
	res, body := postBuild(t, buildServer(t, deps),
		`{"release_id":1,"rule_set_id":9,"views":["disk"]}`)
	if res.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422; body = %s", res.StatusCode, body)
	}
	if !strings.Contains(body, "diskprobe") || !strings.Contains(body, "blob store") {
		t.Errorf("the message must name the file and say the content is not stored: %s", body)
	}
}

// A memory-only build takes no rule set. G3: the split is reachable through the API, not only in
// the package, even though the form does not offer it yet.
func TestPostBuildAcceptsAMemoryOnlyBuildWithNoRuleSet(t *testing.T) {
	deps := buildDeps()
	res, body := postBuild(t, buildServer(t, deps),
		`{"release_id":1,"views":["java-mem"]}`)
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body = %s", res.StatusCode, body)
	}
	if deps.recorded[0].RuleSetID != nil {
		t.Errorf("RuleSetID = %v, want nil", deps.recorded[0].RuleSetID)
	}
}

func TestPostBuildRejectsMalformedJSON(t *testing.T) {
	res, _ := postBuild(t, buildServer(t, buildDeps()), `{not json`)
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", res.StatusCode)
	}
}

func TestListBuildsReturnsAnArrayNotNull(t *testing.T) {
	srv := buildServer(t, buildDeps())
	res, err := http.Get(srv.URL + "/api/builds")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(res.Body); err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(buf.String()) == "null" {
		t.Error("an empty list must encode as [], never null")
	}
}

func TestDownloadServesTheArchiveWithAFilenameAndItsHash(t *testing.T) {
	deps := buildDeps()
	srv := buildServer(t, deps)
	res, body := postBuild(t, srv,
		`{"release_id":1,"rule_set_id":9,"views":["disk"]}`)
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("generate failed: %s", body)
	}
	var created store.Build
	if err := json.Unmarshal([]byte(body), &created); err != nil {
		t.Fatal(err)
	}

	dl, err := http.Get(fmt.Sprintf("%s/api/builds/%d/download", srv.URL, created.ID))
	if err != nil {
		t.Fatal(err)
	}
	defer dl.Body.Close()
	if dl.StatusCode != http.StatusOK {
		t.Fatalf("download status = %d", dl.StatusCode)
	}
	if got := dl.Header.Get("Content-Type"); got != "application/zip" {
		t.Errorf("Content-Type = %q, want application/zip", got)
	}
	// The filename is what lands in the analyst's downloads folder, and it has to identify the
	// build without being opened.
	cd := dl.Header.Get("Content-Disposition")
	if !strings.Contains(cd, created.BuildID) {
		t.Errorf("Content-Disposition %q does not name the build id", cd)
	}
	if !strings.Contains(cd, ".zip") {
		t.Errorf("Content-Disposition %q does not end in .zip", cd)
	}
	// The hash in a header, so a responder can check what they were handed without a second request.
	if got := dl.Header.Get("X-Agent-SHA256"); got != created.SHA256 {
		t.Errorf("X-Agent-SHA256 = %q, want %q", got, created.SHA256)
	}

	var buf bytes.Buffer
	if _, err := buf.ReadFrom(dl.Body); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(buf.Bytes())
	if hex.EncodeToString(sum[:]) != created.SHA256 {
		t.Error("the bytes served do not hash to the recorded sha256")
	}
	if int64(buf.Len()) != created.SizeBytes {
		t.Errorf("served %d bytes, record says %d", buf.Len(), created.SizeBytes)
	}
	// It is a zip, not merely bytes of the right length: PK is the local file header.
	if !bytes.HasPrefix(buf.Bytes(), []byte("PK")) {
		t.Errorf("the served body is not a zip archive: first bytes %q", buf.Bytes()[:4])
	}
}

// Serving by the RECORD's hash, not by anything the caller sends. Two builds exist here and the
// second one's bytes must come back for the second one's id -- a handler that served the newest
// row, or the first, passes a single-build test.
func TestDownloadServesTheArchiveOfTheBuildAsked(t *testing.T) {
	deps := buildDeps()
	srv := buildServer(t, deps)
	var builds []store.Build
	for _, req := range []string{
		`{"release_id":1,"rule_set_id":9,"views":["disk"]}`,
		`{"release_id":1,"views":["java-mem"]}`,
	} {
		res, body := postBuild(t, srv, req)
		if res.StatusCode != http.StatusCreated {
			t.Fatalf("generate failed: %s", body)
		}
		var b store.Build
		if err := json.Unmarshal([]byte(body), &b); err != nil {
			t.Fatal(err)
		}
		builds = append(builds, b)
	}
	if builds[0].SHA256 == builds[1].SHA256 {
		t.Fatal("the fixture produced two identical archives, so this test proves nothing")
	}
	for _, want := range builds {
		dl, err := http.Get(fmt.Sprintf("%s/api/builds/%d/download", srv.URL, want.ID))
		if err != nil {
			t.Fatal(err)
		}
		var buf bytes.Buffer
		if _, err := buf.ReadFrom(dl.Body); err != nil {
			t.Fatal(err)
		}
		dl.Body.Close()
		sum := sha256.Sum256(buf.Bytes())
		if got := hex.EncodeToString(sum[:]); got != want.SHA256 {
			t.Errorf("build %d (%s) served an archive hashing to %s",
				want.ID, want.BuildID, got)
		}
		if !strings.Contains(dl.Header.Get("Content-Disposition"), want.BuildID) {
			t.Errorf("build %d was served under another build's filename %q",
				want.ID, dl.Header.Get("Content-Disposition"))
		}
	}
}

func TestDownloadingAnUnknownBuildIs404(t *testing.T) {
	srv := buildServer(t, buildDeps())
	res, err := http.Get(srv.URL + "/api/builds/999/download")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", res.StatusCode)
	}
}

func TestDownloadingANonNumericBuildIs400(t *testing.T) {
	srv := buildServer(t, buildDeps())
	res, err := http.Get(srv.URL + "/api/builds/notanumber/download")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", res.StatusCode)
	}
	// The BODY, not only the status, and that is the point of asserting it.
	//
	// pathID writes its own 400 and returns false. A handler that ignored the false would carry on
	// with id 0, fail the lookup, and call writeError again -- but the status is already sent, so
	// the FIRST WriteHeader wins and the response still reads 400. Only the body shows it: two JSON
	// objects instead of one. Measured; the status-only assertion was inert against exactly that.
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(res.Body); err != nil {
		t.Fatal(err)
	}
	var body map[string]string
	dec := json.NewDecoder(bytes.NewReader(buf.Bytes()))
	if err := dec.Decode(&body); err != nil {
		t.Fatalf("error body is not JSON: %v", err)
	}
	if body["error"] != "id must be a number" {
		t.Errorf("error = %q, want the id-parse refusal", body["error"])
	}
	if dec.More() {
		t.Errorf("the response carries more than one JSON object -- the handler kept going after "+
			"pathID refused: %s", buf.String())
	}
}

// The recorded hash is the blob key. If the blob is gone, saying so is the only honest answer --
// serving nothing with a 200 would hand the analyst a zero-byte file called an agent.
func TestDownloadWhoseBlobIsMissingFailsLoudly(t *testing.T) {
	deps := buildDeps()
	srv := buildServer(t, deps)
	_, body := postBuild(t, srv, `{"release_id":1,"rule_set_id":9,"views":["disk"]}`)
	var created store.Build
	if err := json.Unmarshal([]byte(body), &created); err != nil {
		t.Fatal(err)
	}
	delete(deps.blobs, created.SHA256)

	res, err := http.Get(fmt.Sprintf("%s/api/builds/%d/download", srv.URL, created.ID))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusOK {
		t.Fatal("a build whose archive is gone must not download as 200")
	}
	// And it must not answer with an empty body and a success-shaped status either. 410 says the
	// artefact was here and is not any more, which is the difference between "regenerate it" and
	// "you asked for the wrong id".
	if res.StatusCode != http.StatusGone {
		t.Errorf("status = %d, want 410", res.StatusCode)
	}
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(res.Body); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "regenerate") {
		t.Errorf("the message must tell the analyst what to do: %s", buf.String())
	}
}
