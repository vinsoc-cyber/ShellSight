package httpapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"shellsightconsole/internal/blob"
	"shellsightconsole/internal/store"
)

type fakeSetSvc struct {
	hash       string
	err        error
	excludeErr error
}

func (f *fakeSetSvc) Freeze(context.Context, int64, int, string) (string, error) {
	return f.hash, f.err
}

func (f *fakeSetSvc) CheckExclusion(string) error { return f.excludeErr }

type fakeSetReader struct {
	set      store.RuleSet
	sel      store.Selection
	sets     []store.RuleSet
	members  []store.FrozenMember
	resolved []store.RuleRevision
}

func (f *fakeSetReader) FrozenMemberList(context.Context, int64) ([]store.FrozenMember, error) {
	return f.members, nil
}

func (f *fakeSetReader) ListRuleSets(context.Context) ([]store.RuleSet, error) {
	return f.sets, nil
}

func (f *fakeSetReader) GetRuleSet(context.Context, int64) (store.RuleSet, error) { return f.set, nil }
func (f *fakeSetReader) GetSelection(context.Context, int64) (store.Selection, error) {
	return f.sel, nil
}
func (f *fakeSetReader) SetSelection(_ context.Context, _ int64, sel store.Selection) error {
	f.sel = sel
	return nil
}
func (f *fakeSetReader) CreateRuleSet(context.Context, string, string) (int64, error)     { return 3, nil }
func (f *fakeSetReader) AddExclusion(context.Context, int64, int64, string, string) error { return nil }
func (f *fakeSetReader) ListExclusions(context.Context, int64) ([]store.Exclusion, error) {
	return nil, nil
}
func (f *fakeSetReader) ResolveSelection(context.Context, int64) ([]store.RuleRevision, error) {
	return f.resolved, nil
}
func (f *fakeSetReader) ListRules(context.Context, string) ([]store.Rule, error) { return nil, nil }

func setServer(t *testing.T, svc *fakeSetSvc, rd *fakeSetReader, bs *blob.Store) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(NewRuleSetAPI(svc, rd, bs).Routes())
	t.Cleanup(s.Close)
	return s
}

func TestFreezeReturnsTheBlobHash(t *testing.T) {
	hash := strings.Repeat("a", 64)
	srv := setServer(t, &fakeSetSvc{hash: hash}, &fakeSetReader{}, blob.New(t.TempDir()))

	resp, err := http.Post(srv.URL+"/api/rulesets/3/freeze", "application/json",
		strings.NewReader(`{"version":1}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d, want 200", resp.StatusCode)
	}
	var got map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&got)
	if got["yarc_sha256"] != hash {
		t.Fatalf("got %+v", got)
	}
}

func TestAFreezeThatDoesNotCompileIs422(t *testing.T) {
	srv := setServer(t,
		&fakeSetSvc{err: errCompile("rule compilation failed:\nerror[E001]: syntax error")},
		&fakeSetReader{}, blob.New(t.TempDir()))

	resp, err := http.Post(srv.URL+"/api/rulesets/3/freeze", "application/json",
		strings.NewReader(`{"version":1}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("status %d, want 422", resp.StatusCode)
	}
}

func TestDownloadingAFrozenBlobReturnsTheBytes(t *testing.T) {
	bs := blob.New(t.TempDir())
	hash, err := bs.Put([]byte("compiled-bytes"))
	if err != nil {
		t.Fatal(err)
	}
	rd := &fakeSetReader{set: store.RuleSet{ID: 3, Name: "s", YarcSHA256: hash}}
	srv := setServer(t, &fakeSetSvc{}, rd, bs)

	resp, err := http.Get(srv.URL + "/api/rulesets/3/yarc")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "compiled-bytes" {
		t.Fatalf("got %q", body)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/octet-stream" {
		t.Fatalf("content type %q", ct)
	}
}

func TestDownloadingAnUnfrozenSetIs404(t *testing.T) {
	rd := &fakeSetReader{set: store.RuleSet{ID: 3, Name: "draft"}} // no YarcSHA256
	srv := setServer(t, &fakeSetSvc{}, rd, blob.New(t.TempDir()))

	resp, err := http.Get(srv.URL + "/api/rulesets/3/yarc")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status %d, want 404", resp.StatusCode)
	}
}

func TestSelectionCanBeSetAndRead(t *testing.T) {
	rd := &fakeSetReader{}
	srv := setServer(t, &fakeSetSvc{}, rd, blob.New(t.TempDir()))

	req, _ := http.NewRequest(http.MethodPut, srv.URL+"/api/rulesets/3/selection",
		strings.NewReader(`{"layers":["own"],"rules":[1,2]}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d, want 200", resp.StatusCode)
	}
	if len(rd.sel.Layers) != 1 || len(rd.sel.Rules) != 2 {
		t.Fatalf("selection not stored: %+v", rd.sel)
	}
}

func TestAnExclusionThatWouldOrphanADependentIs409(t *testing.T) {
	svc := &fakeSetSvc{excludeErr: errCompile(
		"excluding IsPhp would break 2 rule(s) that reference it: DodgyPhp, ObfuscatedPhp")}
	srv := setServer(t, svc, &fakeSetReader{}, blob.New(t.TempDir()))

	resp, err := http.Post(srv.URL+"/api/rulesets/3/exclusions", "application/json",
		strings.NewReader(`{"rule_id":1,"identifier":"IsPhp","reason":"noisy"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("status %d, want 409", resp.StatusCode)
	}
	var got map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&got)
	if !strings.Contains(got["error"], "DodgyPhp") {
		t.Fatalf("error must name what would break, got %q", got["error"])
	}
}

func TestListRuleSetsEndpointReturnsAnArray(t *testing.T) {
	rd := &fakeSetReader{sets: []store.RuleSet{{ID: 2, Name: "sweep-feb"}, {ID: 1, Name: "sweep-jan"}}}
	srv := setServer(t, &fakeSetSvc{}, rd, blob.New(t.TempDir()))

	resp, err := http.Get(srv.URL + "/api/rulesets")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var got []store.RuleSet
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got) != 2 || got[0].Name != "sweep-feb" {
		t.Fatalf("got %+v, want the two sets newest-first", got)
	}
}

func TestMembersEndpointNamesWhatAFrozenSetPins(t *testing.T) {
	// The single most useful fact about a frozen set is what is in it. Without this the screen can
	// show a set that compiled a 5,872-rule blob and say nothing about its contents.
	rd := &fakeSetReader{members: []store.FrozenMember{
		{RuleID: 7, Identifier: "DodgyPhp", Layer: "foundation", Revision: 3},
		{RuleID: 9, Identifier: "AcmeShell", Layer: "own", Revision: 1},
	}}
	srv := setServer(t, &fakeSetSvc{}, rd, blob.New(t.TempDir()))

	resp, err := http.Get(srv.URL + "/api/rulesets/1/members")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var got []store.FrozenMember
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got) != 2 || got[0].Identifier != "DodgyPhp" || got[0].Revision != 3 {
		t.Fatalf("got %+v, want the two pinned members with their revisions", got)
	}
	if got[1].Layer != "own" {
		t.Errorf("layer = %q, want own", got[1].Layer)
	}
}

func TestMembersEndpointRejectsANonNumericID(t *testing.T) {
	srv := setServer(t, &fakeSetSvc{}, &fakeSetReader{}, blob.New(t.TempDir()))
	resp, err := http.Get(srv.URL + "/api/rulesets/notanumber/members")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestResolvedCountReportsWhatTheSetWouldApply(t *testing.T) {
	// The count comes from ResolveSelection rather than from arithmetic, because layers and named
	// rules are a UNION: naming a rule a selected layer already covers adds nothing, and
	// exclusions subtract.
	rd := &fakeSetReader{resolved: []store.RuleRevision{{ID: 1}, {ID: 2}, {ID: 3}}}
	srv := setServer(t, &fakeSetSvc{}, rd, blob.New(t.TempDir()))

	resp, err := http.Get(srv.URL + "/api/rulesets/1/resolved-count")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var got struct{ Count int }
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.Count != 3 {
		t.Errorf("count = %d, want 3", got.Count)
	}
}

func TestResolvedCountIsZeroForAnEmptySelection(t *testing.T) {
	// Zero is the state that makes generation refuse, so it must be reachable and reported plainly
	// rather than as an error.
	srv := setServer(t, &fakeSetSvc{}, &fakeSetReader{}, blob.New(t.TempDir()))
	resp, err := http.Get(srv.URL + "/api/rulesets/1/resolved-count")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var got struct{ Count int }
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.Count != 0 {
		t.Errorf("count = %d, want 0", got.Count)
	}
}

func TestResolvedCountRejectsANonNumericID(t *testing.T) {
	srv := setServer(t, &fakeSetSvc{}, &fakeSetReader{}, blob.New(t.TempDir()))
	resp, err := http.Get(srv.URL + "/api/rulesets/nope/resolved-count")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}
