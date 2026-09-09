package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"shellsightconsole/internal/store"
)

type fakeRuleSvc struct {
	created  int
	lastText string
	failWith error
}

func (f *fakeRuleSvc) Create(_ context.Context, layer, text, lang, author string) (int64, error) {
	if f.failWith != nil {
		return 0, f.failWith
	}
	f.created++
	f.lastText = text
	return 7, nil
}
func (f *fakeRuleSvc) Edit(context.Context, int64, string, string, string) (int, error) {
	return 2, nil
}
func (f *fakeRuleSvc) Delete(context.Context, int64, string) error { return nil }

type fakeRuleReader struct {
	rules []store.Rule
	index []store.RuleIndexRow
}

func (f *fakeRuleReader) RuleIndex(context.Context) ([]store.RuleIndexRow, error) {
	return f.index, nil
}

func (f *fakeRuleReader) ListRules(context.Context, string) ([]store.Rule, error) {
	return f.rules, nil
}
func (f *fakeRuleReader) GetRule(context.Context, int64) (store.Rule, store.RuleRevision, error) {
	return store.Rule{ID: 7, Identifier: "r", Layer: "custom"},
		store.RuleRevision{Revision: 1, Text: "rule r { condition: true }"}, nil
}

func ruleServer(t *testing.T, svc *fakeRuleSvc, rd *fakeRuleReader) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(NewRuleAPI(svc, rd).Routes())
	t.Cleanup(s.Close)
	return s
}

func TestCreateRuleReturnsTheNewID(t *testing.T) {
	svc := &fakeRuleSvc{}
	srv := ruleServer(t, svc, &fakeRuleReader{})

	body := `{"layer":"custom","text":"rule r { condition: true }","lang":"php"}`
	resp, err := http.Post(srv.URL+"/api/rules", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status %d, want 201", resp.StatusCode)
	}
	var got map[string]int64
	_ = json.NewDecoder(resp.Body).Decode(&got)
	if got["id"] != 7 || svc.created != 1 {
		t.Fatalf("got %+v, created=%d", got, svc.created)
	}
}

func TestACompileFailureIs422AndCarriesTheCompilerMessage(t *testing.T) {
	// The analyst must see yr's own words. 422 rather than 400: the request was well-formed,
	// the rule was not.
	svc := &fakeRuleSvc{failWith: errCompile("rule compilation failed:\nerror[E001]: syntax error")}
	srv := ruleServer(t, svc, &fakeRuleReader{})

	resp, err := http.Post(srv.URL+"/api/rules", "application/json",
		strings.NewReader(`{"layer":"custom","text":"rule r { condition: }"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("status %d, want 422", resp.StatusCode)
	}
	var got map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&got)
	if !strings.Contains(got["error"], "syntax error") {
		t.Fatalf("error must carry the compiler's message, got %q", got["error"])
	}
}

func TestMalformedJSONIs400(t *testing.T) {
	srv := ruleServer(t, &fakeRuleSvc{}, &fakeRuleReader{})
	resp, err := http.Post(srv.URL+"/api/rules", "application/json", bytes.NewReader([]byte("{not json")))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status %d, want 400", resp.StatusCode)
	}
}

func TestListRulesFiltersByLayerQueryParameter(t *testing.T) {
	rd := &fakeRuleReader{rules: []store.Rule{{ID: 1, Identifier: "a", Layer: "own"}}}
	srv := ruleServer(t, &fakeRuleSvc{}, rd)

	resp, err := http.Get(srv.URL + "/api/rules?layer=own")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var got []store.Rule
	_ = json.NewDecoder(resp.Body).Decode(&got)
	if len(got) != 1 || got[0].Layer != "own" {
		t.Fatalf("got %+v", got)
	}
}

func TestLangsEndpointOffersTheValidValues(t *testing.T) {
	srv := ruleServer(t, &fakeRuleSvc{}, &fakeRuleReader{})
	resp, err := http.Get(srv.URL + "/api/rules/langs")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var got []string
	_ = json.NewDecoder(resp.Body).Decode(&got)
	if len(got) < 9 {
		t.Fatalf("got %d languages, want at least 9", len(got))
	}
}

type errCompile string

func (e errCompile) Error() string { return string(e) }

func TestRuleIndexEndpointServesTheBrowsableIndex(t *testing.T) {
	seventy := 70
	rd := &fakeRuleReader{index: []store.RuleIndexRow{
		{ID: 1, Identifier: "AcmeShell", Layer: "own", SourcePack: "shellsight",
			Score: &seventy, Description: "detects the Acme uploader"},
		{ID: 2, Identifier: "DodgyPhp", Layer: "foundation", SourcePack: "yara-forge-core"},
	}}
	srv := ruleServer(t, &fakeRuleSvc{}, rd)

	resp, err := http.Get(srv.URL + "/api/rules/index")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	// The index must not carry rule text: it is the bulk of the payload and the browser never
	// shows it.
	if strings.Contains(string(body), `"text"`) {
		t.Error("the index response contains a text field")
	}
	var got []store.RuleIndexRow
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got) != 2 || got[0].Identifier != "AcmeShell" {
		t.Fatalf("got %+v", got)
	}
	if got[0].Score == nil || *got[0].Score != 70 {
		t.Errorf("score = %v, want 70", got[0].Score)
	}
	if got[1].Score != nil {
		t.Errorf("DodgyPhp declared no score; got %v", got[1].Score)
	}
}
