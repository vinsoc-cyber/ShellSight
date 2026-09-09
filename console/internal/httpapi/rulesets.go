package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"

	"shellsightconsole/internal/blob"
	"shellsightconsole/internal/ruleset"
	"shellsightconsole/internal/store"
)

type RuleSetService interface {
	Freeze(ctx context.Context, ruleSetID int64, version int, actor string) (string, error)
	CheckExclusion(identifier string) error
}

type RuleSetReader interface {
	CreateRuleSet(ctx context.Context, name, createdBy string) (int64, error)
	GetRuleSet(ctx context.Context, id int64) (store.RuleSet, error)
	ListRuleSets(ctx context.Context) ([]store.RuleSet, error)
	FrozenMemberList(ctx context.Context, ruleSetID int64) ([]store.FrozenMember, error)
	GetSelection(ctx context.Context, id int64) (store.Selection, error)
	SetSelection(ctx context.Context, id int64, sel store.Selection) error
	AddExclusion(ctx context.Context, ruleSetID, ruleID int64, reason, author string) error
	ListExclusions(ctx context.Context, ruleSetID int64) ([]store.Exclusion, error)
	ResolveSelection(ctx context.Context, id int64) ([]store.RuleRevision, error)
	ListRules(ctx context.Context, layer string) ([]store.Rule, error)
}

type RuleSetAPI struct {
	svc    RuleSetService
	reader RuleSetReader
	blobs  *blob.Store
}

func NewRuleSetAPI(svc RuleSetService, reader RuleSetReader, blobs *blob.Store) *RuleSetAPI {
	return &RuleSetAPI{svc: svc, reader: reader, blobs: blobs}
}

func (a *RuleSetAPI) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/rulesets", a.list)
	mux.HandleFunc("POST /api/rulesets", a.create)
	mux.HandleFunc("GET /api/rulesets/{id}", a.get)
	mux.HandleFunc("GET /api/rulesets/{id}/selection", a.getSelection)
	mux.HandleFunc("PUT /api/rulesets/{id}/selection", a.putSelection)
	mux.HandleFunc("POST /api/rulesets/{id}/exclusions", a.addExclusion)
	mux.HandleFunc("GET /api/rulesets/{id}/exclusions", a.listExclusions)
	mux.HandleFunc("GET /api/rulesets/{id}/members", a.members)
	mux.HandleFunc("GET /api/rulesets/{id}/resolved-count", a.resolvedCount)
	mux.HandleFunc("POST /api/rulesets/{id}/freeze", a.freeze)
	mux.HandleFunc("GET /api/rulesets/{id}/yarc", a.downloadYarc)
	mux.HandleFunc("GET /api/rulesets/{id}/compare/{other}", a.compare)
	mux.HandleFunc("/", notFound)
	return mux
}

func pathID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "id must be a number")
		return 0, false
	}
	return id, true
}

func (a *RuleSetAPI) list(w http.ResponseWriter, r *http.Request) {
	got, err := a.reader.ListRuleSets(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, got)
}

func (a *RuleSetAPI) create(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil || b.Name == "" {
		writeError(w, http.StatusBadRequest, "a rule set needs a name")
		return
	}
	id, err := a.reader.CreateRuleSet(r.Context(), b.Name, actor(r))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]int64{"id": id})
}

func (a *RuleSetAPI) get(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	set, err := a.reader.GetRuleSet(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "no such rule set")
		return
	}
	writeJSON(w, http.StatusOK, set)
}

func (a *RuleSetAPI) getSelection(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	sel, err := a.reader.GetSelection(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "no such rule set")
		return
	}
	writeJSON(w, http.StatusOK, sel)
}

func (a *RuleSetAPI) putSelection(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var sel store.Selection
	if err := json.NewDecoder(r.Body).Decode(&sel); err != nil {
		writeError(w, http.StatusBadRequest, "request body is not valid JSON")
		return
	}
	if err := a.reader.SetSelection(r.Context(), id, sel); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, sel)
}

func (a *RuleSetAPI) addExclusion(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var b struct {
		RuleID     int64  `json:"rule_id"`
		Identifier string `json:"identifier"`
		Reason     string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		writeError(w, http.StatusBadRequest, "request body is not valid JSON")
		return
	}
	if err := a.svc.CheckExclusion(b.Identifier); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	if err := a.reader.AddExclusion(r.Context(), id, b.RuleID, b.Reason, actor(r)); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, nil)
}

// members names what a frozen set pins, without any rule text. A set that compiled a 5,872-rule
// blob and cannot say what is in it is not much use to the analyst who has to defend the scan.
func (a *RuleSetAPI) members(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	got, err := a.reader.FrozenMemberList(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, got)
}

// resolvedCount reports how many rules the set would actually apply. It exists so an analyst sees
// the number while editing rather than discovering at generation time that a set applies nothing.
//
// It counts ResolveSelection rather than doing arithmetic on the selection: layers and named rules
// are a union, so naming a rule a selected layer already covers adds nothing, and exclusions
// subtract.
func (a *RuleSetAPI) resolvedCount(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	revs, err := a.reader.ResolveSelection(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]int{"count": len(revs)})
}

func (a *RuleSetAPI) listExclusions(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	ex, err := a.reader.ListExclusions(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if ex == nil {
		ex = []store.Exclusion{}
	}
	writeJSON(w, http.StatusOK, ex)
}

func (a *RuleSetAPI) freeze(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var b struct {
		Version int `json:"version"`
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		writeError(w, http.StatusBadRequest, "request body is not valid JSON")
		return
	}
	hash, err := a.svc.Freeze(r.Context(), id, b.Version, actor(r))
	if err != nil {
		writeError(w, statusForRuleError(err), err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"yarc_sha256": hash})
}

// downloadYarc streams the frozen blob. This is what a future agent build embeds.
func (a *RuleSetAPI) downloadYarc(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	set, err := a.reader.GetRuleSet(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "no such rule set")
		return
	}
	if set.YarcSHA256 == "" {
		writeError(w, http.StatusNotFound, "this rule set is not frozen and has no compiled blob")
		return
	}
	body, err := a.blobs.Get(set.YarcSHA256)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "the compiled blob is missing from the store")
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-Yarc-SHA256", set.YarcSHA256)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// compare reports what differs between two rule sets' rules and exclusions.
//
// Rules are compared by RULE, not by revision id: the same rule at a different revision is a
// change an analyst needs to see, not a removal paired with an unrelated addition.
func (a *RuleSetAPI) compare(w http.ResponseWriter, r *http.Request) {
	from, ok := pathID(w, r)
	if !ok {
		return
	}
	to, err := strconv.ParseInt(r.PathValue("other"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "the other id must be a number")
		return
	}

	fromRevs, err := a.reader.ResolveSelection(r.Context(), from)
	if err != nil {
		writeError(w, http.StatusNotFound, "no such rule set")
		return
	}
	toRevs, err := a.reader.ResolveSelection(r.Context(), to)
	if err != nil {
		writeError(w, http.StatusNotFound, "no such rule set")
		return
	}
	all, err := a.reader.ListRules(r.Context(), "")
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	names := make(map[int64]string, len(all))
	for _, ru := range all {
		names[ru.ID] = ru.Identifier
	}

	fromEx, err := a.reader.ListExclusions(r.Context(), from)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	toEx, err := a.reader.ListExclusions(r.Context(), to)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"rules":      ruleset.DiffRules(fromRevs, toRevs, names),
		"exclusions": ruleset.DiffExclusions(fromEx, toEx),
	})
}
