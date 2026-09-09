package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"shellsightconsole/internal/rules"
	"shellsightconsole/internal/store"
)

type RuleService interface {
	Create(ctx context.Context, layer, text, lang, author string) (int64, error)
	Edit(ctx context.Context, id int64, text, lang, author string) (int, error)
	Delete(ctx context.Context, id int64, actor string) error
}

type RuleReader interface {
	ListRules(ctx context.Context, layer string) ([]store.Rule, error)
	RuleIndex(ctx context.Context) ([]store.RuleIndexRow, error)
	GetRule(ctx context.Context, id int64) (store.Rule, store.RuleRevision, error)
}

type RuleAPI struct {
	svc    RuleService
	reader RuleReader
}

func NewRuleAPI(svc RuleService, reader RuleReader) *RuleAPI {
	return &RuleAPI{svc: svc, reader: reader}
}

func (a *RuleAPI) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/rules", a.list)
	mux.HandleFunc("POST /api/rules", a.create)
	mux.HandleFunc("GET /api/rules/langs", a.langs)
	mux.HandleFunc("GET /api/rules/index", a.index)
	mux.HandleFunc("GET /api/rules/{id}", a.get)
	mux.HandleFunc("PUT /api/rules/{id}", a.edit)
	mux.HandleFunc("DELETE /api/rules/{id}", a.del)
	mux.HandleFunc("/", notFound)
	return mux
}

type ruleBody struct {
	Layer string `json:"layer"`
	Text  string `json:"text"`
	Lang  string `json:"lang"`
}

func (a *RuleAPI) create(w http.ResponseWriter, r *http.Request) {
	var b ruleBody
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		writeError(w, http.StatusBadRequest, "request body is not valid JSON")
		return
	}
	id, err := a.svc.Create(r.Context(), b.Layer, b.Text, b.Lang, actor(r))
	if err != nil {
		writeError(w, statusForRuleError(err), err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]int64{"id": id})
}

func (a *RuleAPI) edit(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "id must be a number")
		return
	}
	var b ruleBody
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		writeError(w, http.StatusBadRequest, "request body is not valid JSON")
		return
	}
	rev, err := a.svc.Edit(r.Context(), id, b.Text, b.Lang, actor(r))
	if err != nil {
		writeError(w, statusForRuleError(err), err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]int{"revision": rev})
}

func (a *RuleAPI) del(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "id must be a number")
		return
	}
	if err := a.svc.Delete(r.Context(), id, actor(r)); err != nil {
		writeError(w, statusForRuleError(err), err.Error())
		return
	}
	writeJSON(w, http.StatusNoContent, nil)
}

func (a *RuleAPI) list(w http.ResponseWriter, r *http.Request) {
	got, err := a.reader.ListRules(r.Context(), r.URL.Query().Get("layer"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if got == nil {
		got = []store.Rule{}
	}
	writeJSON(w, http.StatusOK, got)
}

// index serves the whole library in the shape the rule browser filters client-side: no rule text,
// one row per non-deleted rule. Roughly 1.2 MB uncompressed at 5,872 rules, fetched once per visit.
func (a *RuleAPI) index(w http.ResponseWriter, r *http.Request) {
	got, err := a.reader.RuleIndex(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, got)
}

func (a *RuleAPI) get(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "id must be a number")
		return
	}
	rule, rev, err := a.reader.GetRule(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "no such rule")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"rule": rule, "revision": rev})
}

func (a *RuleAPI) langs(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, rules.Langs())
}

// statusForRuleError separates "your request was malformed" from "your rule was rejected".
// A compile failure is 422: the request was fine, the content was not, and the client should
// render the compiler's message rather than treat it as a protocol error.
func statusForRuleError(err error) int {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "rule compilation failed"),
		strings.Contains(msg, "no rule declaration"),
		strings.Contains(msg, "declares"):
		return http.StatusUnprocessableEntity
	case strings.Contains(msg, "cannot be edited"),
		strings.Contains(msg, "cannot be deleted"),
		strings.Contains(msg, "not writable"):
		return http.StatusForbidden
	default:
		return http.StatusBadRequest
	}
}
