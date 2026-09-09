// Package httpapi is the console's JSON surface.
//
// Two rules hold everywhere in this package. Errors are JSON, never HTML: the client is a
// single-page app and an HTML error page would surface as an unparseable response rather than a
// message. And the API never echoes a client-supplied path into a filesystem operation -- release
// paths and rule text originate outside the console and are data, never instructions.
package httpapi

import (
	"encoding/json"
	"net/http"
)

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if v != nil {
		_ = json.NewEncoder(w).Encode(v)
	}
}

func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

// notFound replaces http.NotFound so an unmatched route answers in JSON like everything else.
func notFound(w http.ResponseWriter, _ *http.Request) {
	writeError(w, http.StatusNotFound, "no such endpoint")
}

// actor identifies the caller. Stage 1a has no authentication; the header is a placeholder that
// the auth middleware added in a later stage will replace. It is recorded in the audit log so the
// substitution does not change any downstream code.
func actor(r *http.Request) string {
	if a := r.Header.Get("X-Console-Actor"); a != "" {
		return a
	}
	return "unknown"
}
