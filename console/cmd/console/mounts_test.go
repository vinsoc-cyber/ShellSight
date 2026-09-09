package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// named answers with its own name, so a routing test can say WHICH handler a path reached rather
// than only that something did.
func named(name string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(name))
	})
}

func testMux() *http.ServeMux {
	return apiMux(apis{
		releases: named("releases"),
		rules:    named("rules"),
		rulesets: named("rulesets"),
		reports:  named("reports"),
		builds:   named("builds"),
		spa:      named("spa"),
	})
}

// Every API path must reach its own API and not the SPA.
//
// This is the test the missing /api/releases/ subtree needed. A path that falls through to the SPA
// answers 200 with the app shell, so a caller sees a working endpoint returning HTML -- which is
// why the gap survived: nothing was a 404 and nothing errored.
func TestEveryAPIPathReachesItsOwnAPIAndNotTheSPA(t *testing.T) {
	mux := testMux()
	for path, want := range map[string]string{
		"/api/releases":          "releases",
		"/api/releases/7/files":  "releases",
		"/api/rules":             "rules",
		"/api/rules/7":           "rules",
		"/api/rulesets":          "rulesets",
		"/api/rulesets/7/yarc":   "rulesets",
		"/api/builds":            "builds",
		"/api/builds/7/download": "builds",
		"/api/cases":             "reports",
		"/api/cases/7/scans":     "reports",
		"/api/scans/7":           "reports",
		"/api/decisions":         "reports",
		"/":                      "spa",
		"/generate":              "spa",
	} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		if got := rec.Body.String(); got != want {
			t.Errorf("%s reached %q, want %q", path, got, want)
		}
	}
}

// The subtree mount is what makes a nested route reachable at all, and it is the half that was
// missing. Asserted per prefix so a future API added with only the exact path fails here.
func TestEveryAPIPrefixIsMountedAsASubtreeToo(t *testing.T) {
	mux := testMux()
	for prefix, want := range map[string]string{
		"/api/releases": "releases",
		"/api/rules":    "rules",
		"/api/rulesets": "rulesets",
		"/api/builds":   "builds",
		"/api/cases":    "reports",
	} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest("GET", prefix+"/1/anything", nil))
		if got := rec.Body.String(); got != want {
			t.Errorf("%s/1/anything reached %q, want %q -- the subtree mount is missing",
				prefix, got, want)
		}
	}
}
