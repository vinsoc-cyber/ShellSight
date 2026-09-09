package web

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

func get(t *testing.T, p string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, p, nil))
	return rec
}

func TestTheBuiltAppIsServedAtTheRoot(t *testing.T) {
	if !Built() {
		t.Skip("SPA not built; run npm ci && npm run build in console/web")
	}
	rec := get(t, "/")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET / = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}
	if !strings.Contains(rec.Body.String(), `id="root"`) {
		t.Error("served page is not the SPA shell")
	}
}

func TestAClientRouteFallsBackToTheAppShell(t *testing.T) {
	// A hard refresh on /cases/4/scans must load the app, not 404 -- routing happens client-side.
	if !Built() {
		t.Skip("SPA not built")
	}
	rec := get(t, "/cases/4/scans")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /cases/4/scans = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `id="root"`) {
		t.Error("client route did not get the app shell")
	}
}

func TestAMissingAssetIs404NotTheAppShell(t *testing.T) {
	// Answering a missing .js with HTML turns a build mistake into a baffling parse error in the
	// browser console instead of an honest 404.
	if !Built() {
		t.Skip("SPA not built")
	}
	rec := get(t, "/assets/does-not-exist.js")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("missing asset = %d, want 404", rec.Code)
	}
}

func TestTheAppShellIsNotCached(t *testing.T) {
	if !Built() {
		t.Skip("SPA not built")
	}
	if cc := get(t, "/").Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store -- a cached shell outlives its API", cc)
	}
}

func TestEveryClientRouteServesTheAppShell(t *testing.T) {
	// Each of these is a URL an analyst can paste to a colleague, or land on after a hard refresh.
	// If any of them 404s, the link is broken for everyone but the person who clicked through to
	// it -- and that failure is invisible to anyone testing only the root.
	if !Built() {
		t.Skip("SPA not built; run npm ci && npm run build in console/web")
	}
	routes := []string{
		"/",
		"/cases/4",
		"/scans/1",
		"/rules",
		"/rules/new",
		"/rules/12",
		"/rulesets",
		"/generate",
	}
	for _, r := range routes {
		rec := get(t, r)
		if rec.Code != http.StatusOK {
			t.Errorf("GET %s = %d, want 200", r, rec.Code)
			continue
		}
		if !strings.Contains(rec.Body.String(), `id="root"`) {
			t.Errorf("GET %s did not return the app shell", r)
		}
	}
}

func TestTheBuiltShellReferencesItsOwnAssets(t *testing.T) {
	// A shell whose script tag points at a file the embedded FS does not hold renders a blank
	// page with a console error, which is the hardest kind of deployment failure to diagnose.
	if !Built() {
		t.Skip("SPA not built")
	}
	body := get(t, "/").Body.String()
	refs := regexp.MustCompile(`(?:src|href)="(/assets/[^"]+)"`).FindAllStringSubmatch(body, -1)
	if len(refs) == 0 {
		t.Fatal("the shell references no /assets/ files; the build output looks wrong")
	}
	for _, m := range refs {
		if rec := get(t, m[1]); rec.Code != http.StatusOK {
			t.Errorf("the shell references %s but serving it gives %d", m[1], rec.Code)
		}
	}
}
