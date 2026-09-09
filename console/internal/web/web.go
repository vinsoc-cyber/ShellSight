// Package web serves the analyst console's single-page app from an embedded filesystem.
//
// The build output is embedded at compile time, so the console ships as one binary with no assets
// to copy. The package deliberately compiles whether or not the SPA has been built: a dist that
// holds no index.html serves a page SAYING the UI was not built, rather than 404ing and leaving
// someone to guess. Absence is declared, not inferred.
package web

import (
	"embed"
	"errors"
	"io/fs"
	"net/http"
	"path"
	"strings"
)

// all: is required because the committed placeholder in dist is .gitkeep, and go:embed skips
// dot-prefixed names without it -- without all:, a fresh clone would not compile.
//
//go:embed all:dist
var dist embed.FS

//go:embed placeholder.html
var placeholder []byte

// Handler serves the SPA. Unknown paths fall back to index.html so client-side routing works on a
// hard refresh; a request for a missing ASSET still 404s, because silently answering a missing
// .js with HTML turns a build mistake into a confusing runtime parse error.
func Handler() http.Handler {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		return notBuilt()
	}
	index, err := fs.ReadFile(sub, "index.html")
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return notBuilt()
		}
		return notBuilt()
	}
	files := http.FileServer(http.FS(sub))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
		if name == "" {
			serveIndex(w, index)
			return
		}
		if _, err := fs.Stat(sub, name); err == nil {
			files.ServeHTTP(w, r)
			return
		}
		// A path that looks like an asset is a build error, not a route.
		if ext := path.Ext(name); ext != "" && ext != ".html" {
			http.NotFound(w, r)
			return
		}
		serveIndex(w, index)
	})
}

func serveIndex(w http.ResponseWriter, index []byte) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// The SPA is the app shell, not data. Letting it be cached across deploys is how a stale
	// bundle outlives the API it was built against.
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(index)
}

// notBuilt reports, in the page itself, that the binary carries no SPA.
func notBuilt() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write(placeholder)
	})
}

// Built reports whether this binary carries a built SPA. main uses it to say so at startup, so an
// operator learns it from the log rather than from a blank browser tab.
func Built() bool {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		return false
	}
	_, err = fs.Stat(sub, "index.html")
	return err == nil
}
