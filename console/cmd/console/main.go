// Command console is the ShellSight analyst console.
//
// It never compiles scanner code. The only thing it compiles is rule text, using the `yr` given
// by -yr, which must be the engine from the release whose agents will scan with the resulting
// blob: a .yarc is bound to its yara-x version.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"shellsightconsole/internal/blob"
	"shellsightconsole/internal/httpapi"
	"shellsightconsole/internal/reports"
	"shellsightconsole/internal/rules"
	"shellsightconsole/internal/ruleset"
	"shellsightconsole/internal/store"
	"shellsightconsole/internal/web"
)

type config struct {
	DSN     string
	BlobDir string
	YrPath  string
	Addr    string
}

func parseConfig(args []string) (config, error) {
	var cfg config
	fs := flag.NewFlagSet("console", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&cfg.DSN, "dsn", "", "PostgreSQL connection string (required)")
	fs.StringVar(&cfg.BlobDir, "blobs", "", "directory for the content-addressed blob store (required)")
	fs.StringVar(&cfg.YrPath, "yr", "", "path to the yara-x `yr` binary (required)")
	// Loopback by default: the console holds engagement evidence for every customer, so binding a
	// public interface must be something an operator types, never something they inherit.
	fs.StringVar(&cfg.Addr, "addr", "127.0.0.1:8080", "listen address")
	if err := fs.Parse(args); err != nil {
		return cfg, err
	}
	if cfg.DSN == "" {
		return cfg, errors.New("-dsn is required")
	}
	if cfg.BlobDir == "" {
		return cfg, errors.New("-blobs is required")
	}
	if cfg.YrPath == "" {
		return cfg, errors.New("-yr is required: the console cannot validate a rule without it")
	}
	return cfg, nil
}

func main() {
	args := os.Args[1:]
	if len(args) > 0 && args[0] == "publish" {
		cfg, err := parsePublishConfig(args[1:])
		if err != nil {
			fmt.Fprintf(os.Stderr, "console publish: %v\n", err)
			os.Exit(2)
		}
		if err := runPublish(cfg); err != nil {
			fmt.Fprintf(os.Stderr, "console publish: %v\n", err)
			os.Exit(1)
		}
		return
	}
	if len(args) > 0 && args[0] == "import-pack" {
		cfg, err := parseImportConfig(args[1:])
		if err != nil {
			fmt.Fprintf(os.Stderr, "console import-pack: %v\n", err)
			os.Exit(2)
		}
		if err := runImport(cfg); err != nil {
			fmt.Fprintf(os.Stderr, "console import-pack: %v\n", err)
			os.Exit(1)
		}
		return
	}
	if len(args) > 0 && args[0] == "backfill-meta" {
		cfg, err := parseBackfillMetaConfig(args[1:])
		if err != nil {
			fmt.Fprintf(os.Stderr, "console backfill-meta: %v\n", err)
			os.Exit(2)
		}
		if err := runBackfillMeta(cfg); err != nil {
			fmt.Fprintf(os.Stderr, "console backfill-meta: %v\n", err)
			os.Exit(1)
		}
		return
	}
	if len(args) > 0 && args[0] == "import-report" {
		cfg, err := parseImportReportConfig(args[1:])
		if err != nil {
			fmt.Fprintf(os.Stderr, "console import-report: %v\n", err)
			os.Exit(2)
		}
		if err := runImportReport(cfg); err != nil {
			fmt.Fprintf(os.Stderr, "console import-report: %v\n", err)
			os.Exit(1)
		}
		return
	}
	cfg, err := parseConfig(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "console: %v\n", err)
		os.Exit(2)
	}
	if err := run(cfg); err != nil {
		log.Fatalf("console: %v", err)
	}
}

// apis are the handlers apiMux mounts. A struct rather than five parameters so a caller cannot
// transpose two of them and mount the report API at /api/rules.
type apis struct {
	releases, rules, rulesets, reports, builds, spa http.Handler
}

// apiMux is the mount table.
//
// It is a function taking handlers, rather than inline in run(), because the mount table is a
// thing that can be WRONG on its own: /api/releases was mounted at the exact path only, so
// GET /api/releases/{id}/files was declared in the API, reachable in the store, and answered by
// the SPA -- a 200 carrying the app shell, which is worse than a 404 because it looks like a
// working endpoint. No test could see that while this lived inside run(), which needs a database
// and a listener. Now one can.
//
// Each API is mounted ONCE and at both its exact path and its subtree. Building two of the same
// handler would give the two mounts separate state the moment either grows any.
func apiMux(a apis) *http.ServeMux {
	mux := http.NewServeMux()
	for _, m := range []struct {
		prefix  string
		handler http.Handler
	}{
		{"/api/releases", a.releases},
		{"/api/rules", a.rules},
		{"/api/rulesets", a.rulesets},
		{"/api/builds", a.builds},
	} {
		mux.Handle(m.prefix, m.handler)
		mux.Handle(m.prefix+"/", m.handler)
	}
	// The report API is not one resource, so it does not follow the pair-per-prefix shape: /api/scans
	// is a subtree only, and /api/decisions is an exact path only.
	mux.Handle("/api/cases", a.reports)
	mux.Handle("/api/cases/", a.reports)
	mux.Handle("/api/scans/", a.reports)
	mux.Handle("/api/decisions", a.reports)

	// The SPA is mounted last and at the root, so it is the fallback for everything that is not an
	// API path. It answers client-side routes with the app shell; see internal/web.
	mux.Handle("/", a.spa)
	return mux
}

func run(cfg config) error {
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, cfg.DSN)
	if err != nil {
		return fmt.Errorf("connecting to the database: %w", err)
	}
	defer pool.Close()
	if err := store.Migrate(ctx, pool); err != nil {
		return fmt.Errorf("migrating: %w", err)
	}

	st := store.NewPG(pool)
	blobs := blob.New(cfg.BlobDir)
	compiler := rules.NewCompiler(cfg.YrPath)
	// The resolver is what lets the compile check see a rule's dependencies. Without it,
	// every rule whose condition names another rule would be rejected on save.
	ruleSvc := rules.NewService(st, compiler, rules.NewLibraryResolver(st))
	setSvc := ruleset.NewService(st, blobs, compiler)

	// Each API is constructed ONCE, here, and handed to the mount table. Building a second copy per
	// mount would give the two mounts separate state the moment either grows any.
	mux := apiMux(apis{
		releases: httpapi.NewReleaseAPI(st, blobs).Routes(),
		rules:    httpapi.NewRuleAPI(ruleSvc, st).Routes(),
		rulesets: httpapi.NewRuleSetAPI(setSvc, st, blobs).Routes(),
		reports:  httpapi.NewReportAPI(st, reports.NewService(st)).Routes(),
		builds:   httpapi.NewBuildAPI(st, blobs).Routes(),
		spa:      web.Handler(),
	})

	srv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	// Bind BEFORE announcing. Logging "listening" and then failing to bind gives an operator two
	// contradictory lines and hides which one is true.
	ln, err := net.Listen("tcp", cfg.Addr)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", cfg.Addr, err)
	}
	if web.Built() {
		log.Printf("console listening on %s", ln.Addr())
	} else {
		// Say it here rather than let an operator discover it as a blank browser tab.
		log.Printf("console listening on %s -- API only, the SPA is not built into this binary",
			ln.Addr())
	}
	return srv.Serve(ln)
}
