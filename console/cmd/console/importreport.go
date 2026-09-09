package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/jackc/pgx/v5/pgxpool"

	"shellsightconsole/internal/reports"
	"shellsightconsole/internal/store"
)

type importReportConfig struct {
	DSN  string
	Dir  string
	Case string
}

func parseImportReportConfig(args []string) (importReportConfig, error) {
	var cfg importReportConfig
	fs := flag.NewFlagSet("import-report", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&cfg.DSN, "dsn", "", "PostgreSQL connection string (required)")
	fs.StringVar(&cfg.Dir, "dir", "", "a run folder, or a directory of them (required)")
	fs.StringVar(&cfg.Case, "case", "", "case name to file the scans under (required)")
	if err := fs.Parse(args); err != nil {
		return cfg, err
	}
	switch {
	case cfg.DSN == "":
		return cfg, errors.New("-dsn is required")
	case cfg.Dir == "":
		return cfg, errors.New("-dir is required")
	case cfg.Case == "":
		return cfg, errors.New("-case is required")
	}
	return cfg, nil
}

// runImportReport ingests one run folder, or every run folder directly inside -dir.
//
// BULK IS THE PRIMARY MODE. A sweep of forty hosts produces forty run folders, and an analyst
// should hand the console the directory holding them, not run this forty times.
func runImportReport(cfg importReportConfig) error {
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, cfg.DSN)
	if err != nil {
		return err
	}
	defer pool.Close()
	if err := store.Migrate(ctx, pool); err != nil {
		return err
	}
	st := store.NewPG(pool)

	caseID, err := findOrCreateCase(ctx, st, cfg.Case)
	if err != nil {
		return err
	}

	folders, err := runFolders(cfg.Dir)
	if err != nil {
		return err
	}
	if len(folders) == 0 {
		return fmt.Errorf("no run folder found in %s (looked for report.json)", cfg.Dir)
	}

	svc := reports.NewService(st)
	var imported, already, failed int
	for _, dir := range folders {
		res, err := svc.IngestFolder(ctx, caseID, dir)
		if err != nil {
			// One bad folder must not abandon the other thirty-nine.
			fmt.Fprintf(os.Stderr, "  %s: %v\n", filepath.Base(dir), err)
			failed++
			continue
		}
		state := "imported"
		if !res.Created {
			state = "already present"
			already++
		} else {
			imported++
		}
		fmt.Printf("  %-40s %-15s %s  %d findings  integrity=%s\n",
			filepath.Base(dir), state, res.Host, res.Findings, res.Integrity)
	}
	fmt.Printf("%s: %d imported, %d already present, %d failed\n",
		cfg.Case, imported, already, failed)
	if failed > 0 {
		return fmt.Errorf("%d run folder(s) could not be imported", failed)
	}
	return nil
}

func findOrCreateCase(ctx context.Context, st *store.PG, name string) (int64, error) {
	cases, err := st.ListCases(ctx)
	if err != nil {
		return 0, err
	}
	for _, c := range cases {
		if c.Name == name {
			return c.ID, nil
		}
	}
	return st.CreateCase(ctx, name, "import")
}

// runFolders returns dir itself when it holds a report.json, otherwise every immediate
// subdirectory that does.
func runFolders(dir string) ([]string, error) {
	if _, err := os.Stat(filepath.Join(dir, "report.json")); err == nil {
		return []string{dir}, nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		sub := filepath.Join(dir, e.Name())
		if _, err := os.Stat(filepath.Join(sub, "report.json")); err == nil {
			out = append(out, sub)
		}
	}
	return out, nil
}
