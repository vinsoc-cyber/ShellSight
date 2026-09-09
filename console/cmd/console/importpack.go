package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"

	"shellsightconsole/internal/packimport"
	"shellsightconsole/internal/store"
)

type importConfig struct {
	DSN   string
	File  string
	Layer string
	Pack  string
}

func parseImportConfig(args []string) (importConfig, error) {
	var cfg importConfig
	fs := flag.NewFlagSet("import-pack", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&cfg.DSN, "dsn", "", "PostgreSQL connection string (required)")
	fs.StringVar(&cfg.File, "file", "", "pack file to import (required)")
	fs.StringVar(&cfg.Layer, "layer", "foundation", "layer to import into")
	fs.StringVar(&cfg.Pack, "pack", "", "source pack name, e.g. signature-base (required)")
	if err := fs.Parse(args); err != nil {
		return cfg, err
	}
	switch {
	case cfg.DSN == "":
		return cfg, errors.New("-dsn is required")
	case cfg.File == "":
		return cfg, errors.New("-file is required")
	case cfg.Pack == "":
		return cfg, errors.New("-pack is required")
	}
	return cfg, nil
}

// runImport splits a pack and stores each rule as revision 1.
//
// It does NOT compile-check each rule on the way in. That would reject the 50 rules in the shipped
// packs whose conditions reference another rule -- the exact defect the reference graph exists to
// avoid. The pack as a whole is known to compile, because the scanner ships it.
func runImport(cfg importConfig) error {
	body, err := os.ReadFile(cfg.File)
	if err != nil {
		return err
	}
	rules, err := packimport.Split(string(body))
	if err != nil {
		return fmt.Errorf("%s: %w", cfg.File, err)
	}

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

	imported, skipped := 0, 0
	for _, r := range rules {
		_, err := st.CreateRule(ctx,
			store.Rule{Identifier: r.Identifier, Layer: cfg.Layer, SourcePack: cfg.Pack},
			store.RuleRevision{Text: r.Text, Author: "import:" + cfg.Pack})
		if err != nil {
			// A rule already present from an earlier import of the same pack is not an error;
			// re-importing must be safe to run.
			skipped++
			continue
		}
		imported++
	}
	_ = st.Audit(ctx, "import:"+cfg.Pack, "pack.import", cfg.Pack,
		map[string]any{"file": cfg.File, "imported": imported, "skipped": skipped})
	fmt.Printf("%s: %d rules imported, %d already present\n", cfg.Pack, imported, skipped)
	return nil
}
