package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/jackc/pgx/v5/pgxpool"

	"shellsightconsole/internal/store"
)

type backfillMetaConfig struct {
	DSN string
}

func parseBackfillMetaConfig(args []string) (backfillMetaConfig, error) {
	var cfg backfillMetaConfig
	fs := flag.NewFlagSet("backfill-meta", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&cfg.DSN, "dsn", "", "PostgreSQL connection string (required)")
	if err := fs.Parse(args); err != nil {
		return cfg, err
	}
	if cfg.DSN == "" {
		return cfg, errors.New("-dsn is required")
	}
	return cfg, nil
}

// runBackfillMeta re-parses every revision's meta: block into queryable columns.
//
// It REPORTS coverage rather than requiring it. 5,450 of 5,872 rules declare a score
// and 17 have no meta block at all; a command that failed on less than full coverage would
// be failing on a property of the packs.
func runBackfillMeta(cfg backfillMetaConfig) error {
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, cfg.DSN)
	if err != nil {
		return fmt.Errorf("connecting to the database: %w", err)
	}
	defer pool.Close()
	if err := store.Migrate(ctx, pool); err != nil {
		return fmt.Errorf("migrating: %w", err)
	}

	cov, err := store.NewPG(pool).BackfillMeta(ctx)
	if err != nil {
		return err
	}

	pct := func(n int) string {
		if cov.Revisions == 0 {
			return "0.0%"
		}
		return fmt.Sprintf("%.1f%%", 100*float64(n)/float64(cov.Revisions))
	}
	fmt.Printf("backfill-meta: %d revisions\n", cov.Revisions)
	fmt.Printf("  description   %6d  (%s)\n", cov.Description, pct(cov.Description))
	fmt.Printf("  score         %6d  (%s)\n", cov.Score, pct(cov.Score))
	fmt.Printf("  no meta block %6d  (%s)\n", cov.NoMetaBlock, pct(cov.NoMetaBlock))

	type kv struct {
		k string
		n int
	}
	keys := make([]kv, 0, len(cov.Keys))
	for k, n := range cov.Keys {
		keys = append(keys, kv{k, n})
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].n != keys[j].n {
			return keys[i].n > keys[j].n
		}
		return keys[i].k < keys[j].k
	})
	fmt.Printf("  meta keys:\n")
	for _, e := range keys {
		fmt.Printf("    %-22s %6d  (%s)\n", e.k, e.n, pct(e.n))
	}
	if cov.Revisions == 0 {
		fmt.Fprintln(os.Stderr, "backfill-meta: the library is empty; nothing to parse")
	}
	return nil
}
