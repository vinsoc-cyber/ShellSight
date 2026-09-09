package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/jackc/pgx/v5/pgxpool"

	"shellsightconsole/internal/blob"
	"shellsightconsole/internal/release"
	"shellsightconsole/internal/store"
)

// validTargets mirrors the CHECK constraint in migration 0001. Rejecting here as well means the
// operator gets a clear message instead of a constraint violation from the database.
var validTargets = map[string]bool{
	"windows-amd64": true, "linux-amd64": true, "linux-arm64": true,
}

type publishConfig struct {
	DSN     string
	BlobDir string
	Dir     string
	Version string
	Target  string
	By      string
}

func parsePublishConfig(args []string) (publishConfig, error) {
	var cfg publishConfig
	fs := flag.NewFlagSet("publish", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&cfg.DSN, "dsn", "", "PostgreSQL connection string (required)")
	fs.StringVar(&cfg.BlobDir, "blobs", "", "blob store directory (required)")
	fs.StringVar(&cfg.Dir, "dir", "", "unpacked release directory (required)")
	fs.StringVar(&cfg.Version, "version", "", "release version, e.g. v1.0.0-231-g098d8f9 (required)")
	fs.StringVar(&cfg.Target, "target", "", "windows-amd64 | linux-amd64 | linux-arm64 (required)")
	fs.StringVar(&cfg.By, "by", "", "who is publishing")
	if err := fs.Parse(args); err != nil {
		return cfg, err
	}
	switch {
	case cfg.DSN == "":
		return cfg, errors.New("-dsn is required")
	case cfg.BlobDir == "":
		return cfg, errors.New("-blobs is required")
	case cfg.Dir == "":
		return cfg, errors.New("-dir is required")
	case cfg.Version == "":
		return cfg, errors.New("-version is required")
	case cfg.Target == "":
		return cfg, errors.New("-target is required")
	}
	if !validTargets[cfg.Target] {
		return cfg, fmt.Errorf("target %q is not one of windows-amd64, linux-amd64, linux-arm64", cfg.Target)
	}
	if cfg.By == "" {
		cfg.By = "unknown"
	}
	return cfg, nil
}

// runPublish verifies the release, stores every file in the blob store, then records it.
//
// Order matters: verification first, and a single mismatch aborts before anything is written.
// A half-published release would be a release whose manifest does not describe it, which is the
// state verification exists to prevent.
func runPublish(cfg publishConfig) error {
	files, err := release.Verify(cfg.Dir)
	if err != nil {
		return fmt.Errorf("release verification failed: %w", err)
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

	blobs := blob.New(cfg.BlobDir)
	records := make([]store.ReleaseFile, 0, len(files))
	for _, f := range files {
		key, err := blobs.Put(f.Body)
		if err != nil {
			return fmt.Errorf("storing %s: %w", f.Path, err)
		}
		if key != f.SHA256 {
			// The blob store hashes independently of the manifest. Disagreement means one of the
			// two is wrong, and shipping either would be worse than refusing.
			return fmt.Errorf("%s: manifest hash %s but stored content hashes to %s", f.Path, f.SHA256, key)
		}
		records = append(records, store.ReleaseFile{Path: f.Path, SHA256: key})
	}

	st := store.NewPG(pool)
	id, err := st.PublishRelease(ctx,
		store.Release{Version: cfg.Version, Target: cfg.Target, PublishedBy: cfg.By}, records)
	if err != nil {
		return err
	}
	_ = st.Audit(ctx, cfg.By, "release.publish", cfg.Version,
		map[string]any{"target": cfg.Target, "files": len(records)})
	fmt.Printf("published release %d: %s %s, %d files verified\n", id, cfg.Version, cfg.Target, len(records))
	return nil
}
