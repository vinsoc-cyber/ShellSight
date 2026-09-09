// Package consoletest holds scaffolding shared by the console's database-backed test packages.
//
// It exists for one reason. Two test packages -- internal/console/store and internal/console --
// each begin by resetting the shared test schema with `DROP SCHEMA public CASCADE`, and
// `go test ./internal/console/...` runs different packages' test binaries CONCURRENTLY. Measured
// on this tree, that fails on every run and in BOTH directions: the end-to-end test loses its
// tables mid-run ("relation \"releases\" does not exist"), and the store's own tests lose theirs.
// Two concurrent migrations also collide outright on pg_type_typname_nsp_index.
//
// A lock taken only around setup would not be enough. One package's reset must not land while
// another package is midway through its tests, so the schema has to be held for the WHOLE of a
// package's run -- hence a SESSION-level advisory lock, acquired in TestMain and held across
// m.Run().
//
// The cost is that the two packages run one after the other rather than together. That is the
// point, and it is cheap: the store suite is a few seconds and the end-to-end test is a fraction
// of one.
package consoletest

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/jackc/pgx/v5"
)

// FindYr locates the bundled yara-x binary, or returns "" when it cannot be found.
//
// It WALKS UP looking for third_party/yara-x rather than counting `../` levels, because counting
// levels encodes the package's depth in the tree. When the console was extracted from the scanner's
// module every package moved up one directory, every hard-coded `../../../../` silently pointed at
// nothing, and the affected tests SKIPPED -- reporting `ok` in 0.014s while verifying nothing. A
// relative path that breaks by skipping is worse than one that breaks by failing.
//
// CONSOLE_TEST_YR overrides the search.
func FindYr() string {
	if p := os.Getenv("CONSOLE_TEST_YR"); p != "" {
		return p
	}
	dir, err := os.Getwd()
	if err != nil {
		return ""
	}
	for {
		for _, rel := range []string{
			filepath.Join("third_party", "yara-x", "yr.exe"),
			filepath.Join("third_party", "yara-x", "linux-amd64", "yr"),
			filepath.Join("third_party", "yara-x", "yr"),
		} {
			candidate := filepath.Join(dir, rel)
			if st, err := os.Stat(candidate); err == nil && !st.IsDir() {
				return candidate
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "" // reached the filesystem root
		}
		dir = parent
	}
}

// lockKey is arbitrary, but every package that resets the shared schema must use the same value or
// the lock protects nothing.
const lockKey int64 = 0x5348454C4C53 // "SHELLS"

// LockDatabase blocks until this process owns the shared test schema and returns the release
// function.
//
// With no DSN configured it is a no-op returning a no-op release: the tests themselves skip in that
// case, so there is nothing to protect and nothing to wait for. That keeps `go test ./...` green on
// a machine with no database.
func LockDatabase() (release func(), err error) {
	dsn := os.Getenv("CONSOLE_TEST_DSN")
	if dsn == "" {
		return func() {}, nil
	}
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("connecting to take the test-schema lock: %w", err)
	}
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock($1)`, lockKey); err != nil {
		_ = conn.Close(ctx)
		return nil, fmt.Errorf("taking the test-schema lock: %w", err)
	}
	return func() {
		_, _ = conn.Exec(ctx, `SELECT pg_advisory_unlock($1)`, lockKey)
		_ = conn.Close(ctx)
	}, nil
}

// Main is the TestMain body for a package that resets the shared schema. A package uses it as:
//
//	func TestMain(m *testing.M) { consoletest.Main(m) }
func Main(m interface{ Run() int }) {
	release, err := LockDatabase()
	if err != nil {
		fmt.Fprintf(os.Stderr, "console tests: %v\n", err)
		os.Exit(1)
	}
	code := m.Run()
	release()
	os.Exit(code)
}
