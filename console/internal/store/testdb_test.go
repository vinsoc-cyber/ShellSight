package store

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// testPool returns a pool against CONSOLE_TEST_DSN, or skips. Each caller gets a database
// migrated from scratch: the test database is dropped to public and re-migrated, so tests
// never inherit another test's rows.
func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("CONSOLE_TEST_DSN")
	if dsn == "" {
		t.Skip("CONSOLE_TEST_DSN not set; skipping PostgreSQL-backed test")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)
	if _, err := pool.Exec(context.Background(),
		`DROP SCHEMA public CASCADE; CREATE SCHEMA public;`); err != nil {
		t.Fatalf("reset schema: %v", err)
	}
	return pool
}

func TestTestPoolConnects(t *testing.T) {
	pool := testPool(t)
	var got int
	if err := pool.QueryRow(context.Background(), "SELECT 1").Scan(&got); err != nil {
		t.Fatalf("query: %v", err)
	}
	if got != 1 {
		t.Fatalf("got %d, want 1", got)
	}
}
