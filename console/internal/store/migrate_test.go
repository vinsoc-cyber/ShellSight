package store

import (
	"context"
	"testing"
)

func TestMigrateCreatesEveryTable(t *testing.T) {
	pool := testPool(t)
	if err := Migrate(context.Background(), pool); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	want := []string{
		"schema_migrations", "releases", "release_files",
		"rules", "rule_revisions", "rule_sets", "rule_set_members",
		"rule_set_exclusions", "audit_log",
	}
	for _, table := range want {
		var exists bool
		err := pool.QueryRow(context.Background(),
			`SELECT EXISTS (SELECT 1 FROM information_schema.tables
			                WHERE table_schema='public' AND table_name=$1)`, table).Scan(&exists)
		if err != nil {
			t.Fatalf("check %s: %v", table, err)
		}
		if !exists {
			t.Errorf("table %s was not created", table)
		}
	}
}

func TestMigrateIsIdempotent(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	if err := Migrate(ctx, pool); err != nil {
		t.Fatalf("first migrate: %v", err)
	}
	if err := Migrate(ctx, pool); err != nil {
		t.Fatalf("second migrate must be a no-op, got: %v", err)
	}
	// Idempotent means the second run applies nothing NEW. It does NOT mean some fixed number of
	// migrations exists -- hardcoding that count makes every future migration red on arrival,
	// which is a failing test that says nothing about idempotency.
	files, err := migrationFS.ReadDir("migrations")
	if err != nil {
		t.Fatal(err)
	}
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM schema_migrations`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != len(files) {
		t.Fatalf("applied %d migrations, want %d (one row per embedded file)", n, len(files))
	}
}
