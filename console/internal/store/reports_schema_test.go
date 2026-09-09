package store

import (
	"context"
	"testing"
)

func TestReportsMigrationCreatesItsTables(t *testing.T) {
	pool := testPool(t)
	if err := Migrate(context.Background(), pool); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	for _, table := range []string{"cases", "scans", "scan_coverage", "findings", "decisions"} {
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

func TestScansAreUniqueByRunID(t *testing.T) {
	// RunID is the ingest idempotency key. The constraint, not application logic, is what
	// guarantees a re-import cannot create a second scan.
	pool := testPool(t)
	ctx := context.Background()
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	var caseID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO cases (name, created_by) VALUES ('c','a') RETURNING id`).Scan(&caseID); err != nil {
		t.Fatal(err)
	}
	ins := `INSERT INTO scans (case_id, run_id, host, tier, score, incomplete, integrity)
	        VALUES ($1,'run-1','h','clean',0,false,'unverified')`
	if _, err := pool.Exec(ctx, ins, caseID); err != nil {
		t.Fatalf("first insert: %v", err)
	}
	if _, err := pool.Exec(ctx, ins, caseID); err == nil {
		t.Fatal("expected a duplicate run_id to be rejected")
	}
}

func TestADecisionIsKeyedOnContentNotOnAFinding(t *testing.T) {
	// The property that makes a judgement outlive the scan it was made on: decisions reference a
	// content key, so the next scan containing the same file finds them.
	pool := testPool(t)
	ctx := context.Background()
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	var n int
	err := pool.QueryRow(ctx,
		`SELECT count(*) FROM information_schema.columns
		  WHERE table_name='decisions' AND column_name='content_key'`).Scan(&n)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatal("decisions must be keyed on content_key")
	}
	err = pool.QueryRow(ctx,
		`SELECT count(*) FROM information_schema.columns
		  WHERE table_name='decisions' AND column_name='finding_id'`).Scan(&n)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatal("decisions must NOT be keyed on a finding id; that would die with the scan")
	}
}
