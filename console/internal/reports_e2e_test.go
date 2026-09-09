package console_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"shellsightconsole/internal/reports"
	"shellsightconsole/internal/store"
	"shellsightconsole/internal/triage"
)

// TestIngestGroupAndRemember is the whole reports slice in one test: ingest a real scanner report,
// group its findings by content, record a judgement, and confirm the judgement comes back for the
// same content on a DIFFERENT case.
func TestIngestGroupAndRemember(t *testing.T) {
	dsn := os.Getenv("CONSOLE_TEST_DSN")
	if dsn == "" {
		t.Skip("CONSOLE_TEST_DSN not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if _, err := pool.Exec(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public;`); err != nil {
		t.Fatal(err)
	}
	if err := store.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	st := store.NewPG(pool)

	// A real scanner report, copied into a run folder.
	body, err := os.ReadFile(filepath.Join("report", "testdata", "report.json"))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "report.json"), body, 0o644); err != nil {
		t.Fatal(err)
	}

	first, err := st.CreateCase(ctx, "IR-first", "tester")
	if err != nil {
		t.Fatal(err)
	}
	res, err := reports.NewService(st).IngestFolder(ctx, first, dir)
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if !res.Created || res.Findings == 0 {
		t.Fatalf("ingest produced nothing: %+v", res)
	}

	rows, err := st.FindingsForScan(ctx, res.ScanID)
	if err != nil {
		t.Fatal(err)
	}
	groups := triage.Groups(rows)
	if len(groups) == 0 {
		t.Fatal("no groups")
	}
	if len(groups) >= len(rows) {
		t.Fatalf("grouping did nothing: %d groups for %d findings", len(groups), len(rows))
	}

	// The property this whole slice exists to deliver, stated exactly rather than as an
	// inequality. The fixture is ONE webshell the scanner reported FIVE times -- five rules,
	// five distinct fingerprints, one SHA-256. It must reach the analyst as one queue item
	// carrying all five, because "5 groups of 1" and "2 groups" both satisfy the loose
	// `len(groups) < len(rows)` check above while being exactly the failure that matters.
	if len(rows) != 5 {
		t.Fatalf("fixture no longer supplies the five-rules-one-file case: %d findings, want 5", len(rows))
	}
	if len(groups) != 1 {
		t.Fatalf("one webshell became %d analyst queue items, want 1", len(groups))
	}
	if len(groups[0].Findings) != 5 {
		t.Fatalf("the single group carries %d findings, want all 5", len(groups[0].Findings))
	}
	t.Logf("end to end: %d findings collapsed to %d group carrying %d findings (content_key=%s)",
		len(rows), len(groups), len(groups[0].Findings), groups[0].ContentKey)

	// Judge the worst group.
	worst := groups[0]
	if _, err := st.RecordDecision(ctx, store.Decision{
		ContentKey: worst.ContentKey, Verdict: "malicious",
		Note: "confirmed webshell", Author: "tester", CaseID: &first,
	}); err != nil {
		t.Fatal(err)
	}

	// The same content, a different engagement.
	second, err := st.CreateCase(ctx, "IR-second", "tester")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE scans SET run_id='run-2', case_id=$1 WHERE id=$2`,
		second, res.ScanID); err != nil {
		t.Fatal(err)
	}

	priors, err := st.DecisionsFor(ctx, []string{worst.ContentKey})
	if err != nil {
		t.Fatal(err)
	}
	if len(priors[worst.ContentKey]) != 1 {
		t.Fatal("the prior judgement did not survive into the second case")
	}
	if priors[worst.ContentKey][0].CaseName != "IR-first" {
		t.Fatalf("prior names case %q, want IR-first", priors[worst.ContentKey][0].CaseName)
	}
}
