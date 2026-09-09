package store

import (
	"context"
	"testing"
)

// nullOutMeta puts the database back into the state the migration leaves it in, so the backfill has
// something to do. Task 3 populates on write, so seeded rules arrive already parsed.
func nullOutMeta(t *testing.T, s *PG) {
	t.Helper()
	if _, err := s.pool.Exec(context.Background(),
		`UPDATE rule_revisions SET description=NULL, score=NULL, meta=NULL`); err != nil {
		t.Fatal(err)
	}
}

func seedForBackfill(t *testing.T, s *PG) {
	t.Helper()
	ctx := context.Background()
	rules := []struct {
		id, text string
	}{
		{"WithBoth", "rule WithBoth {\n meta:\n  description = \"has both\"\n  score = 75\n  author = \"a\"\n condition:\n  true\n}"},
		{"DescOnly", "rule DescOnly {\n meta:\n  description = \"no score here\"\n condition:\n  true\n}"},
		{"Bare", "rule Bare { condition: true }"},
	}
	for _, r := range rules {
		if _, err := s.CreateRule(ctx, Rule{Identifier: r.id, Layer: "own"},
			RuleRevision{Text: r.text, Author: "a"}); err != nil {
			t.Fatal(err)
		}
	}
	nullOutMeta(t, s)
}

func TestBackfillMetaPopulatesAndReportsCoverage(t *testing.T) {
	s := newTestStore(t)
	seedForBackfill(t, s)

	got, err := s.BackfillMeta(context.Background())
	if err != nil {
		t.Fatalf("backfill: %v", err)
	}
	if got.Revisions != 3 {
		t.Errorf("Revisions = %d, want 3", got.Revisions)
	}
	if got.Description != 2 {
		t.Errorf("Description = %d, want 2", got.Description)
	}
	if got.Score != 1 {
		t.Errorf("Score = %d, want 1", got.Score)
	}
	if got.NoMetaBlock != 1 {
		t.Errorf("NoMetaBlock = %d, want 1", got.NoMetaBlock)
	}
	if got.Keys["author"] != 1 {
		t.Errorf("Keys[author] = %d, want 1", got.Keys["author"])
	}
}

func TestBackfillMetaActuallyWritesTheValues(t *testing.T) {
	// Coverage counts alone would pass even if nothing were written.
	s := newTestStore(t)
	ctx := context.Background()
	seedForBackfill(t, s)
	if _, err := s.BackfillMeta(ctx); err != nil {
		t.Fatal(err)
	}

	var desc string
	var score *int
	if err := s.pool.QueryRow(ctx,
		`SELECT COALESCE(rv.description,''), rv.score
		   FROM rule_revisions rv JOIN rules ru ON ru.id = rv.rule_id
		  WHERE ru.identifier = 'WithBoth'`).Scan(&desc, &score); err != nil {
		t.Fatal(err)
	}
	if desc != "has both" {
		t.Errorf("description = %q, want %q", desc, "has both")
	}
	if score == nil || *score != 75 {
		t.Errorf("score = %v, want 75", score)
	}
}

func TestBackfillMetaIsIdempotent(t *testing.T) {
	// It will be run again after every pack import, so a second run must neither change values nor
	// report different coverage.
	s := newTestStore(t)
	ctx := context.Background()
	seedForBackfill(t, s)

	first, err := s.BackfillMeta(ctx)
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.BackfillMeta(ctx)
	if err != nil {
		t.Fatalf("second run: %v", err)
	}
	if first.Revisions != second.Revisions || first.Description != second.Description ||
		first.Score != second.Score || first.NoMetaBlock != second.NoMetaBlock {
		t.Errorf("coverage changed between runs: %+v then %+v", first, second)
	}
}

func TestBackfillMetaOnAnEmptyLibraryIsNotAnError(t *testing.T) {
	s := newTestStore(t)
	got, err := s.BackfillMeta(context.Background())
	if err != nil {
		t.Fatalf("empty library: %v", err)
	}
	if got.Revisions != 0 {
		t.Errorf("Revisions = %d, want 0", got.Revisions)
	}
	if got.Keys == nil {
		t.Error("Keys is nil; want an empty map so the report can range over it")
	}
}
