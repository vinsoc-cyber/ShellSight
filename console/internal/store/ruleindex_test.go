package store

import (
	"context"
	"testing"
)

func TestRuleIndexReturnsOneRowPerRuleOrderedByIdentifier(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if _, err := s.CreateRule(ctx, Rule{Identifier: "Zulu", Layer: "own", SourcePack: "shellsight"},
		RuleRevision{Text: "rule Zulu {\n meta:\n  description = \"last alphabetically\"\n  score = 60\n condition:\n  true\n}", Author: "a"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateRule(ctx, Rule{Identifier: "Alpha", Layer: "foundation", SourcePack: "yara-forge-core"},
		RuleRevision{Text: "rule Alpha {\n meta:\n  description = \"first\"\n condition:\n  true\n}", Author: "a"}); err != nil {
		t.Fatal(err)
	}

	got, err := s.RuleIndex(ctx)
	if err != nil {
		t.Fatalf("index: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d rows, want 2", len(got))
	}
	// Ordered by identifier so the browser is stable between loads.
	if got[0].Identifier != "Alpha" || got[1].Identifier != "Zulu" {
		t.Fatalf("order = %q,%q want Alpha,Zulu", got[0].Identifier, got[1].Identifier)
	}
	if got[0].Layer != "foundation" || got[0].SourcePack != "yara-forge-core" {
		t.Errorf("Alpha = %+v", got[0])
	}
	if got[0].Description != "first" {
		t.Errorf("Alpha description = %q", got[0].Description)
	}
	if got[0].Score != nil {
		t.Errorf("Alpha declared no score, got %v", got[0].Score)
	}
	if got[1].Score == nil || *got[1].Score != 60 {
		t.Errorf("Zulu score = %v, want 60", got[1].Score)
	}
}

func TestRuleIndexUsesTheLatestRevision(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	id, err := s.CreateRule(ctx, Rule{Identifier: "Moves", Layer: "own"},
		RuleRevision{Text: "rule Moves {\n meta:\n  description = \"old\"\n condition:\n  true\n}", Author: "a"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddRevision(ctx, id,
		RuleRevision{Text: "rule Moves {\n meta:\n  description = \"new\"\n condition:\n  true\n}", Author: "a"}); err != nil {
		t.Fatal(err)
	}

	got, err := s.RuleIndex(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d rows, want 1 -- a second revision must not add a row", len(got))
	}
	if got[0].Description != "new" {
		t.Errorf("description = %q, want the latest revision's", got[0].Description)
	}
}

func TestRuleIndexOmitsADeletedRule(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	own, _ := seedRules(t, s)
	if err := s.SoftDeleteRule(ctx, own); err != nil {
		t.Fatal(err)
	}
	got, err := s.RuleIndex(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range got {
		if r.ID == own {
			t.Fatalf("a soft-deleted rule is still in the index: %+v", r)
		}
	}
}

func TestRuleIndexIsNeverNil(t *testing.T) {
	s := newTestStore(t)
	got, err := s.RuleIndex(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Error("RuleIndex returned nil; the API encodes it straight to JSON and null crashes the browser")
	}
}
