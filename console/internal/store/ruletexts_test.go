package store

import (
	"context"
	"testing"
)

func TestAllRuleTextsReturnsTheLatestRevisionOfEachRule(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	a, err := s.CreateRule(ctx, Rule{Identifier: "alpha", Layer: "own"},
		RuleRevision{Text: "rule alpha { condition: true }", Author: "a"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateRule(ctx, Rule{Identifier: "beta", Layer: "custom"},
		RuleRevision{Text: "rule beta { condition: false }", Author: "a"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddRevision(ctx, a,
		RuleRevision{Text: "rule alpha { condition: false }", Author: "b"}); err != nil {
		t.Fatal(err)
	}

	got, err := s.AllRuleTexts(ctx)
	if err != nil {
		t.Fatalf("AllRuleTexts: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d rules, want 2", len(got))
	}
	if got["alpha"] != "rule alpha { condition: false }" {
		t.Fatalf("alpha is %q, want its LATEST revision", got["alpha"])
	}
	if got["beta"] != "rule beta { condition: false }" {
		t.Fatalf("beta is %q", got["beta"])
	}
}

func TestAllRuleTextsOmitsDeletedRules(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	id, err := s.CreateRule(ctx, Rule{Identifier: "gone", Layer: "own"},
		RuleRevision{Text: "rule gone { condition: true }", Author: "a"})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SoftDeleteRule(ctx, id); err != nil {
		t.Fatal(err)
	}
	got, err := s.AllRuleTexts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, present := got["gone"]; present {
		t.Fatal("a soft-deleted rule must not appear in the compile context")
	}
}
