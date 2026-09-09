package store

import (
	"context"
	"testing"
)

func seedRules(t *testing.T, s *PG) (own, custom int64) {
	t.Helper()
	ctx := context.Background()
	var err error
	own, err = s.CreateRule(ctx, Rule{Identifier: "own_rule", Layer: "own"},
		RuleRevision{Text: "rule own_rule { condition: true }", Author: "a"})
	if err != nil {
		t.Fatal(err)
	}
	custom, err = s.CreateRule(ctx, Rule{Identifier: "custom_rule", Layer: "custom"},
		RuleRevision{Text: "rule custom_rule { condition: true }", Author: "a"})
	if err != nil {
		t.Fatal(err)
	}
	return own, custom
}

func TestSelectionRoundTrips(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	own, _ := seedRules(t, s)

	id, err := s.CreateRuleSet(ctx, "acme-ir", "v.quannh67")
	if err != nil {
		t.Fatalf("create set: %v", err)
	}
	want := Selection{Layers: []string{"own"}, Rules: []int64{own}}
	if err := s.SetSelection(ctx, id, want); err != nil {
		t.Fatalf("set selection: %v", err)
	}
	got, err := s.GetSelection(ctx, id)
	if err != nil {
		t.Fatalf("get selection: %v", err)
	}
	if len(got.Layers) != 1 || got.Layers[0] != "own" || len(got.Rules) != 1 {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestResolveSelectionReturnsLatestRevisionsMinusExclusions(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	own, custom := seedRules(t, s)

	id, _ := s.CreateRuleSet(ctx, "set", "a")
	if err := s.SetSelection(ctx, id, Selection{Layers: []string{"own", "custom"}}); err != nil {
		t.Fatal(err)
	}

	revs, err := s.ResolveSelection(ctx, id)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(revs) != 2 {
		t.Fatalf("got %d revisions, want 2", len(revs))
	}

	if err := s.AddExclusion(ctx, id, custom, "noisy on Acme CMS", "v.quannh67"); err != nil {
		t.Fatalf("exclude: %v", err)
	}
	revs, err = s.ResolveSelection(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if len(revs) != 1 || revs[0].RuleID != own {
		t.Fatalf("exclusion was not applied: got %+v", revs)
	}

	ex, err := s.ListExclusions(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if len(ex) != 1 || ex[0].Reason != "noisy on Acme CMS" || ex[0].Identifier != "custom_rule" {
		t.Fatalf("got %+v", ex)
	}
}

func TestResolveSelectionPicksTheLatestRevision(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	own, _ := seedRules(t, s)
	if _, err := s.AddRevision(ctx, own, RuleRevision{Text: "rule own_rule { condition: false }", Author: "b"}); err != nil {
		t.Fatal(err)
	}
	id, _ := s.CreateRuleSet(ctx, "set", "a")
	if err := s.SetSelection(ctx, id, Selection{Rules: []int64{own}}); err != nil {
		t.Fatal(err)
	}
	revs, err := s.ResolveSelection(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if len(revs) != 1 || revs[0].Revision != 2 {
		t.Fatalf("got revision %d, want the latest (2)", revs[0].Revision)
	}
}
