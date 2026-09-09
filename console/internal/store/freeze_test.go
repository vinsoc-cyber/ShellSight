package store

import (
	"context"
	"testing"
)

func TestFreezePinsRevisionsAndRecordsTheBlob(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	own, _ := seedRules(t, s)
	id, _ := s.CreateRuleSet(ctx, "baseline", "a")
	if err := s.SetSelection(ctx, id, Selection{Rules: []int64{own}}); err != nil {
		t.Fatal(err)
	}
	revs, err := s.ResolveSelection(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	blobHash := "ab" + repeat62()

	if err := s.Freeze(ctx, id, 1, "v.quannh67", blobHash, []int64{revs[0].ID}); err != nil {
		t.Fatalf("freeze: %v", err)
	}

	set, err := s.GetRuleSet(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if set.Version == nil || *set.Version != 1 {
		t.Fatalf("version is %v, want 1", set.Version)
	}
	if set.YarcSHA256 != blobHash || set.FrozenBy != "v.quannh67" || set.FrozenAt == nil {
		t.Fatalf("freeze metadata not recorded: %+v", set)
	}

	members, err := s.FrozenMembers(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if len(members) != 1 || members[0].RuleID != own {
		t.Fatalf("got %+v, want the pinned own rule", members)
	}
}

func TestAFrozenSetIsUnaffectedByLaterEditsAndDeletes(t *testing.T) {
	// The property that makes a frozen set reconstructible, and the reason members pin a
	// REVISION rather than a rule.
	s := newTestStore(t)
	ctx := context.Background()
	own, _ := seedRules(t, s)
	id, _ := s.CreateRuleSet(ctx, "baseline", "a")
	if err := s.SetSelection(ctx, id, Selection{Rules: []int64{own}}); err != nil {
		t.Fatal(err)
	}
	revs, _ := s.ResolveSelection(ctx, id)
	if err := s.Freeze(ctx, id, 1, "a", "cd"+repeat62(), []int64{revs[0].ID}); err != nil {
		t.Fatal(err)
	}
	frozenText := revs[0].Text

	if _, err := s.AddRevision(ctx, own, RuleRevision{Text: "rule own_rule { condition: false }", Author: "b"}); err != nil {
		t.Fatal(err)
	}
	if err := s.SoftDeleteRule(ctx, own); err != nil {
		t.Fatal(err)
	}

	members, err := s.FrozenMembers(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if len(members) != 1 {
		t.Fatalf("frozen set lost a member after the rule was edited and deleted: %+v", members)
	}
	if members[0].Text != frozenText {
		t.Fatalf("frozen member text changed: got %q, want %q", members[0].Text, frozenText)
	}
}

func TestFreezingAnAlreadyFrozenSetIsRejected(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	own, _ := seedRules(t, s)
	id, _ := s.CreateRuleSet(ctx, "baseline", "a")
	_ = s.SetSelection(ctx, id, Selection{Rules: []int64{own}})
	revs, _ := s.ResolveSelection(ctx, id)
	if err := s.Freeze(ctx, id, 1, "a", "ee"+repeat62(), []int64{revs[0].ID}); err != nil {
		t.Fatal(err)
	}
	if err := s.Freeze(ctx, id, 2, "a", "ff"+repeat62(), []int64{revs[0].ID}); err == nil {
		t.Fatal("expected re-freezing an immutable set to be rejected")
	}
}
