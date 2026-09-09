package store

import (
	"context"
	"testing"
)

// frozenWithBoth pins both seeded rules into a fresh frozen set and returns its id.
func frozenWithBoth(t *testing.T, s *PG) int64 {
	t.Helper()
	ctx := context.Background()
	own, custom := seedRules(t, s)
	id, err := s.CreateRuleSet(ctx, "pinned", "v.quannh67")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetSelection(ctx, id, Selection{Rules: []int64{own, custom}}); err != nil {
		t.Fatal(err)
	}
	revs, err := s.ResolveSelection(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	ids := make([]int64, 0, len(revs))
	for _, r := range revs {
		ids = append(ids, r.ID)
	}
	if err := s.Freeze(ctx, id, 1, "v.quannh67", "ab"+repeat62(), ids); err != nil {
		t.Fatal(err)
	}
	return id
}

func TestFrozenMemberListNamesEachPinnedRule(t *testing.T) {
	// FrozenMembers carries every revision's full TEXT, which is what the compile path needs and
	// exactly what a browser does not: 5,872 rules would be megabytes of payload. This lists what
	// a set contains -- identifier, layer, revision -- without the text.
	s := newTestStore(t)
	id := frozenWithBoth(t, s)

	got, err := s.FrozenMemberList(context.Background(), id)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("listed %d members, want 2", len(got))
	}
	// Ordered by identifier, so the screen is stable between loads.
	if got[0].Identifier != "custom_rule" || got[1].Identifier != "own_rule" {
		t.Errorf("order = %q,%q want custom_rule,own_rule", got[0].Identifier, got[1].Identifier)
	}
	if got[0].Layer != "custom" || got[1].Layer != "own" {
		t.Errorf("layers = %q,%q want custom,own", got[0].Layer, got[1].Layer)
	}
	for _, m := range got {
		if m.Revision != 1 {
			t.Errorf("%s pinned at revision %d, want 1", m.Identifier, m.Revision)
		}
		if m.RuleID == 0 {
			t.Errorf("%s has no rule id, so the screen cannot link to it", m.Identifier)
		}
	}
}

func TestFrozenMemberListStillNamesADeletedRule(t *testing.T) {
	// The property that makes a frozen set reconstructible: it pins a REVISION, so deleting the
	// rule afterwards must not make the set look smaller than the blob an agent is carrying.
	// FrozenMembers deliberately does not filter deleted rules, and neither may this.
	s := newTestStore(t)
	ctx := context.Background()
	id := frozenWithBoth(t, s)

	before, err := s.FrozenMemberList(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SoftDeleteRule(ctx, before[0].RuleID); err != nil {
		t.Fatal(err)
	}

	after, err := s.FrozenMemberList(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) {
		t.Fatalf("after deleting one rule the set lists %d members, want %d — a frozen set must "+
			"not appear to shrink", len(after), len(before))
	}
}

func TestFrozenMemberListIsNeverNil(t *testing.T) {
	// A draft set pins nothing. The API encodes this straight to JSON, and `null` would crash a
	// client that maps over it instead of showing "pins nothing yet".
	s := newTestStore(t)
	ctx := context.Background()
	id, err := s.CreateRuleSet(ctx, "draft", "a")
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.FrozenMemberList(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Error("FrozenMemberList returned nil; want an empty slice")
	}
}
