package store

import (
	"context"
	"strings"
	"testing"
)

func TestListRuleSetsReturnsNewestFirst(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	first, err := s.CreateRuleSet(ctx, "sweep-jan", "v.quannh67")
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.CreateRuleSet(ctx, "sweep-feb", "v.quannh67")
	if err != nil {
		t.Fatal(err)
	}

	got, err := s.ListRuleSets(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) < 2 {
		t.Fatalf("listed %d sets, want at least the 2 just created", len(got))
	}
	// Newest first: an analyst opening the screen wants the set they are working on, not the
	// oldest one the team ever made.
	if got[0].ID != second || got[1].ID != first {
		t.Errorf("order = %d,%d want %d,%d (newest first)", got[0].ID, got[1].ID, second, first)
	}
	if got[0].Name != "sweep-feb" {
		t.Errorf("name = %q, want sweep-feb", got[0].Name)
	}
}

func TestListRuleSetsIsNeverNil(t *testing.T) {
	// The API encodes this straight to JSON. A nil slice becomes `null`, and a UI that maps over
	// the response then crashes on an empty console instead of showing "no rule sets yet".
	s := newTestStore(t)
	got, err := s.ListRuleSets(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Error("ListRuleSets returned nil; want an empty slice")
	}
}

func TestListRuleSetsCarriesFrozenState(t *testing.T) {
	// Frozen vs draft is the single most important thing about a set on a list screen: a frozen
	// set is what an agent can actually be built from.
	s := newTestStore(t)
	ctx := context.Background()
	id, err := s.CreateRuleSet(ctx, "frozen-one", "a")
	if err != nil {
		t.Fatal(err)
	}
	// yarc_sha256 is CHAR(64) and BLANK-PADS anything shorter, so a real 64-character digest is
	// the only value that round-trips unchanged. Real hashes are exactly 64; short ones are not.
	hash := strings.Repeat("a", 64)
	if err := s.Freeze(ctx, id, 3, "a", hash, nil); err != nil {
		t.Fatal(err)
	}
	got, err := s.ListRuleSets(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var found *RuleSet
	for i := range got {
		if got[i].ID == id {
			found = &got[i]
		}
	}
	if found == nil {
		t.Fatal("the frozen set is missing from the list")
	}
	if found.FrozenAt == nil {
		t.Error("FrozenAt is nil on a frozen set")
	}
	if found.Version == nil || *found.Version != 3 {
		t.Errorf("Version = %v, want 3", found.Version)
	}
	if found.YarcSHA256 != hash {
		t.Errorf("YarcSHA256 = %q, want the 64-char digest", found.YarcSHA256)
	}
}
