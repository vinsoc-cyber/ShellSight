package store

import (
	"context"
	"fmt"
	"sync"
	"testing"
)

func TestCreateRuleStoresRevisionOne(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	id, err := s.CreateRule(ctx,
		Rule{Identifier: "acme_uploader", Layer: "custom"},
		RuleRevision{Text: "rule acme_uploader { condition: true }", Lang: "php", Author: "v.quannh67"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	rule, rev, err := s.GetRule(ctx, id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if rule.Identifier != "acme_uploader" || rule.Layer != "custom" {
		t.Fatalf("got %+v", rule)
	}
	if rev.Revision != 1 {
		t.Fatalf("first revision is %d, want 1", rev.Revision)
	}
}

func TestAddRevisionIncrementsAndGetReturnsTheLatest(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	id, err := s.CreateRule(ctx,
		Rule{Identifier: "r", Layer: "own"},
		RuleRevision{Text: "v1", Author: "a"})
	if err != nil {
		t.Fatal(err)
	}
	n, err := s.AddRevision(ctx, id, RuleRevision{Text: "v2", Author: "b"})
	if err != nil {
		t.Fatalf("add revision: %v", err)
	}
	if n != 2 {
		t.Fatalf("new revision is %d, want 2", n)
	}
	_, rev, err := s.GetRule(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if rev.Text != "v2" || rev.Revision != 2 {
		t.Fatalf("got revision %d %q, want 2 \"v2\"", rev.Revision, rev.Text)
	}
}

func TestListRulesFiltersByLayerAndHidesDeleted(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	own, _ := s.CreateRule(ctx, Rule{Identifier: "o", Layer: "own"}, RuleRevision{Text: "x", Author: "a"})
	_, _ = s.CreateRule(ctx, Rule{Identifier: "c", Layer: "custom"}, RuleRevision{Text: "x", Author: "a"})

	got, err := s.ListRules(ctx, "own")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Identifier != "o" {
		t.Fatalf("got %+v, want the one own rule", got)
	}

	if err := s.SoftDeleteRule(ctx, own); err != nil {
		t.Fatal(err)
	}
	got, err = s.ListRules(ctx, "own")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("deleted rule still listed: %+v", got)
	}

	all, err := s.ListRules(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 1 {
		t.Fatalf("got %d rules across all layers, want 1 (the custom one)", len(all))
	}
}

func TestDuplicateIdentifierIsRejected(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	r := Rule{Identifier: "dup", Layer: "custom"}
	rev := RuleRevision{Text: "x", Author: "a"}
	if _, err := s.CreateRule(ctx, r, rev); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateRule(ctx, r, rev); err == nil {
		t.Fatal("expected a duplicate rule identifier to be rejected")
	}
}

func TestConcurrentAddRevisionsDoNotCollide(t *testing.T) {
	// The property the parent-row lock exists for, and which nothing previously tested. Without
	// the lock, concurrent writers read the same MAX(revision) and either hand out a duplicate
	// number or trip the UNIQUE(rule_id, revision) constraint.
	s := newTestStore(t)
	ctx := context.Background()
	id, err := s.CreateRule(ctx, Rule{Identifier: "raced", Layer: "own"},
		RuleRevision{Text: "v1", Author: "a"})
	if err != nil {
		t.Fatal(err)
	}

	const writers = 8
	got := make(chan int, writers)
	errs := make(chan error, writers)
	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			r, err := s.AddRevision(ctx, id, RuleRevision{Text: fmt.Sprintf("v%d", n), Author: "a"})
			if err != nil {
				errs <- err
				return
			}
			got <- r
		}(i)
	}
	wg.Wait()
	close(got)
	close(errs)

	for err := range errs {
		t.Fatalf("concurrent AddRevision failed: %v", err)
	}
	seen := map[int]bool{}
	for r := range got {
		if seen[r] {
			t.Fatalf("revision %d was handed out twice", r)
		}
		seen[r] = true
	}
	if len(seen) != writers {
		t.Fatalf("got %d distinct revisions, want %d", len(seen), writers)
	}
}

func TestAddRevisionRejectsAnUnknownRule(t *testing.T) {
	// Falls out of locking the parent: no parent row, no revision.
	s := newTestStore(t)
	if _, err := s.AddRevision(context.Background(), 999999,
		RuleRevision{Text: "orphan", Author: "a"}); err == nil {
		t.Fatal("expected AddRevision on an unknown rule id to fail")
	}
}
