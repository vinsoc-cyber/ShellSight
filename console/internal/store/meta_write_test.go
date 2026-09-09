package store

import (
	"context"
	"testing"
)

const ruleWithMeta = `
rule AcmeCustomShell {
   meta:
      description = "detects the Acme uploader backdoor"
      author = "v.quannh67"
      score = 80
   condition:
      true
}
`

func TestCreateRuleStoresParsedMetadata(t *testing.T) {
	// A rule written in the console must be searchable in the browser without waiting for a
	// backfill run.
	s := newTestStore(t)
	ctx := context.Background()
	id, err := s.CreateRule(ctx, Rule{Identifier: "AcmeCustomShell", Layer: "own"},
		RuleRevision{Text: ruleWithMeta, Author: "v.quannh67"})
	if err != nil {
		t.Fatal(err)
	}

	_, rev, err := s.GetRule(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if rev.Description != "detects the Acme uploader backdoor" {
		t.Errorf("Description = %q", rev.Description)
	}
	if rev.Score == nil || *rev.Score != 80 {
		t.Errorf("Score = %v, want 80", rev.Score)
	}
	if rev.Meta["author"] != "v.quannh67" {
		t.Errorf("Meta[author] = %q", rev.Meta["author"])
	}
}

func TestAddRevisionReparsesTheMetadata(t *testing.T) {
	// Metadata belongs to the revision, so editing a rule's text must move its description with it.
	s := newTestStore(t)
	ctx := context.Background()
	id, err := s.CreateRule(ctx, Rule{Identifier: "Edited", Layer: "own"},
		RuleRevision{Text: ruleWithMeta, Author: "a"})
	if err != nil {
		t.Fatal(err)
	}
	edited := `
rule Edited {
   meta:
      description = "rewritten after a false positive"
      score = 55
   condition:
      true
}
`
	if _, err := s.AddRevision(ctx, id, RuleRevision{Text: edited, Author: "a"}); err != nil {
		t.Fatal(err)
	}

	_, rev, err := s.GetRule(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if rev.Description != "rewritten after a false positive" {
		t.Errorf("Description = %q, want the new revision's", rev.Description)
	}
	if rev.Score == nil || *rev.Score != 55 {
		t.Errorf("Score = %v, want 55", rev.Score)
	}
}

func TestARuleWithNoMetaBlockStoresNulls(t *testing.T) {
	// Not an error. 17 rules in the shipped packs are exactly that.
	s := newTestStore(t)
	ctx := context.Background()
	id, err := s.CreateRule(ctx, Rule{Identifier: "Bare", Layer: "own"},
		RuleRevision{Text: "rule Bare { condition: true }", Author: "a"})
	if err != nil {
		t.Fatalf("a rule with no meta block must still be storable: %v", err)
	}
	_, rev, err := s.GetRule(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if rev.Description != "" || rev.Score != nil {
		t.Errorf("got description=%q score=%v, want empty and nil", rev.Description, rev.Score)
	}
	if rev.Meta == nil {
		t.Error("Meta is nil; want an empty map so a caller can index it without a check")
	}
}
