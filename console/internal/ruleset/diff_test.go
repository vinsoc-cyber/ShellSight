package ruleset

import (
	"testing"

	"shellsightconsole/internal/store"
)

func TestDiffReportsAddedRemovedAndChangedRules(t *testing.T) {
	a := []store.RuleRevision{
		{RuleID: 1, Revision: 1},
		{RuleID: 2, Revision: 3},
		{RuleID: 3, Revision: 1},
	}
	b := []store.RuleRevision{
		{RuleID: 2, Revision: 5}, // same rule, different revision
		{RuleID: 3, Revision: 1}, // unchanged
		{RuleID: 4, Revision: 1}, // added
	}
	names := map[int64]string{1: "alpha", 2: "beta", 3: "gamma", 4: "delta"}

	d := DiffRules(a, b, names)

	if len(d.Removed) != 1 || d.Removed[0].Identifier != "alpha" {
		t.Fatalf("Removed = %+v, want [alpha]", d.Removed)
	}
	if len(d.Added) != 1 || d.Added[0].Identifier != "delta" {
		t.Fatalf("Added = %+v, want [delta]", d.Added)
	}
	if len(d.Changed) != 1 || d.Changed[0].Identifier != "beta" ||
		d.Changed[0].FromRevision != 3 || d.Changed[0].ToRevision != 5 {
		t.Fatalf("Changed = %+v, want beta 3->5", d.Changed)
	}
	if d.Unchanged != 1 {
		t.Fatalf("Unchanged = %d, want 1", d.Unchanged)
	}
}

func TestDiffOfIdenticalSetsIsEmpty(t *testing.T) {
	a := []store.RuleRevision{{RuleID: 1, Revision: 2}}
	d := DiffRules(a, a, map[int64]string{1: "alpha"})
	if len(d.Added) != 0 || len(d.Removed) != 0 || len(d.Changed) != 0 {
		t.Fatalf("identical sets produced a diff: %+v", d)
	}
	if d.Unchanged != 1 {
		t.Fatalf("Unchanged = %d, want 1", d.Unchanged)
	}
}

func TestDiffExclusionsReportsBothDirections(t *testing.T) {
	a := []store.Exclusion{{RuleID: 1, Identifier: "alpha", Reason: "noisy"}}
	b := []store.Exclusion{{RuleID: 2, Identifier: "beta", Reason: "false positives"}}

	d := DiffExclusions(a, b)

	if len(d.Removed) != 1 || d.Removed[0].Identifier != "alpha" {
		t.Fatalf("Removed = %+v", d.Removed)
	}
	if len(d.Added) != 1 || d.Added[0].Identifier != "beta" || d.Added[0].Reason != "false positives" {
		t.Fatalf("Added = %+v", d.Added)
	}
}
