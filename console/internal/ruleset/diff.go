package ruleset

import (
	"sort"

	"shellsightconsole/internal/store"
)

type RuleRef struct {
	RuleID     int64  `json:"rule_id"`
	Identifier string `json:"identifier"`
	Revision   int    `json:"revision"`
}

type RuleChange struct {
	RuleID       int64  `json:"rule_id"`
	Identifier   string `json:"identifier"`
	FromRevision int    `json:"from_revision"`
	ToRevision   int    `json:"to_revision"`
}

type RuleDiff struct {
	Added     []RuleRef    `json:"added"`
	Removed   []RuleRef    `json:"removed"`
	Changed   []RuleChange `json:"changed"`
	Unchanged int          `json:"unchanged"`
}

type ExclusionDiff struct {
	Added   []store.Exclusion `json:"added"`
	Removed []store.Exclusion `json:"removed"`
}

// DiffRules compares two resolved selections by RULE, not by revision id.
//
// The distinction matters: the same rule at a different revision is a CHANGE an analyst needs to
// see, whereas keying on revision id alone would report it as one removal plus one addition and
// bury the fact that it is the same detection with different text.
func DiffRules(from, to []store.RuleRevision, names map[int64]string) RuleDiff {
	fromByRule := map[int64]int{}
	for _, r := range from {
		fromByRule[r.RuleID] = r.Revision
	}
	toByRule := map[int64]int{}
	for _, r := range to {
		toByRule[r.RuleID] = r.Revision
	}

	var d RuleDiff
	for id, toRev := range toByRule {
		fromRev, present := fromByRule[id]
		switch {
		case !present:
			d.Added = append(d.Added, RuleRef{RuleID: id, Identifier: names[id], Revision: toRev})
		case fromRev != toRev:
			d.Changed = append(d.Changed, RuleChange{
				RuleID: id, Identifier: names[id], FromRevision: fromRev, ToRevision: toRev})
		default:
			d.Unchanged++
		}
	}
	for id, fromRev := range fromByRule {
		if _, present := toByRule[id]; !present {
			d.Removed = append(d.Removed, RuleRef{RuleID: id, Identifier: names[id], Revision: fromRev})
		}
	}

	// Sorted by identifier so the same comparison always renders in the same order.
	sort.Slice(d.Added, func(i, j int) bool { return d.Added[i].Identifier < d.Added[j].Identifier })
	sort.Slice(d.Removed, func(i, j int) bool { return d.Removed[i].Identifier < d.Removed[j].Identifier })
	sort.Slice(d.Changed, func(i, j int) bool { return d.Changed[i].Identifier < d.Changed[j].Identifier })
	return d
}

func DiffExclusions(from, to []store.Exclusion) ExclusionDiff {
	inFrom := map[int64]store.Exclusion{}
	for _, e := range from {
		inFrom[e.RuleID] = e
	}
	inTo := map[int64]store.Exclusion{}
	for _, e := range to {
		inTo[e.RuleID] = e
	}

	var d ExclusionDiff
	for id, e := range inTo {
		if _, present := inFrom[id]; !present {
			d.Added = append(d.Added, e)
		}
	}
	for id, e := range inFrom {
		if _, present := inTo[id]; !present {
			d.Removed = append(d.Removed, e)
		}
	}
	sort.Slice(d.Added, func(i, j int) bool { return d.Added[i].Identifier < d.Added[j].Identifier })
	sort.Slice(d.Removed, func(i, j int) bool { return d.Removed[i].Identifier < d.Removed[j].Identifier })
	return d
}
