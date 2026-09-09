// Package triage turns a flat list of findings into the items an analyst actually decides on.
//
// The unit is CONTENT. One webshell copied into twelve directories across four hosts, matched by
// five rules apiece, is ONE item and ONE decision -- not sixty. That is the whole reason grouping
// exists, and it is why the key is the file's content hash rather than Finding.Fingerprint, which
// embeds the host and path and would give sixty.
package triage

import (
	"sort"

	"shellsightconsole/internal/store"
)

// tierRank orders the verdict bands. Higher is worse.
var tierRank = map[string]int{
	"clean": 0, "unknown": 1, "suspicious": 2, "likely-malicious": 3, "confirmed": 4,
}

// Group is one piece of content and everything said about it.
type Group struct {
	ContentKey string                `json:"content_key"`
	Tier       string                `json:"tier"`
	Score      int                   `json:"score"`
	Locations  int                   `json:"locations"`
	Hosts      []string              `json:"hosts"`
	Rules      []string              `json:"rules"`
	Findings   []store.FindingRecord `json:"findings"`
}

// Groups collapses findings by content key, ordered worst-first. It is named for what it returns
// rather than sharing the type's name, which Go does not allow at one package scope.
func Groups(in []store.FindingRecord) []Group {
	byKey := map[string]*Group{}
	var order []string

	for _, f := range in {
		g, seen := byKey[f.ContentKey]
		if !seen {
			g = &Group{ContentKey: f.ContentKey}
			byKey[f.ContentKey] = g
			order = append(order, f.ContentKey)
		}
		g.Findings = append(g.Findings, f)

		// The group's severity is the WORST thing said about the content, not the first.
		if tierRank[f.Tier] > tierRank[g.Tier] {
			g.Tier = f.Tier
		}
		if f.Score > g.Score {
			g.Score = f.Score
		}
	}

	out := make([]Group, 0, len(order))
	for _, k := range order {
		g := byKey[k]
		g.Locations = countDistinct(g.Findings, func(f store.FindingRecord) string {
			return f.Host + "|" + f.FilePath
		})
		g.Hosts = distinct(g.Findings, func(f store.FindingRecord) string { return f.Host })
		g.Rules = distinct(g.Findings, func(f store.FindingRecord) string { return f.KnowledgeRef })
		out = append(out, *g)
	}

	sort.SliceStable(out, func(i, j int) bool {
		if tierRank[out[i].Tier] != tierRank[out[j].Tier] {
			return tierRank[out[i].Tier] > tierRank[out[j].Tier]
		}
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		return out[i].Locations > out[j].Locations
	})
	return out
}

func distinct(in []store.FindingRecord, key func(store.FindingRecord) string) []string {
	seen := map[string]bool{}
	var out []string
	for _, f := range in {
		k := key(f)
		if k == "" || seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func countDistinct(in []store.FindingRecord, key func(store.FindingRecord) string) int {
	seen := map[string]bool{}
	for _, f := range in {
		seen[key(f)] = true
	}
	return len(seen)
}
