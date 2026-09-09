// Package packimport splits a monolithic YARA pack into per-rule records.
//
// The console's library unit is one rule, but the bundled packs are single files -- yara-rules-core
// holds 5,152 rules in 172,252 lines. Import therefore has to split them.
//
// THE SPLIT IS AT RULE STARTS, NOT BY BRACE MATCHING. The splitter never needs to find where a rule
// ENDS, only where the next one BEGINS, so braces inside string literals and comments are not a
// hazard -- and both occur in the real packs. Anything between the end of one rule and the start of
// the next (comments, blank lines) is attached to the preceding rule, which is harmless.
//
// Measured (docs/measurements/2026-08-30-yarc-parity/ C4): splitting yara-rules-core this way and
// recompiling the 5,152 records produces a blob BYTE-IDENTICAL to compiling the original file.
package packimport

import (
	"fmt"
	"regexp"
	"strings"
)

type Rule struct {
	Identifier string
	Text       string // the pack's imports, then the rule
	Private    bool
}

var (
	ruleStart = regexp.MustCompile(`^[ \t]*(?:private[ \t]+)?(?:global[ \t]+)?rule[ \t]+([A-Za-z_][A-Za-z0-9_]*)`)
	importRe  = regexp.MustCompile(`^[ \t]*import[ \t]+"`)
)

// Split returns one record per rule, in pack order.
func Split(pack string) ([]Rule, error) {
	lines := strings.Split(pack, "\n")

	var starts []int
	for i, l := range lines {
		if ruleStart.MatchString(l) {
			starts = append(starts, i)
		}
	}
	if len(starts) == 0 {
		return nil, fmt.Errorf("no rule declarations found")
	}

	// The header is everything before the first rule; only its imports travel with each record.
	var imports []string
	for _, l := range lines[:starts[0]] {
		if importRe.MatchString(l) {
			imports = append(imports, strings.TrimSpace(l))
		}
	}
	prefix := ""
	if len(imports) > 0 {
		prefix = strings.Join(imports, "\n") + "\n\n"
	}

	seen := map[string]bool{}
	out := make([]Rule, 0, len(starts))
	for n, s := range starts {
		end := len(lines)
		if n+1 < len(starts) {
			end = starts[n+1]
		}
		decl := lines[s]
		name := ruleStart.FindStringSubmatch(decl)[1]
		if seen[name] {
			return nil, fmt.Errorf("pack declares rule %q more than once", name)
		}
		seen[name] = true
		out = append(out, Rule{
			Identifier: name,
			Text:       prefix + strings.Join(lines[s:end], "\n") + "\n",
			Private:    strings.Contains(decl, "private "),
		})
	}
	return out, nil
}
