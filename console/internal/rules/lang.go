package rules

import (
	"fmt"
	"regexp"
	"sort"
)

// validLangs mirrors declaredWeblangs in cmd/diskprobe/rulegate.go. The console offers these as a
// fixed choice rather than a text field: an unrecognised value changes which files a rule may fire
// on, and no compiler can see the mistake.
var validLangs = map[string]bool{
	"php": true, "jsp": true, "java": true, "asp": true, "aspx": true,
	"dotnet": true, "asp-family": true, "web-generic": true,
	"perl": true, "python": true, "shtml": true,
}

func ValidLang(s string) bool { return validLangs[s] }

// Langs returns the accepted shellsight_lang values, sorted. The order is part of the contract:
// the API serves this list to a <select>, and map iteration order would reshuffle the dropdown on
// every page load.
func Langs() []string {
	out := make([]string, 0, len(validLangs))
	for k := range validLangs {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ruleDecl matches a YARA rule declaration, allowing the optional `private`/`global` modifiers and
// an optional tag list. Anchored to a line start so the word "rule" inside a string cannot match.
var ruleDecl = regexp.MustCompile(`(?m)^[ \t]*(?:private[ \t]+)?(?:global[ \t]+)?rule[ \t]+([A-Za-z_][A-Za-z0-9_]*)`)

// Identifier returns the single rule identifier declared in text.
//
// Exactly one rule per editor pane: two would make a revision history and an exclusion ambiguous
// about which rule they refer to.
func Identifier(text string) (string, error) {
	m := ruleDecl.FindAllStringSubmatch(text, -1)
	switch len(m) {
	case 0:
		return "", fmt.Errorf("no rule declaration found")
	case 1:
		return m[0][1], nil
	default:
		return "", fmt.Errorf("text declares %d rules; one rule per entry", len(m))
	}
}
