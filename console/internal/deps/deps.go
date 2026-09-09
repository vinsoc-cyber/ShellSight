// Package deps computes which rules reference which other rules.
//
// YARA permits a rule's condition to name another rule. That makes two console operations unsafe
// without a reference graph:
//
//   - EXCLUDING a rule that others depend on leaves an unresolved identifier, and a compile with an
//     unresolved identifier produces NO blob at all -- so one exclusion blocks every analyst's
//     builds, not just the excluding one's.
//   - VALIDATING a rule by compiling it alone rejects any rule that has a dependency. Measured over
//     the shipped packs, that is 50 rules, including 16 of the first 400 in the YARA-Forge pack.
//
// Scanning is limited to the condition section. A rule name appearing in a meta description or a
// string literal is not a reference, and treating it as one would invent dependencies that do not
// exist -- which in the exclusion gate means refusing an exclusion for no reason.
package deps

import "regexp"

var (
	ruleDecl   = regexp.MustCompile(`(?m)^[ \t]*(?:private[ \t]+)?(?:global[ \t]+)?rule[ \t]+([A-Za-z_][A-Za-z0-9_]*)`)
	identifier = regexp.MustCompile(`\b([A-Za-z_][A-Za-z0-9_]*)\b`)
)

// noise is YARA's own vocabulary plus the module namespaces. These parse as identifiers and are
// never rule references.
var noise = map[string]bool{}

func init() {
	for _, w := range []string{
		"and", "or", "not", "all", "any", "of", "them", "for", "in", "at", "filesize", "entrypoint",
		"true", "false", "condition", "strings", "meta", "rule", "private", "global", "import",
		"include", "this", "defined", "none", "matches", "contains", "icontains", "startswith",
		"endswith", "istartswith", "iendswith", "iequals", "wide", "ascii", "nocase", "fullword",
		"base64", "base64wide", "xor", "KB", "MB", "GB",
		"uint8", "uint16", "uint32", "int8", "int16", "int32",
		"uint8be", "uint16be", "uint32be", "int8be", "int16be", "int32be",
		"pe", "elf", "math", "hash", "dotnet", "time", "cuckoo", "magic", "console", "string",
	} {
		noise[w] = true
	}
}

// Graph holds the reference relation over a set of rules, keyed by rule identifier.
type Graph struct {
	direct  map[string]map[string]bool // rule -> rules it names directly
	reverse map[string]map[string]bool // rule -> rules that name it directly
}

// New builds the graph from identifier -> full rule text.
func New(rules map[string]string) *Graph {
	g := &Graph{direct: map[string]map[string]bool{}, reverse: map[string]map[string]bool{}}
	for name := range rules {
		g.direct[name] = map[string]bool{}
		g.reverse[name] = map[string]bool{}
	}
	for name, text := range rules {
		for _, ref := range referencesIn(text, rules) {
			if ref == name {
				continue // a rule naming itself is not a dependency we can act on
			}
			g.direct[name][ref] = true
			g.reverse[ref][name] = true
		}
	}
	return g
}

// referencesIn returns the known rule names appearing in text's CONDITION section.
func referencesIn(text string, known map[string]string) []string {
	idx := conditionStart(text)
	if idx < 0 {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, m := range identifier.FindAllStringSubmatch(text[idx:], -1) {
		tok := m[1]
		if noise[tok] || seen[tok] {
			continue
		}
		if _, ok := known[tok]; ok {
			seen[tok] = true
			out = append(out, tok)
		}
	}
	return out
}

// condRe finds the `condition:` keyword.
var condRe = regexp.MustCompile(`(?m)^\s*condition\s*:`)

// conditionStart finds the `condition:` keyword. Returns -1 when the rule has none, which a
// malformed rule can produce -- callers treat that as "no references" rather than an error,
// because the compile check is what reports malformedness.
//
// FindStringIndex returns nil when there is no match, so the result must be nil-checked before
// it is indexed. An earlier draft of this plan indexed it directly and would have panicked on
// any rule without a condition section.
func conditionStart(text string) int {
	loc := condRe.FindStringIndex(text)
	if loc == nil {
		return -1
	}
	return loc[0]
}

// DependenciesOf returns every rule that must be compiled alongside name, transitively.
func (g *Graph) DependenciesOf(name string) []string { return g.walk(name, g.direct) }

// DependentsOf returns every rule that would fail to compile if name were excluded, transitively.
// This is the blast radius the exclusion gate reports to the analyst.
func (g *Graph) DependentsOf(name string) []string { return g.walk(name, g.reverse) }

// walk does a breadth-first traversal, guarding against cycles. YARA forbids circular rule
// references, but the graph is built from text the console did not write, so it must not hang on one.
func (g *Graph) walk(start string, edges map[string]map[string]bool) []string {
	seen := map[string]bool{start: true}
	queue := []string{start}
	var out []string
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for next := range edges[cur] {
			if seen[next] {
				continue
			}
			seen[next] = true
			out = append(out, next)
			queue = append(queue, next)
		}
	}
	return out
}
