// Package rulemeta reads the meta: block of a YARA rule.
//
// It is a leaf package on purpose: internal/store parses on write, and internal/rules already
// imports internal/store, so a parser living in internal/rules would be an import cycle.
//
// The scan is LINE-ANCHORED and never looks for where the meta block or the rule ends. A
// block-delimited regex — match from meta: to the following strings: or condition: — silently
// returned zero keys for all 50 sampled yara-forge rules while measuring for this design, because
// real pack text does not cooperate. Reading forward line by line and stopping on the first line
// that IS a section header cannot fail that way: a description mentioning "strings:" does not start
// with it.
package rulemeta

import (
	"strconv"
	"strings"
)

// Meta is what one rule declared. Every field is optional: measured over the whole 5,872-rule
// library, 17 rules have no meta block at all and 422 declare no score.
type Meta struct {
	// HasBlock distinguishes "declared nothing" from "had no meta: block", which the coverage
	// report needs and a nil map cannot express.
	HasBlock    bool
	Description string
	Score       *int
	Keys        map[string]string
}

// Parse reads the first meta: block in text. Keys is never nil.
func Parse(text string) Meta {
	m := Meta{Keys: map[string]string{}}
	inBlock := false

	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)

		if !inBlock {
			// `meta:` possibly followed by a comment. Anything else is not the block's start.
			if head, ok := sectionHeader(line); ok && head == "meta" {
				inBlock = true
				m.HasBlock = true
			}
			continue
		}

		// The first line that IS a section header ends the block. A value merely CONTAINING
		// "strings:" does not match, because it does not start with it.
		if _, ok := sectionHeader(line); ok {
			break
		}
		if line == "" || strings.HasPrefix(line, "//") || strings.HasPrefix(line, "/*") {
			continue
		}

		key, value, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		key = strings.TrimSpace(key)
		if !isIdentifier(key) {
			// A YARA string definition ($a = ...) or anything else that is not a bare identifier.
			continue
		}
		m.Keys[key] = unquote(strings.TrimSpace(value))
	}

	m.Description = m.Keys["description"]
	if n, err := strconv.Atoi(m.Keys["score"]); err == nil {
		m.Score = &n
	}
	return m
}

// sectionHeader reports whether line is a YARA section header, and which one. It tolerates a
// trailing comment, which signature-base uses.
func sectionHeader(line string) (string, bool) {
	name, rest, found := strings.Cut(line, ":")
	if !found {
		return "", false
	}
	name = strings.TrimSpace(name)
	switch name {
	case "meta", "strings", "condition":
	default:
		return "", false
	}
	rest = strings.TrimSpace(rest)
	if rest != "" && !strings.HasPrefix(rest, "//") && !strings.HasPrefix(rest, "/*") {
		return "", false
	}
	return name, true
}

func isIdentifier(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r == '_':
		case i > 0 && r >= '0' && r <= '9':
		default:
			return false
		}
	}
	return true
}

// unquote strips one layer of double quotes and drops a trailing line comment on an unquoted
// value. It deliberately does not interpret escapes: the values are displayed, never re-parsed.
func unquote(s string) string {
	if len(s) >= 2 && strings.HasPrefix(s, `"`) {
		if end := strings.LastIndex(s, `"`); end > 0 {
			return s[1:end]
		}
	}
	if i := strings.Index(s, "//"); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}
	return s
}
