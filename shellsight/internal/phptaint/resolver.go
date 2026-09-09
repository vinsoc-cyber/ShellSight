// Package phptaint provides static, PHP-aware resolution that the byte-level YARA rules cannot
// express. It NEVER executes PHP. Tier 1 (this file) resolves the variable-function dispatch
// pattern where a sink NAME is assembled at runtime (chr()/concat) into a variable and then
// invoked: $X = <sink-name>; ... $X(  ->  a synthetic layer rewrites $X( to the literal sink name,
// so the existing literal-anchored YARA rules fire on the resolved call site.
//
// The approach mirrors the deobfuscate engine: pure (bytes -> layers), bounded, FP-gated (a layer
// is only emitted if resolving unmasks a sink call that was not literally present).
package phptaint

import (
	"bytes"
	"regexp"
	"strconv"
)

const (
	maxResolveSize = 1 << 20 // cap input size (pathological large benign files)
	maxAssignments = 4096    // cap assignments scanned per file
)

// Layer is one resolved view of the source, mirroring deobfuscate.Layer.
type Layer struct {
	Method string
	Data   []byte
}

var (
	reComment = regexp.MustCompile(`(?s)/\*.*?\*/`)
	reConcatD = regexp.MustCompile(`"([^"\\]*)"\s*\.\s*"([^"\\]*)"`)
	reConcatS = regexp.MustCompile(`'([^'\\]*)'\s*\.\s*'([^'\\]*)'`)
	reChr     = regexp.MustCompile(`chr\s*\(\s*(\d+)\s*\)`)
	// $X = <rhs>;  — capture the variable name and rhs (bounded length, single statement).
	reAssign = regexp.MustCompile(`(\$\w+)\s*=\s*([^;{}\n]{1,300});`)
)

// sinkNames are the dangerous function names whose assignment to a variable + later call is the
// signal we resolve. Order does not matter; matching is case-insensitive.
var sinkNames = []string{
	"eval", "assert", "system", "exec", "passthru", "shell_exec",
	"proc_open", "popen", "pcntl_exec", "create_function", "call_user_func",
	"call_user_func_array", "preg_replace", "include", "require",
}

// fold statically resolves chr(N) and adjacent "a"."b" string concatenation to fixed point, so a
// sink name built from pieces collapses to its literal form in the rhs we inspect.
func fold(src []byte) []byte {
	d := reComment.ReplaceAll(src, nil)
	for iter := 0; iter < 60; iter++ {
		nd := reConcatD.ReplaceAllFunc(d, func(m []byte) []byte {
			g := reConcatD.FindSubmatch(m)
			return []byte("\"" + string(g[1]) + string(g[2]) + "\"")
		})
		nd = reConcatS.ReplaceAllFunc(nd, func(m []byte) []byte {
			g := reConcatS.FindSubmatch(m)
			return []byte("'" + string(g[1]) + string(g[2]) + "'")
		})
		nd = reChr.ReplaceAllFunc(nd, func(m []byte) []byte {
			g := reChr.FindSubmatch(m)
			n, err := strconv.ParseInt(string(g[1]), 10, 32)
			if err != nil || n < 32 || n > 126 || n == '"' {
				return m
			}
			// Emit a QUOTED char so concat-fold ("a"."b" -> "ab") can merge it with adjacent
			// quoted fragments (sink names are [a-z_], so quoting is always safe here).
			return []byte("\"" + string(rune(n)) + "\"")
		})
		if bytes.Equal(nd, d) {
			break
		}
		d = nd
	}
	return d
}

// ResolvedLayers returns synthetic layers in which resolved variable-function call sites are
// rewritten to their literal sink name, so existing literal-anchored YARA rules can fire. Each
// returned layer is gated: it is only emitted if rewriting unmasked a sink call ("sink(") that was
// not literally present in the original source. Returns nil for non-PHP-looking or oversize input.
func ResolvedLayers(src []byte) []Layer {
	if len(src) == 0 || len(src) > maxResolveSize || !bytes.Contains(src, []byte("$")) {
		return nil
	}
	folded := fold(src)

	// Collect variables whose rhs (after folding) contains a sink-name token. LAST-write-wins:
	// a later assignment to the same var overrides an earlier one, and a later NON-sink assignment
	// clears it. Without this, $f='exec'; $f='executeQuery'; $f($_GET['q']) would falsely resolve
	// $f to exec (the first assignment) and synthesize exec($_GET['q']) -> a false positive.
	lastSink := map[string]string{}
	var order []string // first-seen order, for stable layer emission
	matches := reAssign.FindAllSubmatch(folded, maxAssignments)
	for _, m := range matches {
		varName, rhs := m[1], bytes.ToLower(m[2])
		vn := string(varName)
		found := ""
		for _, s := range sinkNames {
			if containsWord(rhs, []byte(s)) {
				found = s
				break
			}
		}
		if found != "" {
			if _, ok := lastSink[vn]; !ok {
				order = append(order, vn)
			}
			lastSink[vn] = found
		} else {
			delete(lastSink, vn) // reassigned to a non-sink -> no longer a resolved sink
		}
	}
	if len(lastSink) == 0 {
		return nil
	}

	var out []Layer
	for _, vn := range order {
		sink, ok := lastSink[vn]
		if !ok {
			continue
		}
		// Rewrite "$<var>(" (and "${<var>}(") occurrences to "<sink>(".
		callRe := regexp.MustCompile(`\$\{?` + regexp.QuoteMeta(vn[1:]) + `\}?\s*\(`)
		rewritten := callRe.ReplaceAll(folded, []byte(sink+"("))
		// FP gate: only emit if rewriting revealed a sink call not in the ORIGINAL source.
		if bytes.Contains(bytes.ToLower(rewritten), []byte(sink+"(")) &&
			!bytes.Contains(bytes.ToLower(src), []byte(sink+"(")) {
			out = append(out, Layer{Method: "php-resolved:" + sink, Data: rewritten})
		}
	}
	return out
}

// containsWord reports whether b contains needle as a word (bounded by non-[a-z0-9_]).
func containsWord(b, needle []byte) bool {
	idx := bytes.Index(b, needle)
	for idx >= 0 {
		before := idx == 0 || !isWordByte(b[idx-1])
		after := idx+len(needle) == len(b) || !isWordByte(b[idx+len(needle)])
		if before && after {
			return true
		}
		next := idx + 1
		if next >= len(b) {
			break
		}
		sub := b[next:]
		off := bytes.Index(sub, needle)
		if off < 0 {
			break
		}
		idx = next + off
	}
	return false
}

func isWordByte(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') || b == '_'
}
