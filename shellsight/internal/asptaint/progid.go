// Constant folding for VBScript string expressions, and the COM object map it feeds.
//
// WHY THIS EXISTS
// ---------------
// `classic_asp_shell` is a literal-string YARA rule -- `("WScript.Shell" or "ExecuteGlobal") and
// "Request"` -- and `asptaint`'s ScriptControl sink was gated on `scriptControlRe`, a file-wide test
// for the literal token `ScriptControl`. Both miss `Server.CreateObject(Chr(77) & Chr(83) & ...)`
// BY CONSTRUCTION: the ProgID is never a literal in the file.
//
// Measured 2026-09-05 on a generated corpus crossing every ASP dispatch x channel x obfuscation
// cell: ShellSight caught 16 of 92 cells -- the four literal-sink dispatch cells at PLAINTEXT ONLY.
// Every obfuscated ProgID missed, and so did MSScriptControl and Shell.Application even in
// plaintext. The incumbent caught 90 of 92, not because it resolves anything but because its flat
// alternation contains `.CreateObject(` and `&`.
//
// THE METHOD, AND WHY THIS ONE
// -----------------------------
// Not a wider literal list -- that re-imports the weakness one alternation at a time. Fold the
// expression and resolve the ProgID at the call site.
//
// This is the third instance of a pattern already shipped twice in this repo, not a new idea:
// `internal/phptaint` resolves PHP variable functions, and `internal/perlpytaint` folds Perl/Python
// sink names. The recorded lesson from that work is the one that matters here -- **folding alone
// was INERT**; it only became a detection once the folded value was propagated to the call site.
// So this file does not merely fold: it binds the folded ProgID to the variable it was assigned to,
// and the sink gate then asks about the RECEIVER of the method call rather than about the file.
//
// That is strictly tighter than what it replaces. `scriptControlRe` fired if the token appeared
// anywhere in the file; this fires only when the object the method is called on is that object.
//
// PRIOR ART. `Neo23x0/signature-base`'s `gen_webshells.yar` -- the reference OSS rule set this
// project bundles -- contains NO Classic ASP rules at all (fetched 2026-09-05; ~20 PHP rules, and
// the only ASP-adjacent string is `"WScript.Shell.1"` inside a generic suspicious-indicator rule).
// So there is nothing to reuse for this technique and the "reuse first" step terminates. See
// the prior-art lit review for this pass (held privately).
package asptaint

import (
	"regexp"
	"strconv"
	"strings"
)

// The ProgIDs whose methods are execution sinks, lowercased for comparison. A ProgID is a stable
// registry identity, not an attacker-chosen name, which is what makes it a sound gate: an intruder
// can rename every variable in the file but cannot rename WScript.Shell and still get a shell.
const (
	progWScriptShell = "wscript.shell"
	progScriptCtl    = "scriptcontrol"
	progShellApp     = "shell.application"
	// Not an execution sink: ADODB.Stream is the binary-write half of a dropper, and it gates
	// `SaveToFile` in filedrop.go. Measured 2026-09-06: ungated, 7 of 8 benign hits were
	// Z-BlogASP's own four-argument `Call SaveToFile(...)` helper, which is not ADO at all.
	progADODBStream = "adodb.stream"

	// .NET types whose methods are execution or deserialisation sinks. Same role as a ProgID: a
	// framework type name the intruder cannot rename.
	typeLosFormatter = "losformatter"
	typeObjStateFmt  = "objectstateformatter"
	typeCSharpProv   = "csharpcodeprovider"
)

var (
	// `Set o = Server.CreateObject(<expr>)`, and the bare `CreateObject(<expr>)` form. The
	// expression is captured whole and folded; it is NOT required to be a literal, which is the
	// entire point.
	createObjRe = regexp.MustCompile(
		`(?i)^\s*(?:Set\s+)?([A-Za-z_]\w*)\s*=\s*(?:Server\s*\.\s*)?CreateObject\s*\(\s*(.+?)\s*\)\s*$`)

	// C# object construction: `LosFormatter lf = new LosFormatter();`, with an optional declared
	// type before the identifier. The captured type is the CONSTRUCTED one, not the declared one --
	// `object o = new LosFormatter()` should gate on LosFormatter, and a declared interface tells
	// you less than the concrete class does.
	newObjRe = regexp.MustCompile(
		`(?i)^\s*(?:[A-Za-z_][\w.]*(?:\s*\[\s*\])*\s+)?([A-Za-z_]\w*)\s*=\s*new\s+([A-Za-z_][\w.]*)`)

	// Folding atoms. RE2 has no backreferences and no lookaround, so a VBScript string literal --
	// which escapes a quote by doubling it -- is scanned by hand in foldOne rather than matched.
	chrRe        = regexp.MustCompile(`(?i)^Chr[W$]?\s*\(\s*(&H[0-9A-Fa-f]+|\d+)\s*\)$`)
	strReverseRe = regexp.MustCompile(`(?i)^StrReverse\s*\(\s*(.+)\s*\)$`)
	replaceRe    = regexp.MustCompile(`(?i)^Replace\s*\(\s*(.+)\s*\)$`)
)

// foldVB reduces a VBScript string expression to the constant it evaluates to.
//
// Handles the four transforms the corpus and the real gap items actually use: `&` concatenation,
// Chr()/ChrW(), StrReverse(), and Replace(x, sentinel, ""). Returns ok=false the moment any operand
// is not constant -- a partially folded ProgID is worse than none, because it would gate on a
// prefix and quietly widen the sink.
func foldVB(expr string) (string, bool) {
	parts, ok := splitTopLevel(expr, '&')
	if !ok {
		return "", false
	}
	var b strings.Builder
	for _, p := range parts {
		s, ok := foldOne(strings.TrimSpace(p))
		if !ok {
			return "", false
		}
		b.WriteString(s)
	}
	return b.String(), true
}

func foldOne(t string) (string, bool) {
	if t == "" {
		return "", false
	}
	if t[0] == '"' {
		return unquoteVB(t)
	}
	if m := chrRe.FindStringSubmatch(t); m != nil {
		n, err := parseVBInt(m[1])
		if err != nil || n < 0 || n > 0x10FFFF {
			return "", false
		}
		return string(rune(n)), true
	}
	if m := strReverseRe.FindStringSubmatch(t); m != nil {
		inner, ok := foldVB(m[1])
		if !ok {
			return "", false
		}
		r := []rune(inner)
		for i, j := 0, len(r)-1; i < j; i, j = i+1, j-1 {
			r[i], r[j] = r[j], r[i]
		}
		return string(r), true
	}
	if m := replaceRe.FindStringSubmatch(t); m != nil {
		args, ok := splitTopLevel(m[1], ',')
		if !ok || len(args) < 3 {
			return "", false
		}
		src, ok1 := foldVB(args[0])
		old, ok2 := foldVB(args[1])
		new_, ok3 := foldVB(args[2])
		if !ok1 || !ok2 || !ok3 || old == "" {
			return "", false
		}
		return strings.ReplaceAll(src, old, new_), true
	}
	return "", false
}

func parseVBInt(s string) (int, error) {
	if len(s) > 2 && (s[0] == '&') && (s[1] == 'H' || s[1] == 'h') {
		n, err := strconv.ParseInt(s[2:], 16, 32)
		return int(n), err
	}
	n, err := strconv.Atoi(s)
	return n, err
}

// unquoteVB reads one VBScript string literal. A quote inside a literal is written "" -- there is
// no backslash escape in VBScript, and treating one as an escape is how a scanner walks off the end
// of the literal and swallows the rest of the statement.
func unquoteVB(t string) (string, bool) {
	if len(t) < 2 || t[0] != '"' {
		return "", false
	}
	var b strings.Builder
	for i := 1; i < len(t); i++ {
		if t[i] != '"' {
			b.WriteByte(t[i])
			continue
		}
		if i+1 < len(t) && t[i+1] == '"' {
			b.WriteByte('"')
			i++
			continue
		}
		// Closing quote. Anything after it means this was not a single literal.
		return b.String(), i == len(t)-1
	}
	return "", false
}

// splitTopLevel splits on `sep` outside string literals and outside parentheses. Splitting a
// VBScript expression with strings.Split would cut inside `"a & b"` and inside a nested call's
// argument list, both of which appear in real shells.
func splitTopLevel(s string, sep byte) ([]string, bool) {
	var out []string
	var cur strings.Builder
	depth, inStr := 0, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case inStr:
			cur.WriteByte(c)
			if c == '"' {
				if i+1 < len(s) && s[i+1] == '"' {
					cur.WriteByte('"')
					i++
				} else {
					inStr = false
				}
			}
		case c == '"':
			inStr = true
			cur.WriteByte(c)
		case c == '(':
			depth++
			cur.WriteByte(c)
		case c == ')':
			depth--
			if depth < 0 {
				return nil, false
			}
			cur.WriteByte(c)
		case c == sep && depth == 0:
			out = append(out, cur.String())
			cur.Reset()
		default:
			cur.WriteByte(c)
		}
	}
	if inStr || depth != 0 {
		return nil, false
	}
	out = append(out, cur.String())
	return out, true
}

// comObjects maps each variable holding a CreateObject result to its FOLDED ProgID, lowercased.
//
// File-scoped on purpose. VBScript has routine scope for variables, but a shell's COM handle is
// almost always assigned once at page level and used below; scoping this to the routine would lose
// the binding for the common case while protecting against a collision the corpus does not contain.
// The cost of the choice is a same-named variable in two routines sharing a ProgID, which widens
// the gate slightly -- and the gate is only ever a NARROWING of today's file-wide literal test, so
// the direction is safe.
func comObjects(stmts []string) map[string]string {
	out := map[string]string{}
	for _, stmt := range stmts {
		if m := createObjRe.FindStringSubmatch(stmt); m != nil {
			if prog, ok := foldVB(m[2]); ok {
				out[strings.ToLower(m[1])] = strings.ToLower(prog)
			}
			continue
		}
		// C# / ASP.NET: `LosFormatter lf = new LosFormatter();` binds a receiver to a TYPE exactly
		// as CreateObject binds one to a ProgID, so the same receiver gate serves both. The type is
		// recorded fully qualified-or-not as written; objectIs matches on substring, so
		// `System.Web.UI.LosFormatter` and `LosFormatter` both satisfy a want of "losformatter".
		if m := newObjRe.FindStringSubmatch(stmt); m != nil {
			out[strings.ToLower(m[1])] = strings.ToLower(m[2])
		}
	}
	return out
}

// objectIs reports whether the receiver variable holds a ProgID containing `want`.
//
// Substring rather than equality because a ProgID carries an optional version suffix --
// `MSScriptControl.ScriptControl` and `MSScriptControl.ScriptControl.1` are the same object, and
// the accepted gap item ea52103d78c7667a uses the `.1` form.
func objectIs(objects map[string]string, recv, want string) bool {
	prog, ok := objects[strings.ToLower(recv)]
	return ok && strings.Contains(prog, want)
}
