package deobfuscate

// Constant folding — a static pre-pass that collapses constant string expressions to the literal
// they evaluate to, so a literal-matching rule engine can see a sink name the author split up.
//
// WHY. Measured on the 1,008-sample generated technique matrices
// (docs/measurements/2026-08-18-perl-python-detection-litreview), ShellSight scores 0.000 on the
// `concat` and `reverse` obfuscation cells in BOTH Perl and Python, and 0.000 on Python's `chr`
// cell. The cause is not subtle: the whole Perl/Python capability is one literal source->sink YARA
// rule per language, so `'ex' . 'ec'` simply is not the string `exec` and nothing matches.
//
// PRIOR ART. SAFE-Deobs (Herrera, "Optimizing Away JavaScript Obfuscation", IEEE SCAM 2020) applies
// compiler-theory static analyses — constant folding and propagation, string decoding — as a
// pre-pass before analysis. The JavaScript-malware literature measures string splitting and keyword
// substitution in 47% of malicious samples, so this is the majority obfuscation technique rather
// than an exotic one. This file implements the folding subset that the measurement showed we need.
//
// WHAT THIS IS NOT. It is not an evaluator and it never executes anything. It rewrites only
// expressions whose operands are ALL literals, which is what makes it safe: an expression touching
// a variable is left exactly as written, because folding across one would fabricate a string that
// never exists at runtime and invent a detection out of nothing.
//
// Perl's `reverse` is list-reversing in list context and string-reversing in scalar context. This
// pass takes the scalar reading for a single literal argument, because the result is a CANDIDATE
// VIEW offered to the scanner, never an assertion about program semantics.

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"regexp"
	"strconv"
)

const (
	// A fold can expose a new fold (reverse of a concatenation needs two), so the pass iterates.
	// Bounded because input is attacker-controlled and each pass is a full-buffer rewrite.
	maxFoldPasses = 8
	// Beyond this a file is not worth folding; the rule engine already scans the raw bytes.
	maxFoldInput = 2 << 20
)

// A single-quoted or double-quoted literal, honouring backslash escapes so `'don\'t'` is one token.
const litPattern = `'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*"`

var (
	// Two adjacent literals joined by a concatenation operator: `.` (Perl/PHP) or `+` (Python).
	// BOTH sides must be literals -- that requirement is the safety property of this whole file.
	reConcatPair = regexp.MustCompile(`(` + litPattern + `)\s*[.+]\s*(` + litPattern + `)`)

	// Perl: reverse('...') / scalar reverse("...").
	rePerlReverse = regexp.MustCompile(`(?i)(?:scalar\s+)?\breverse\s*\(\s*(` + litPattern + `)\s*\)`)
	// Python: '...'[::-1]
	rePySliceReverse = regexp.MustCompile(`(` + litPattern + `)\s*\[\s*::\s*-\s*1\s*\]`)

	// A chr() run separated by `.` OR `+`. The package's existing reChrRun accepts only `.`, which
	// is why Perl's chr cell measured 1.000 and Python's measured 0.000 -- Python concatenates
	// with `+`. This one folds the run into a quoted literal so it can then compose with an
	// adjacent literal via reConcatPair.
	// The separator is matched only BETWEEN chr calls, never after the last one. A trailing
	// `(?:[.+]\s*)?` swallows the operator joining the run to a following literal, so
	// `chr(115).chr(121).chr(115) . 'tem'` folded to `'sys''tem'` -- two literals with nothing
	// between them, which reConcatPair then cannot join.
	reChrRunAny = regexp.MustCompile(
		`(?i)chr\s*\(\s*(?:0x[0-9a-f]{1,2}|\d{1,3})\s*\)` +
			`(?:\s*[.+]\s*chr\s*\(\s*(?:0x[0-9a-f]{1,2}|\d{1,3})\s*\))+`)

	// Decoder spellings of a constant name.
	//   python: __import__('base64').b64decode('Y2FsbA==').decode() / base64.b64decode(...)
	//   perl:   decode_base64("Y2FsbA==")
	// The trailing .decode()/.encode() is optional so both the bytes and str spellings fold.
	reB64Decode = regexp.MustCompile(
		`(?i)(?:__import__\s*\(\s*['"]base64['"]\s*\)|\bbase64)\s*\.\s*b64decode\s*\(\s*(` +
			litPattern + `)\s*\)(?:\s*\.\s*decode\s*\(\s*\))?` +
			`|\bdecode_base64\s*\(\s*(` + litPattern + `)\s*\)`)
	//   python: bytes.fromhex('63616c6c').decode()
	//   perl:   pack("H*", "63616c6c")
	reHexDecode = regexp.MustCompile(
		`(?i)\bbytes\s*\.\s*fromhex\s*\(\s*(` + litPattern + `)\s*\)` +
			`(?:\s*\.\s*decode\s*\(\s*\))?` +
			`|\bpack\s*\(\s*['"]H\*['"]\s*,\s*(` + litPattern + `)\s*\)`)

	// Cheap presence check: skip the whole pass unless there is something to fold OR to propagate.
	// The propagation clauses matter -- `my $fn = 'system'; $fn($CMD);` contains nothing foldable at
	// all, so a folding-only marker returned early and the propagation pass never ran, which is why
	// the first end-to-end measurement moved exactly zero cells.
	// The decoder clauses are load-bearing: without them a file whose ONLY obfuscation is
	// `fn = bytes.fromhex('63616c6c').decode()` returns early and never folds. These samples
	// happen to also carry `getattr(`, so the omission would have hidden behind that -- which is
	// exactly the kind of accidental pass this project keeps finding.
	reFoldMarker = regexp.MustCompile(`(?i)` + `(` + litPattern + `)\s*[.+]|` +
		`\breverse\s*\(|\[\s*::\s*-\s*1\s*\]|chr\s*\(|` +
		`\bb64decode\s*\(|\bdecode_base64\s*\(|\bfromhex\s*\(|\bpack\s*\(|` +
		`getattr\s*\(|=\s*(` + litPattern + `)`)

	// Sink names revealed by folding. These are BARE NAMES, not call syntax, because that is the
	// point of the technique: the author builds the name as a string and dispatches on it
	// (`eval "$fn(...)"`, `getattr(os, fn)(...)`). Gating on `exec(` the way the escape normalizer
	// does would miss every sample in the matrix this pass exists to catch.
	foldSinkNames = [][]byte{
		[]byte("exec"), []byte("system"), []byte("popen"), []byte("eval"),
		[]byte("subprocess"), []byte("passthru"), []byte("shell_exec"),
		[]byte("proc_open"), []byte("assert"), []byte("check_output"),
		[]byte("getruntime"), []byte("processbuilder"),
	}
)

// quote wraps a folded value as a single-quoted literal so later passes can treat it as one token.
// Backslashes and single quotes are escaped, keeping the literal well-formed under litPattern.
func quote(v []byte) []byte {
	out := make([]byte, 0, len(v)+2)
	out = append(out, '\'')
	for _, c := range v {
		if c == '\\' || c == '\'' {
			out = append(out, '\\')
		}
		out = append(out, c)
	}
	return append(out, '\'')
}

// unquote returns a literal token's contents, resolving backslash escapes for the two characters
// quote() introduces. Other escapes are left as written -- this is a view for matching, and
// over-interpreting them would change bytes the scanner may want to see.
func unquote(tok []byte) []byte {
	if len(tok) < 2 {
		return nil
	}
	body := tok[1 : len(tok)-1]
	out := make([]byte, 0, len(body))
	for i := 0; i < len(body); i++ {
		if body[i] == '\\' && i+1 < len(body) && (body[i+1] == '\\' || body[i+1] == '\'' || body[i+1] == '"') {
			i++
		}
		out = append(out, body[i])
	}
	return out
}

func reverseBytes(b []byte) []byte {
	out := make([]byte, len(b))
	for i, c := range b {
		out[len(b)-1-i] = c
	}
	return out
}

// foldChrRuns collapses a run of chr(N) calls into one quoted literal.
func foldChrRuns(src []byte) []byte {
	return reChrRunAny.ReplaceAllFunc(src, func(run []byte) []byte {
		var buf []byte
		for _, m := range reChrCall.FindAllSubmatch(run, -1) {
			arg := string(m[1])
			base, digits := 10, arg
			if len(arg) > 2 && (arg[1] == 'x' || arg[1] == 'X') {
				base, digits = 16, arg[2:]
			}
			n, err := strconv.ParseUint(digits, base, 16)
			if err != nil || n > 255 {
				return run // not a clean run; leave it exactly as found
			}
			buf = append(buf, byte(n))
		}
		if len(buf) == 0 {
			return run
		}
		return quote(buf)
	})
}

// foldConcat joins adjacent literal pairs. One call folds one level; Fold iterates.
func foldConcat(src []byte) []byte {
	return reConcatPair.ReplaceAllFunc(src, func(m []byte) []byte {
		p := reConcatPair.FindSubmatch(m)
		if p == nil {
			return m
		}
		return quote(append(unquote(p[1]), unquote(p[2])...))
	})
}

// firstGroup returns the first NON-EMPTY capture. Each decoder regex is an alternation of two
// spellings -- the Python one and the Perl one -- and each alternative carries its own capture
// group, so a Perl match populates group 2 and leaves group 1 empty. Reading p[1] unconditionally
// silently dropped every Perl decode_base64/pack("H*") fold.
func firstGroup(p [][]byte) []byte {
	for _, g := range p[1:] {
		if len(g) > 0 {
			return g
		}
	}
	return nil
}

// foldDecoders resolves the two ENCODED spellings of a constant sink name.
//
// Folding handled chr / concat / reverse and nothing else, so measured 2026-09-05 on the generated
// matrices the `base64` and `hex` obfuscation cells scored zero across EVERY dispatch in both
// languages -- 12 python cells and the perl equivalents -- while concat and chr passed. The name is
// still a compile-time constant in those cells; it is simply spelled through a decoder call.
//
// Safety is the same property the rest of this file rests on: the argument must be a LITERAL. A
// decoder call on a variable is left exactly as written, because resolving it would fabricate a
// string that need not exist at runtime.
func foldDecoders(src []byte) []byte {
	out := reB64Decode.ReplaceAllFunc(src, func(m []byte) []byte {
		p := reB64Decode.FindSubmatch(m)
		if p == nil {
			return m
		}
		dec, err := base64.StdEncoding.DecodeString(string(unquote(firstGroup(p))))
		if err != nil || len(dec) == 0 || !printableASCII(dec) {
			return m
		}
		return quote(dec)
	})
	return reHexDecode.ReplaceAllFunc(out, func(m []byte) []byte {
		p := reHexDecode.FindSubmatch(m)
		if p == nil {
			return m
		}
		dec, err := hex.DecodeString(string(unquote(firstGroup(p))))
		if err != nil || len(dec) == 0 || !printableASCII(dec) {
			return m
		}
		return quote(dec)
	})
}

// printableASCII keeps a decode from turning a benign binary blob into a quoted literal full of
// control bytes. A sink NAME is printable by construction, and this pass exists to reveal names.
func printableASCII(b []byte) bool {
	for _, c := range b {
		if c < 0x20 || c > 0x7E {
			return false
		}
	}
	return true
}

// foldReverse resolves reversal of a literal in both languages' spellings.
func foldReverse(src []byte) []byte {
	out := rePerlReverse.ReplaceAllFunc(src, func(m []byte) []byte {
		p := rePerlReverse.FindSubmatch(m)
		if p == nil {
			return m
		}
		return quote(reverseBytes(unquote(p[1])))
	})
	return rePySliceReverse.ReplaceAllFunc(out, func(m []byte) []byte {
		p := rePySliceReverse.FindSubmatch(m)
		if p == nil {
			return m
		}
		return quote(reverseBytes(unquote(p[1])))
	})
}

// Fold applies the folding passes until the output stops changing.
//
// Returns input unchanged when there is nothing to fold. That identity property is load-bearing:
// Run gates the emitted layer on folding having REVEALED something, and a folder that rewrote every
// benign file would defeat that gate and double the mirror-scan surface for no detection gain.
func Fold(src []byte) []byte {
	if len(src) == 0 || len(src) > maxFoldInput || !reFoldMarker.Match(src) {
		return src
	}
	cur := src
	for i := 0; i < maxFoldPasses; i++ {
		next := foldReverse(foldConcat(foldChrRuns(foldDecoders(cur))))
		next = resolveGetattr(propagate(next, constants(next)))
		if bytes.Equal(next, cur) {
			break
		}
		cur = next
	}
	return cur
}

// Dynamic-dispatch constructs whose DISAPPEARANCE across a fold is itself a reveal.
var foldDispatchMarkers = [][]byte{
	[]byte("getattr("),
	[]byte("__import__("),
}

// revealsFoldedSink reports whether folding exposed a sink NAME that was not already present, or
// resolved a dynamic-dispatch construct away.
//
// "Newly revealed" is the whole gate: benign code concatenates constantly, and a file that already
// contained the name gains nothing from a second copy of it.
//
// THE NAME TEST ALONE IS NOT ENOUGH, and the miss it caused was total. In
//
//	fn = 'ca' + 'll'
//	getattr(__import__('subprocess'), fn)(cmd, shell=True)
//
// folding correctly produces `subprocess.call(cmd, shell=True)` -- but `subprocess` is present
// BEFORE as well, inside `__import__('subprocess')`, so no token was newly revealed and the layer
// was dropped. The technique hides the METHOD name; this gate was only looking for the module.
// Measured 2026-09-05: all 15 obfuscated python subprocess cells scored 0 while `os-system` scored
// 1.00 -- and the folding itself had been working correctly the whole time.
//
// Adding the method names to foldSinkNames would not fix it and would be actively harmful: `call`
// and `run` are among the most common identifiers in any codebase. What distinguishes the technique
// is the CONSTRUCT -- a getattr/__import__ dispatch that folding resolved away. That is what this
// pass's own header calls the technique ("building the name and dispatching on it ... is the
// technique"), so gate on it directly. A benign file that merely concatenates has no such marker.
func revealsFoldedSink(before, after []byte) bool {
	lb, la := bytes.ToLower(before), bytes.ToLower(after)
	for _, tok := range foldSinkNames {
		if bytes.Contains(la, tok) && !bytes.Contains(lb, tok) {
			return true
		}
	}
	for _, m := range foldDispatchMarkers {
		if bytes.Count(la, m) < bytes.Count(lb, m) {
			return true
		}
	}
	return false
}

// --- constant propagation ----------------------------------------------------------------------
//
// Folding alone is inert end to end, which the first measurement showed plainly: it turns
// `'ex' . 'ec'` into `'exec'`, but every sink rule is anchored on a CALL (`system\s*\(`,
// `os.popen\s*\(`) and a bare literal is not a call. Building the name and then dispatching on it
// IS the technique, so the constant has to reach its use site. This mirrors what
// phptaint.ResolvedLayers already does for PHP -- rewrite the dynamic call site to the literal
// sink name so existing literal-anchored rules fire -- rather than inventing a second mechanism.

var (
	// `my $fn = 'literal';` / `$fn = "literal";` (Perl, PHP) and `fn = 'literal'` (Python).
	reConstAssign = regexp.MustCompile(
		`(?m)^[ \t]*(?:my|our|local)?[ \t]*\$?([A-Za-z_]\w*)[ \t]*=[ \t]*(` + litPattern + `)[ \t]*;?[ \t]*$`)
	// Any assignment to a name, literal or not -- used to spot reassignment.
	reAnyAssign = regexp.MustCompile(`(?m)^[ \t]*(?:my|our|local)?[ \t]*\$?([A-Za-z_]\w*)[ \t]*=[^=]`)

	// getattr(__import__('os'), 'popen')  /  getattr(os, 'system')
	reGetattrImport = regexp.MustCompile(
		`getattr\s*\(\s*__import__\s*\(\s*(` + litPattern + `)\s*\)\s*,\s*(` + litPattern + `)\s*\)`)
	reGetattrPlain = regexp.MustCompile(
		`getattr\s*\(\s*([A-Za-z_]\w*)\s*,\s*(` + litPattern + `)\s*\)`)
)

// constants returns name -> value for variables assigned a string literal EXACTLY ONCE.
//
// The single-assignment requirement is the safety property. A variable reassigned from request
// input later is not a constant, and propagating its first value would describe code that never
// runs -- inventing a detection rather than revealing one.
func constants(src []byte) map[string][]byte {
	assigns := map[string]int{}
	for _, m := range reAnyAssign.FindAllSubmatch(src, -1) {
		assigns[string(m[1])]++
	}
	out := map[string][]byte{}
	for _, m := range reConstAssign.FindAllSubmatch(src, -1) {
		name := string(m[1])
		if assigns[name] > 1 {
			continue // reassigned: not a constant
		}
		v := unquote(m[2])
		// A one- or two-character value carries no signal and risks mangling ordinary code.
		if len(v) >= 3 && len(v) <= 128 {
			out[name] = v
		}
	}
	return out
}

// propagate substitutes known constants where they are used as a callee or as getattr's attribute.
// Assignment sites are left intact so the rewrite stays readable and the pass remains idempotent.
func propagate(src []byte, consts map[string][]byte) []byte {
	if len(consts) == 0 {
		return src
	}
	out := src
	for name, val := range consts {
		// Callee position: `$fn(` (Perl/PHP, including inside an interpolated string) and `fn(`
		// (Python). \b keeps `fn` from matching inside `myfn`.
		callee := regexp.MustCompile(`\$?\b` + regexp.QuoteMeta(name) + `\b\s*\(`)
		out = callee.ReplaceAllFunc(out, func(m []byte) []byte {
			return append(append([]byte{}, val...), '(')
		})
		// getattr's attribute argument: getattr(mod, fn) -> getattr(mod, 'popen')
		attr := regexp.MustCompile(`(getattr\s*\([^,()]*(?:\([^()]*\))?[^,()]*,\s*)\b` +
			regexp.QuoteMeta(name) + `\b(\s*\))`)
		out = attr.ReplaceAllFunc(out, func(m []byte) []byte {
			p := attr.FindSubmatch(m)
			if p == nil {
				return m
			}
			return append(append(append([]byte{}, p[1]...), quote(val)...), p[2]...)
		})
	}
	return out
}

// resolveGetattr rewrites the getattr dynamic-dispatch idiom to the equivalent attribute access, so
// `os.popen(` exists literally for the rule engine. Only a literal attribute is resolved; a
// variable one is left as written.
func resolveGetattr(src []byte) []byte {
	out := reGetattrImport.ReplaceAllFunc(src, func(m []byte) []byte {
		p := reGetattrImport.FindSubmatch(m)
		if p == nil {
			return m
		}
		return append(append(unquote(p[1]), '.'), unquote(p[2])...)
	})
	return reGetattrPlain.ReplaceAllFunc(out, func(m []byte) []byte {
		p := reGetattrPlain.FindSubmatch(m)
		if p == nil {
			return m
		}
		return append(append(append([]byte{}, p[1]...), '.'), unquote(p[2])...)
	})
}
