// Package perlpytaint is a source-to-sink taint pass for Perl and Python that supplies
// CONFIRMED-BAND evidence: a request value demonstrably reaching an execution sink in the same file.
//
// WHY THIS EXISTS, AND WHY IT DOES NOT REPLACE THE RULES.
// The shipped Perl/Python YARA rules fire on `(any sink) AND (any source)` anywhere in the file.
// Measured (docs/measurements/2026-08-18-perl-python-taint), that co-occurrence produces 14 of the
// 20 benign false positives, and inspection shows why: django's defaulttags.py has `eval(` at line
// 326 and `request.GET` at line 1294; the stdlib's server.py has `subprocess.Popen(` at line 14 and
// `QUERY_STRING` at line 1134. Sink and source are unrelated code that happens to share a file.
//
// Taint fixes that -- but prototyped against the corpus it reaches 9 of 24 real samples against the
// co-occurrence rules' 21, because real shells route request data through parameter-parsing
// subroutines (`&read_param()` filling `%param`, `sub ReadParse` filling `%in`) that a parser-free
// pass cannot follow without tainting so broadly that the precision it exists for is gone. So this
// is an ESCALATOR, not a replacement: the rules keep the recall at `likely`, and a proven flow is
// what earns `confirmed`. That band is currently empty on these languages -- 2 of 24 real samples
// and 0 of 1,008 synthetic reach >=85 -- and this signal carries 1,104 synthetic detections at
// 5 false positives in 5,592 benign files.
//
// PRIOR ART. WTA (Applied Sciences 11(16):7763, 2021): mark externally imported taint sources,
// propagate, and decide at the sink whether a dangerous function references a tainted variable.
// WTA is interprocedural over ZendVM Oplines. Neither Perl nor Python has a pure-Go parser and
// tree-sitter would mean adding cgo to a binary that ships self-contained, so this is deliberately
// the intraprocedural, flow-insensitive approximation -- and it is scoped to a band where being
// conservative is the correct failure mode.
//
// WHAT IT IS NOT. It never executes anything. It has no aliasing, no control flow, no
// interprocedural summary, and no notion of sanitisation: a flow that passes through a validator is
// still reported, because recognising validators is a separate problem with its own evidence bar.
package perlpytaint

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

const (
	// Files beyond this are not analysed. The rule engine already scans them; this pass is a
	// per-file O(lines x names) fixpoint and attacker-controlled input should not choose its cost.
	maxInput = 2 << 20
	// The fixpoint converges in far fewer rounds in practice; this only bounds the pathological case.
	maxRounds = 8
	// Confirmed band. The whole purpose of the pass is to earn this score, so it is not a parameter.
	score = 85
)

// Finding is one proven source-to-sink flow. Converted to a finding.Finding by the diskprobe
// wiring, mirroring how phptaint.Finding is handled.
type Finding struct {
	Score    int
	Family   string
	Rule     string // full knowledge-ref, e.g. "perlpytaint:sink-on-request"
	Evidence string
}

// An expression that introduces attacker-controlled data. Kept to CGI/HTTP meta-variables and
// explicit request accessors: bare %ENV / os.environ access is ubiquitous in benign code (reading
// PATH or HOME) and was the source of 98 stdlib false positives when the YARA rules were first
// written.
var framedSource = regexp.MustCompile(
	`\$ENV\s*\{\s*['"]?(?:QUERY_STRING|REQUEST_METHOD|CONTENT_LENGTH|CONTENT_TYPE|HTTP_\w+` +
		`|PATH_INFO|PATH_TRANSLATED|REMOTE_\w+|AUTH_TYPE|SCRIPT_NAME)` +
		`|\bparam\s*\(|\bReadParse\b|\bparse_parameters\s*\(` +
		`|FieldStorage\s*\(|\.getvalue\s*\(` +
		`|request\.(?:args|form|values|data|cookies|GET|POST|body|FILES)` +
		`|environ\s*(?:\[|\.get\s*\()\s*['"](?:QUERY_STRING|HTTP_|REQUEST_METHOD|PATH_INFO` +
		`|REMOTE_|CONTENT_)` +
		`|\bwsgi\.input\b`)

// stdinSource is the request BODY channel -- RFC 3875 section 4.2, "reading the 'standard input'
// file descriptor or file handle", bounded by CONTENT_LENGTH.
//
// IT COUNTS ONLY IN A FILE THAT IS ALREADY FRAMED AS CGI, and that condition is the whole reason it
// is a separate pattern. `<STDIN>` is a POST body in a CGI script and an interactive prompt in a
// command-line tool, and nothing in the line distinguishes them. Treating it as a source
// unconditionally is a defect this pass shipped: `webmin/bin/language-manager`, a 2,282-line
// maintainer utility, produces three CONFIRMED-band findings at score 85 off
// `chomp(my $a = <STDIN>);` -- a y/n prompt.
//
// MEASURED, both directions, before the condition was added:
//   * recall cost ZERO -- of the 24 real samples, NONE has a STDIN source without CGI framing.
//   * precision gain 32 files -- 20 of 1,552 benign Perl and 12 of 4,039 benign Python carry a
//     bare STDIN source with no framing, every one of them the webmin shape.
var stdinSource = regexp.MustCompile(
	`<\s*STDIN\s*>|\b(?:read|sysread)\s*\(\s*STDIN\s*,|\bsys\.stdin\s*\.\s*(?:read|buffer)\b`)

// perlBodyRead captures the OUT PARAMETER of a Perl body read, which is why the channel was
// invisible: `sysread(STDIN,$query,$ENV{'CONTENT_LENGTH'})` assigns through its SECOND argument, so
// there is no `$x =` on the line for perlAssign to match and the taint never enters the variable.
// The third argument is itself a recognised source and it made no difference -- the value it
// tainted was the length, not the body.
//
// Measured on the real corpus: two of the 24 samples produce no finding at all for exactly this
// reason, `Perl_Web_Shell_by_RST-GHC.pl` and `devilzShell.cgi`, both feeding a hand-rolled
// parameter parser the pass already knows how to follow.
var perlBodyRead = regexp.MustCompile(`\b(?:read|sysread)\s*\(\s*STDIN\s*,\s*(?:my\s+)?[\$\\]?(\w+)`)

// sources reports which source predicate applies to a file, resolved once per Analyze call.
type sources struct{ framed bool }

// match reports whether `s` introduces attacker-controlled data, given the file's framing.
func (s sources) match(text string) bool {
	if framedSource.MatchString(text) {
		return true
	}
	return s.framed && stdinSource.MatchString(text)
}

// Go's regexp is RE2, which has no negative lookahead, so `=(?!=|~)` cannot be expressed in the
// pattern. The `=` is captured plainly and comparison/binding operators are rejected in code by
// isAssignment -- see the benchmark harness README for the same RE2-vs-PCRE constraint biting the
// Ported from prior art.
var (
	// Perl scalar/array/hash assignment, with optional my/our/local.
	perlAssign = regexp.MustCompile(`(?:\bmy\s+|\bour\s+|\blocal\s+)?([\$@%][A-Za-z_]\w*)\s*=(.*)`)
	// Perl list unpacking: ($name, $value) = split(/=/, $pair);
	perlListAssign = regexp.MustCompile(
		`\(\s*((?:[\$@%][A-Za-z_]\w*\s*,\s*)*[\$@%][A-Za-z_]\w*)\s*\)\s*=(.*)`)
	// Python simple assignment.
	pyAssign = regexp.MustCompile(`^\s*([A-Za-z_]\w*)\s*=(.*)`)

	// Assignment to a hash/array ELEMENT taints the container: $param{$name} = $value (Perl),
	// results[key] = value (Python). This is how every CGI parameter parser publishes what it
	// parsed, so without it the parsed request data never escapes the parser.
	perlElemAssign = regexp.MustCompile(`[\$@]([A-Za-z_]\w*)\s*[\{\[][^\}\]]*[\}\]]\s*=(.*)`)
	pyElemAssign   = regexp.MustCompile(`^\s*([A-Za-z_]\w*)\s*\[[^\]]*\]\s*=(.*)`)

	// Iteration is assignment. `foreach $pair (@pairs)` binds each element of a tainted list to
	// $pair; `for entry in items:` does the same. Without this the taint dies at the loop header,
	// which is exactly where the standard CGI parameter-parsing chain passes through.
	perlForeach = regexp.MustCompile(`\bfor(?:each)?\s+(?:my\s+)?\$([A-Za-z_]\w*)\s*\(([^)]*)\)`)
	pyForIn     = regexp.MustCompile(`\bfor\s+([A-Za-z_]\w*)\s+in\s+([^:]*):`)

	// A bare identifier, with any Perl sigil stripped. Word-bounded so $cmd does not taint $cmdline.
	nameRe = regexp.MustCompile(`[\$@%]?\b([A-Za-z_]\w*)\b`)
)

// sink pairs a reported name with a pattern capturing the ARGUMENT text, because the argument is
// what has to be tainted. A sink whose argument is a literal is not a finding.
type sink struct {
	name string
	re   *regexp.Regexp
	arg  int // capture group holding the argument text
}

var perlSinks = []sink{
	{"system", regexp.MustCompile(`(?i)\bsystem\s*\(([^)]*)\)`), 1},
	{"exec", regexp.MustCompile(`(?i)\bexec\s*[\(\s]([^)\n;]*)`), 1},
	{"backtick", regexp.MustCompile("`([^`\n]*)`"), 1},
	{"qx", regexp.MustCompile(`qx[/{(#|!~]([^\n]*)`), 1},
	{"piped-open", regexp.MustCompile(`(?i)open\s*\([^,]*,\s*["']([^"']*\|[^"']*)["']`), 1},
	{"string-eval", regexp.MustCompile(`(?i)\beval\s*["'{]([^"'}\n]*)`), 1},
}

var pySinks = []sink{
	{"os.system", regexp.MustCompile(`os\.system\s*\(([^)]*)\)`), 1},
	{"os.popen", regexp.MustCompile(`os\.popen\d?\s*\(([^)]*)\)`), 1},
	{"subprocess", regexp.MustCompile(`subprocess\.(?:Popen|call|run|check_output|check_call)\s*\(([^)]*)\)`), 1},
	// The builtin only: a leading "." makes it a METHOD call. django's defaulttags.py calls
	// `condition.eval(context)` on a template object, which the bare pattern read as eval() and
	// promoted to a confirmed webshell. RE2 has no lookbehind, so the preceding character is
	// matched explicitly and the argument lands in group 2.
	{"eval/exec", regexp.MustCompile(`(^|[^.\w])(?:eval|exec)\s*\(([^)]*)\)`), 2},
}

// isAssignment rejects the operators that an `=`-anchored pattern also matches: `==` and `>=`/`<=`
// comparisons, and Perl's `=~` binding. Without this every equality test looks like an assignment
// and taint spreads through conditions.
func isAssignment(rhs string) bool {
	return !(len(rhs) > 0 && (rhs[0] == '=' || rhs[0] == '~'))
}

func namesIn(s string) map[string]bool {
	out := map[string]bool{}
	for _, m := range nameRe.FindAllStringSubmatch(s, -1) {
		out[m[1]] = true
	}
	return out
}

func intersects(a map[string]bool, b map[string]bool) bool {
	for k := range a {
		if b[k] {
			return true
		}
	}
	return false
}

// assignment is one left-hand name set and the right-hand expression text.
type assignment struct {
	lhs []string
	rhs string
}

// assignmentsIn returns every assignment form recognised on one line.
//
// Perl list unpacking is handled explicitly because it is load-bearing rather than exotic: the
// standard CGI parameter-parsing idiom is `($name, $value) = split(/=/, $pair);`, and without it
// $value never becomes tainted and the hash it fills stays clean.
func assignmentsIn(line, lang string, src sources) []assignment {
	var out []assignment
	if lang == "python" {
		if m := pyForIn.FindStringSubmatch(line); m != nil {
			out = append(out, assignment{lhs: []string{m[1]}, rhs: m[2]})
		}
		if m := pyElemAssign.FindStringSubmatch(line); m != nil && isAssignment(m[2]) {
			out = append(out, assignment{lhs: []string{m[1]}, rhs: m[2]})
		}
		if m := pyAssign.FindStringSubmatch(line); m != nil && isAssignment(m[2]) {
			if n := nameRe.FindStringSubmatch(m[1]); n != nil {
				out = append(out, assignment{lhs: []string{n[1]}, rhs: m[2]})
			}
		}
		return out
	}
	// The body read, before the assignment forms: it is an assignment through an OUT PARAMETER, so
	// none of them can see it. Only in a file already framed as CGI -- see stdinSource.
	if src.framed {
		if m := perlBodyRead.FindStringSubmatch(line); m != nil {
			// rhs is the matched call itself, which stdinSource matches, so the edge is `sourced`
			// by the same predicate as every other source rather than by a special case.
			out = append(out, assignment{lhs: []string{m[1]}, rhs: m[0]})
		}
	}
	if m := perlListAssign.FindStringSubmatch(line); m != nil && isAssignment(m[2]) {
		var names []string
		for _, n := range nameRe.FindAllStringSubmatch(m[1], -1) {
			names = append(names, n[1])
		}
		if len(names) > 0 {
			out = append(out, assignment{lhs: names, rhs: m[2]})
		}
	}
	if m := perlForeach.FindStringSubmatch(line); m != nil {
		out = append(out, assignment{lhs: []string{m[1]}, rhs: m[2]})
	}
	if m := perlElemAssign.FindStringSubmatch(line); m != nil && isAssignment(m[2]) {
		out = append(out, assignment{lhs: []string{m[1]}, rhs: m[2]})
	}
	if m := perlAssign.FindStringSubmatch(line); m != nil && isAssignment(m[2]) {
		if n := nameRe.FindStringSubmatch(m[1]); n != nil {
			out = append(out, assignment{lhs: []string{n[1]}, rhs: m[2]})
		}
	}
	return out
}

// taintedNames runs the forward fixpoint. Name-based, so a tainted %FORM also taints $FORM{'path'} --
// which list.pl's shape requires, and which is the correct direction to approximate in: a hash
// filled from the request has request data in all of it.
func taintedNames(lines []string, lang string, src sources) map[string]bool {
	// Parse once. The fixpoint below runs up to maxRounds times, and re-running every regex and
	// re-tokenising every right-hand side on each round cost 220-670 ms per file on the real 20-57 KB
	// shells -- these pack a whole CGI parser onto a single line, so namesIn was repeatedly walking
	// ~10 KB strings. Precomputing drops that to one pass.
	type edge struct {
		lhs     []string
		names   map[string]bool
		sourced bool
	}
	var edges []edge
	for _, line := range lines {
		for _, a := range assignmentsIn(line, lang, src) {
			edges = append(edges, edge{
				lhs:     a.lhs,
				names:   namesIn(a.rhs),
				sourced: src.match(a.rhs),
			})
		}
	}

	tainted := map[string]bool{}
	for round := 0; round < maxRounds; round++ {
		grew := false
		for _, e := range edges {
			if !e.sourced && !intersects(e.names, tainted) {
				continue
			}
			for _, n := range e.lhs {
				if !tainted[n] {
					tainted[n] = true
					grew = true
				}
			}
		}
		if !grew {
			break
		}
	}
	return tainted
}

// isDefinitionSite reports whether the match at off sits on a line that DECLARES a function, so a
// class defining `def eval(...)` or a package defining `sub system { ... }` is not mistaken for a
// call to the sink it shares a name with. RE2 has no lookbehind, hence the positional check.
func isDefinitionSite(text string, off int) bool {
	start := strings.LastIndexByte(text[:off], '\n') + 1
	// The sink patterns capture the character BEFORE the name, so the text up to the match ends at
	// the declaring keyword rather than after it -- `    def` for `    def eval(...)`, with no
	// trailing space. Compare the last token rather than a prefix.
	head := strings.TrimRight(text[start:off], " \t")
	i := strings.LastIndexAny(head, " \t")
	last := head
	if i >= 0 {
		last = head[i+1:]
	}
	return last == "def" || last == "sub"
}

// Analyze reports one finding per distinct sink kind whose argument carries request-derived data.
//
// One finding per sink KIND rather than per occurrence: three `system($c)` calls in one shell are
// one fact about that file, and emitting three would triple-count it in any per-file tally.
func Analyze(src []byte, lang string) []Finding {
	var sinks []sink
	switch lang {
	case "perl", "cgi":
		sinks = perlSinks
	case "python":
		sinks = pySinks
	default:
		return nil
	}
	if len(src) == 0 || len(src) > maxInput {
		return nil
	}
	text := string(src)
	// Framing is resolved ONCE per file and then governs every source decision below: whether
	// this file is a CGI program at all is a property of the file, not of the line read.
	srcs := sources{framed: framedSource.MatchString(text)}
	if !srcs.match(text) {
		return nil // no request source anywhere: nothing can be tainted
	}

	tainted := taintedNames(splitLines(text), lang, srcs)

	hit := map[string]string{}
	for _, s := range sinks {
		for _, loc := range s.re.FindAllStringSubmatchIndex(text, -1) {
			if 2*s.arg+1 >= len(loc) || loc[2*s.arg] < 0 {
				continue
			}
			if isDefinitionSite(text, loc[0]) {
				continue // `def eval(self, context):` declares a method, it does not call one
			}
			arg := text[loc[2*s.arg]:loc[2*s.arg+1]]
			if srcs.match(arg) || intersects(namesIn(arg), tainted) {
				if _, seen := hit[s.name]; !seen {
					hit[s.name] = trim(arg, 80)
				}
				break
			}
		}
	}
	if len(hit) == 0 {
		return nil
	}

	names := make([]string, 0, len(hit))
	for k := range hit {
		names = append(names, k)
	}
	sort.Strings(names)

	out := make([]Finding, 0, len(names))
	for _, n := range names {
		out = append(out, Finding{
			Score:    score,
			Family:   "GenericCmdExec",
			Rule:     "perlpytaint:sink-on-request",
			Evidence: fmt.Sprintf("request-derived data reaches %s(%s)", n, hit[n]),
		})
	}
	return out
}

func splitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}

func trim(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
