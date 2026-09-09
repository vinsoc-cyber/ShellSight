// Package asptaint is a source-to-sink taint pass for Classic ASP / VBScript -- and, since
// 2026-08-24, for the ASP.NET pages whose statement forms coincide with it -- that supplies
// CONFIRMED-BAND evidence: a request value demonstrably reaching a code-execution sink in the same
// file.
//
// WHAT "COINCIDE" MEANS, because it bounds the claim. JScript's untyped assignment `keng =
// Request.Item["zhe"];` is character-for-character the VBScript form this pass already parses, so
// ASP.NET JScript pages are analysed properly and four of the ASPX kit's eight phase-5 gap items are
// closed by opening the file gate alone. C# is NOT covered: `string command = ...` is a typed
// declaration `assignRe` does not match, so C# pages are analysed and found clean. That is the
// conservative direction for an escalator -- a miss, never a false confirmation -- and the two gap
// items it leaves open are published as residuals with that reason rather than papered over. A C#
// statement model, and a JScript-aware statement splitter for `var x:String = ...` spread across
// lines, are the named next steps; neither is emulated by widening a VBScript pattern.
//
// WHY THIS EXISTS. Measured in phase 5 of the Classic ASP language session, over the whole corpus
// on both operating systems:
//
//	<%Execute(Request("c"))%>                  ->  75   detected
//	<%a=request("leon1942")%><%execute(a)%>    ->   0   missed
//
// The shipped rules require the request accessor to sit syntactically INSIDE the dispatch call. One
// intervening assignment defeats them, and that is not an exotic shape: 33 of this language's 349
// malicious samples take it, across 7 origins, and 28 of those contain no adjacent form anywhere in
// the file. Two of the twelve samples the incumbent caught and we missed are exactly this.
//
// PRIOR ART, and why this method rather than another (see langkit/asp/lit-review.md for the full
// review, which is a precondition of this file existing at all):
//
//   - The published Classic ASP method is adjacency matching. 15seconds' ASP guide ships a findstr
//     signature file whose dispatch lines are `execute *\(? *request` and `eval *\(? *request`. This
//     technique is precisely what that method misses.
//   - The published fix is taint. WTA (Appl. Sci. 2021, 11, 7763) marks the externally imported
//     taint source, propagates through assignment, and decides at the sink. Its own ablation
//     measures what the propagation is worth: recall 0.9645 with the interprocedural module against
//     0.7461 without it, over 1,776 webshells and 6,874 CMS pages. The same paper shows the keyword
//     tool D-Shield scoring such a sample as a normal file, giving as its reason that the payload
//     arrives through a variable.
//   - DataDog/webshell-detector ships the method as a Semgrep `mode: taint` rule with sources,
//     sinks AND sanitizers -- and declares `languages: [php]`. Semgrep supports no VBScript or
//     Classic ASP at any maturity level (semgrep#10389, open). WTA is ZendVM-specific. Fortify SCA
//     does run interprocedural taint on Classic ASP, which proves the analysis is tractable here,
//     but it is commercial and aimed at vulnerabilities in code you own.
//
// So the method is the field's, and no open-source or on-premise webshell detector implements it
// for this language.
//
// WHY IT DOES NOT REPLACE THE RULES. WTA pays for its recall in precision -- 0.9771 against
// D-Shield's 0.9981 on the same corpus -- and this project measured the same direction on Perl and
// Python, where taint alone reached 9 of 24 real samples against the rules' 21. Precision is the
// claim this release makes, so this is an ESCALATOR: the rules keep the recall, and a proven flow
// is what earns `confirmed`.
//
// WHAT IT IS NOT. It never executes anything. It is intraprocedural and flow-insensitive: no
// aliasing, no control flow, no interprocedural summary. VBScript has no pure-Go parser and no
// tree-sitter grammar, and tree-sitter would mean adding cgo to a binary that ships self-contained,
// so this is deliberately the parser-free approximation -- scoped to a band where being
// conservative is the correct failure mode.
//
// SCOPE. Code-execution sinks only. The request-to-file-write half of the phase 5 gap list is NOT
// implemented here: the lit review licenses it only behind a measurement against the 0.053-precision
// result this project already recorded for a request-derived-path discriminator.
package asptaint

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

const (
	// Files beyond this are not analysed. The rule engine already scans them; this pass is a
	// per-file O(statements x names) fixpoint and attacker-controlled input should not choose its
	// cost.
	maxInput = 2 << 20
	// The fixpoint converges in far fewer rounds in practice; this only bounds the pathological case.
	maxRounds = 8
	// Confirmed band. The whole purpose of the pass is to earn this score, so it is not a parameter.
	score = 85
	// The lower tier of the file-drop pass: request content written to a destination that is
	// NOT server-executable. Measured 0.700 precision on real code against tier A's 1.000, so
	// it scores below the alert band while staying above the 40 reporting threshold -- a
	// finding an analyst should see and triage, not one that should read as proven.
	scoreFileWrite = 60
)

// Finding is one proven source-to-sink flow.
type Finding struct {
	Score    int
	Family   string
	Rule     string
	Evidence string
}

// An expression that introduces attacker-controlled data. The ASP intrinsic request accessors and
// nothing else: `Session` and `Application` are server-side stores, and tainting them outright would
// make every page that remembers anything look attacker-controlled. They become tainted only by
// assignment from one of these, which is the session-staged shell's actual shape and is handled by
// the container rule below.
//
// `Request[...]` -- the INDEXER -- is the same property as the `.Item` alternative already listed,
// not a new channel: HttpRequest.Item[String] is declared `public string this[string key] { get; }`
// with `get_Item` as its accessor name, and "Gets the specified object from the QueryString, Form,
// Cookies, or ServerVariables collections" (Microsoft Learn, System.Web.HttpRequest.Item, retrieved
// 2026-08-24). Omitting it meant the canonical C#/JScript spelling of a property we already trusted
// was invisible: two of the ASPX kit's phase-5 gap items read the request through it and nothing
// else, and one of them is the .ashx form `eval(context.Request["Ivan"])`, where the accessor is
// also qualified by a receiver.
// `Headers`, `InputStream` and `Params` are ASP.NET spellings that were missing until 2026-09-05.
// Each is attacker-controlled by definition -- HttpRequest.Headers is the request's own header
// collection, InputStream is the raw body, Params is the union of QueryString/Form/Cookies/
// ServerVariables (Microsoft Learn, System.Web.HttpRequest). Their absence made every generated
// header- and body-channel cell unreachable no matter what the sink side did, because nothing in
// the file counted as a source at all.
var sourceExpr = regexp.MustCompile(`(?i)\bRequest\s*(?:\(|\[|\.\s*(?:Form|QueryString|ServerVariables|Cookies|BinaryRead|Files|Item|TotalBytes|Headers|InputStream|Params)\b)`)

var (
	// Assignment. `Set` is VBScript's object-assignment keyword and binds the same way.
	// The optional leading TYPE is what opens this pass to C# ASP.NET pages. Until 2026-09-05 this
	// pattern required the statement to begin with the identifier, so `string CMD =
	// Request.Form["c"];` did not match and every C# page was analysed and found clean -- 0 of 85
	// generated ASPX cells, exactly as the package header predicted ("a C# statement model ... is
	// the named next step").
	//
	// The type is a qualified name with optional generic arguments and array brackets, so
	// `System.Reflection.Assembly asm =`, `byte[] b =`, `Dictionary<string,string> d =` and
	// `var x =` all bind. It cannot swallow a VBScript statement: VBScript has no `a b = c` form,
	// and the group still captures the identifier immediately left of the `=`.
	csTypePattern = `(?:[A-Za-z_][\w.]*(?:\s*<[^<>=]*>)?(?:\s*\[\s*\])*\s+)?`
	assignRe      = regexp.MustCompile(
		`(?i)^\s*(?:Set\s+)?` + csTypePattern + `([A-Za-z_]\w*)\s*=([^=].*|)$`)

	// Assignment to a collection element taints the container: `Session("c") = Request("x")` is how
	// a session-staged shell parks its payload, and without this the payload never escapes.
	elemAssignRe = regexp.MustCompile(`(?i)^\s*(?:Set\s+)?([A-Za-z_]\w*)\s*\([^)]*\)\s*=([^=].*|)$`)

	// Iteration is assignment.
	forEachRe = regexp.MustCompile(`(?i)^\s*For\s+Each\s+([A-Za-z_]\w*)\s+In\s+(.*)$`)

	// .NET reflection property-set: SetValue(target, value, index). The TARGET is the assignment's
	// left side. Requiring the `GetProperty`/`GetField` resolution in the same statement keeps this
	// from firing on the many unrelated SetValue methods in the framework (DataRow, Dictionary,
	// ConfigurationElement) -- it is specifically the reflection form that carries a payload into an
	// object the analysis is otherwise blind to.
	setValueRe = regexp.MustCompile(
		`(?i)\bGet(?:Property|Field)\s*\([^)]*\)\s*\.\s*SetValue\s*\(\s*([A-Za-z_]\w*)\s*,\s*([^,]+)`)

	// A bare identifier. VBScript has no sigils, so this is the whole token.
	nameRe = regexp.MustCompile(`\b([A-Za-z_]\w*)\b`)

	// A conditional statement's `=` is a COMPARISON, not an assignment -- VBScript spells both with
	// one character. Without this, `If x = Request("c") Then` taints x and every guarded page looks
	// like a flow.
	condRe = regexp.MustCompile(`(?i)^\s*(?:If|ElseIf|While|Until|Case|Do\s+While|Do\s+Until|Loop\s+While|Loop\s+Until)\b`)

	// `If cond Then stmt` puts a real statement on the same line as a condition.
	thenRe = regexp.MustCompile(`(?i)\bThen\b(.+)$`)

	// Routine boundaries and the names a routine owns. VBScript has no block scope, but it does
	// have routine scope: parameters and Dim'd locals are the routine's own, and a same-named
	// variable in the file body is a different variable.
	routineOpenRe  = regexp.MustCompile(`(?i)^\s*(?:Public\s+|Private\s+)?(?:Sub|Function)\s+([A-Za-z_]\w*)\s*(?:\(([^)]*)\))?`)
	routineCloseRe = regexp.MustCompile(`(?i)^\s*End\s+(?:Sub|Function)\b`)
	localDeclRe    = regexp.MustCompile(`(?i)^\s*(?:Dim|Private|Public|Const|ReDim)\s+(.+)$`)

	// A value coerced to a number cannot carry a payload. This is the sanitizer element of the
	// cited method; ASP has no escaping function that makes a string safe to Execute, so coercion
	// is the honest whole of it.
	sanitizedRe = regexp.MustCompile(`(?i)^\s*(?:CInt|CLng|CDbl|CSng|CBool|Abs|Len|LenB|UBound|LBound|Asc|AscW)\s*\(`)
)

// sink pairs a reported name with a pattern capturing the ARGUMENT text, because the argument is
// what has to be tainted. A sink whose argument is a literal is not a finding.
type sink struct {
	name string
	re   *regexp.Regexp
	arg  int
	// recv is the capture group holding the RECEIVER variable of a method-form sink, or 0 when the
	// sink is a bare statement with no receiver.
	recv int
	// owner is the ProgID a method-form sink's receiver must hold, lowercased and matched as a
	// substring (a ProgID carries an optional version suffix). Empty means "no object required".
	//
	// This REPLACES a file-wide literal test for the token `ScriptControl`. `.Eval(`, `.Run(` and
	// `.Exec(` are ordinary method names, so they need a gate -- but the gate has to be about the
	// object the method is called ON, not about whether a string appears somewhere in the file.
	// The old form was defeated by `Server.CreateObject(Chr(77) & Chr(83) & ...)`, which is the
	// technique in accepted gap item ea52103d78c7667a and in 74 of the 92 generated ASP cells.
	owner string
	// templateExcuse allows isCodeTemplate to skip this sink when its argument begins with a string
	// literal -- "the application is building its own code".
	//
	// TRUE FOR THE Execute/Eval FAMILY ONLY, and stated per sink rather than inferred, because
	// inferring it twice produced the same silent failure twice. Every other sink here takes a
	// leading literal for an ordinary reason: a command line has a prefix
	// (`sh.Exec("cmd.exe /c " & CMD)`), and a reflection call names its method
	// (`t.InvokeMember("Start", ..., CMD)`). Applying the excuse to those silences the whole
	// technique -- measured, twice: all 60 COM dispatch cells and all 5 InvokeMember cells stayed
	// dark with every other part of the analysis working.
	templateExcuse bool
}

// The leading `(^|[^.\w])` is a hand-rolled negative lookbehind -- RE2 has neither lookbehind nor
// negative lookahead. It is what keeps `conn.Execute(sql)` (ADODB, a database sink and a different
// cell) and `Server.Execute(path)` from being read as VBScript's `Execute` statement.
var sinks = []sink{
	// Call form: Execute(expr), ExecuteGlobal(expr), Eval(expr).
	{name: "Execute", arg: 2, templateExcuse: true, re: regexp.MustCompile(`(?i)(^|[^.\w])(?:ExecuteGlobal|Execute|Eval)\s*\(([^)]*)\)`)},
	// Statement form: VBScript allows `Execute a` with no parentheses, and shells use it. Anchored
	// at the START of a statement, which is the only place the statement form can legally appear.
	// Unanchored it matched the word "Execute" in an English sentence and read the rest of that
	// sentence as its argument -- measured on a real benign page, whose prose mentions
	// `Server.Execute /default.asp in case a 404-error ... is thrown by IIS`.
	{name: "Execute", arg: 1, templateExcuse: true, re: regexp.MustCompile(`(?i)^\s*(?:ExecuteGlobal|Execute|Eval)\s+(\S.*)$`)},
	// MSScriptControl, the technique the incumbent's own rule catches and ours did not.
	//
	// BOTH FORMS. VBScript lets a method be called with or without parentheses, and until
	// 2026-09-05 only the parenthesised form was modelled -- so `sc.ExecuteStatement "..."`, the
	// idiomatic spelling, was missed even when the ProgID was a plain literal. That was not a
	// gating failure, it was a missing regex, and it is why the PLAINTEXT ScriptControl cells
	// missed alongside the obfuscated ones.
	{name: "ScriptControl", recv: 1, arg: 2, owner: progScriptCtl,
		re: regexp.MustCompile(`(?i)([A-Za-z_]\w*)\s*\.\s*(?:ExecuteStatement|AddCode|Eval)\s*\(([^)]*)\)`)},
	{name: "ScriptControl", recv: 1, arg: 2, owner: progScriptCtl,
		re: regexp.MustCompile(`(?i)^\s*([A-Za-z_]\w*)\s*\.\s*(?:ExecuteStatement|AddCode|Eval)\s+(\S.*)$`)},

	// WScript.Shell. `.Run` and `.Exec` are the two documented execution methods (Windows Script
	// Host object model). Not modelled at all before 2026-09-05: the only coverage was the YARA
	// rule's literal `"WScript.Shell"` string, which any ProgID assembly defeats.
	{name: "WScriptShell", recv: 1, arg: 2, owner: progWScriptShell,
		re: regexp.MustCompile(`(?i)([A-Za-z_]\w*)\s*\.\s*(?:Run|Exec)\s*\(([^)]*)\)`)},
	{name: "WScriptShell", recv: 1, arg: 2, owner: progWScriptShell,
		re: regexp.MustCompile(`(?i)^\s*([A-Za-z_]\w*)\s*\.\s*(?:Run|Exec)\s+(\S.*)$`)},

	// Shell.Application. ShellExecute takes the command as its SECOND argument, so the whole
	// argument list is captured and the taint test runs over all of it.
	{name: "ShellApplication", recv: 1, arg: 2, owner: progShellApp,
		re: regexp.MustCompile(`(?i)([A-Za-z_]\w*)\s*\.\s*ShellExecute\s*\(([^)]*)\)`)},
	{name: "ShellApplication", recv: 1, arg: 2, owner: progShellApp,
		re: regexp.MustCompile(`(?i)^\s*([A-Za-z_]\w*)\s*\.\s*ShellExecute\s+(\S.*)$`)},

	// ---- ASP.NET / C# sinks -----------------------------------------------------------------
	//
	// ViewState deserialisation. This is the shape docs/RESEARCH.md records as the one every
	// published .NET incident used, and the prior-art review found the field does NOT detect it:
	// Stairwell's published ToolShell rule keys on MachineKeySection and an Assembly.Load of
	// System.Web -- the POST-EXPLOITATION behaviour -- explicitly "rather than targeting ViewState
	// or LosFormatter deserialization directly". The incumbent reaches it with the single keyword
	// `MachineKey`. This is the build-the-gap branch, so the receiver gate is not optional: bare
	// `.Deserialize(` is far too common to fire on unqualified.
	{name: "LosFormatter", recv: 1, arg: 2, owner: typeLosFormatter,
		re: regexp.MustCompile(`(?i)([A-Za-z_]\w*)\s*\.\s*Deserialize\s*\(([^)]*)\)`)},
	{name: "ObjectStateFormatter", recv: 1, arg: 2, owner: typeObjStateFmt,
		re: regexp.MustCompile(`(?i)([A-Za-z_]\w*)\s*\.\s*Deserialize\s*\(([^)]*)\)`)},

	// Runtime compilation -- SharPyShell's documented core ("compiles commands in memory at
	// runtime"). The source text is the SECOND argument, so the whole argument list is captured and
	// the taint test runs over all of it.
	{name: "RuntimeCompile", recv: 1, arg: 2, owner: typeCSharpProv,
		re: regexp.MustCompile(`(?i)([A-Za-z_]\w*)\s*\.\s*CompileAssemblyFrom\w*\s*\(([^)]*)\)`)},

	// Process.Start. The direct spelling; the reflection spelling reaches ReflectionInvoke below.
	// Qualified or bare, for the same reason AssemblyLoad carries no dot-guard: the idiomatic form
	// is `System.Diagnostics.Process.Start(...)`.
	{name: "ProcessStart", arg: 1,
		re: regexp.MustCompile(`(?i)\bProcess\s*\.\s*Start\s*\(([^)]*)\)`)},

	// Assembly.Load of request bytes -- the shape the incumbent's own rule encodes as its first and
	// most specific alternative.
	//
	// NO `(^|[^.\w])` GUARD HERE. That guard is copied from the Execute sink, where it exists to
	// keep `conn.Execute(sql)` from reading as VBScript's Execute statement. Applied to this sink
	// it is exactly backwards: the NORMAL spelling is the fully qualified
	// `System.Reflection.Assembly.Load(...)`, whose `Assembly` is preceded by a dot, so the guard
	// rejected every plaintext assembly-load cell in the corpus.
	{name: "AssemblyLoad", arg: 1,
		re: regexp.MustCompile(`(?i)\bAssembly\s*\.\s*Load\s*\(([^)]*)\)`)},

	// Late-bound reflection dispatch. InvokeMember's argument array is where a request value lands.
	{name: "InvokeMember", arg: 1,
		re: regexp.MustCompile(`(?i)\.\s*InvokeMember\s*\(([^)]*)\)`)},

	// Reflection-driven invocation: `t.GetMethod("Load", ...).Invoke(null, new object[]{...CMD...})`
	// is how the obfuscated assembly-load cells reach the sink once the type name is reconstructed.
	// A bare `.Invoke(` is far too common to be a sink on its own -- it is every delegate call and
	// every EventHandler in the framework -- so this requires the RESOLUTION and the CALL in the
	// SAME statement, which is what makes it a reflection dispatch rather than an ordinary invoke.
	{name: "ReflectionInvoke", arg: 1,
		re: regexp.MustCompile(`(?i)\bGet(?:Method|Constructor)\s*\([^)]*\)[^;]*?\.\s*Invoke\s*\(([^)]*)\)`)},
}

// statements normalises one ASP source into VBScript statements.
//
// Three transformations, each of which the corpus requires:
//
//   - Line continuations (`_` at end of line) are joined, or an assignment split across two lines
//     is invisible.
//   - Comments are stripped. VBScript comments start at `'` or `REM` and run to end of line, and one
//     of the two real gap samples carries a block of them. A `'` INSIDE a string literal is not a
//     comment, so the scan tracks quote state -- VBScript has only double-quoted strings, which
//     makes that exact rather than approximate.
//   - Statements are split on `:` outside strings. One-liner shells put the whole flow on a single
//     line, and without this the assignment and the sink are one uncuttable string.
func statements(text string) []string {
	joined := joinUnbalanced(joinContinuations(scriptRegions(text)))
	var out []string
	for _, line := range strings.Split(joined, "\n") {
		for _, stmt := range splitStatements(stripComment(line)) {
			s := strings.TrimSpace(stmt)
			if s == "" {
				continue
			}
			out = append(out, s)
			// `If cond Then stmt` -- the tail is a statement in its own right, and the head is a
			// condition whose `=` must not be read as an assignment.
			if condRe.MatchString(s) {
				if m := thenRe.FindStringSubmatch(s); m != nil {
					if tail := strings.TrimSpace(m[1]); tail != "" {
						out = append(out, tail)
					}
				}
			}
		}
	}
	return out
}

// scriptRegions returns only the text the ASP runtime executes.
//
// Two things depend on this, and the second was measured rather than anticipated. First,
// `<%a=request("x")%><%execute(a)%>` is two statements, so the delimiters have to become statement
// boundaries -- without that the file is one line beginning with `<`, which no pattern anchors on,
// and the pass found nothing at all on the 39-byte sample it was written for.
//
// Second, and this cost three false positives on a real application before it was fixed: the text
// BETWEEN the delimiters is HTML, not code, and prose is full of English words. `aspLite/ebook.asp`
// contains the sentence "...Server.Execute /default.asp in case a 404-error (file not found) is
// thrown by IIS", and a sink pattern reading the rest of the line as an argument found variable
// names in it. Anything outside a script region is discarded.
//
// A file with no delimiters at all is treated as one script region: the language gate admits bare
// script bodies, and several of this corpus's smallest shells are exactly that.
var (
	openRe  = regexp.MustCompile(`(?i)<%=?|<\s*script[^>]*\brunat\s*=\s*["']?server[^>]*>`)
	closeRe = regexp.MustCompile(`(?i)%>|<\s*/\s*script\s*>`)
)

// A WebHandler/WebService file is NOT a template, and treating it as one makes this pass inert on
// every `.ashx` and `.asmx` in the corpus. The directive is followed by the class source itself --
// no `<% %>` wraps it -- so the `<%`/`%>` model above keeps the directive and discards the entire
// body. That is the difference between a pass that reports zero and a pass that cannot fire, which
// this project does not allow to be confused.
//
// The shape is derived from the parser, not from the samples. `<%\s*@` is the directive opener in
// System.Web.RegularExpressions.DirectiveRegex -- read off System.Web.RegularExpressions.dll
// 4.8.4084.0 on the build host, 2026-08-24:
//
//	\G<%\s*@(\s*(?<attrname>\w[\w:]*(?=\W))(\s*(?<equal>=)\s*"(?<attrval>[^"]*)"|...))*\s*?%>
//
// so whitespace after `<%` and around `=` is legal and the directive name is matched as an ordinary
// attribute token, i.e. case carries no meaning. The tail is `.*?%>` rather than `[^%]*%>` because a
// quoted attribute value may itself contain `%`.
//
// Widening this cannot hide code: a `.aspx` that carries the directive gets MORE text analysed, not
// less, so the failure direction is a false positive the benign pool measures -- never a miss.
var handlerDirectiveRe = regexp.MustCompile(`(?is)<%\s*@\s*(?:WebHandler|WebService)\b.*?%>`)

func scriptRegions(text string) string {
	if m := handlerDirectiveRe.FindStringIndex(text); m != nil {
		return text[m[1]:]
	}
	var b strings.Builder
	rest := text
	found := false
	for {
		o := openRe.FindStringIndex(rest)
		if o == nil {
			break
		}
		found = true
		rest = rest[o[1]:]
		end := len(rest)
		if c := closeRe.FindStringIndex(rest); c != nil {
			end = c[0]
		}
		b.WriteString(rest[:end])
		b.WriteString("\n")
		if end == len(rest) {
			rest = ""
			break
		}
		rest = rest[end:]
		if c := closeRe.FindStringIndex(rest); c != nil {
			rest = rest[c[1]:]
		}
	}
	if !found {
		return text
	}
	return b.String()
}

// joinUnbalanced folds a line into the next while its brackets are still open.
//
// The splitter is line-oriented because VBScript is, and VBScript spells continuation with a
// trailing `_`. C# and JScript do not: they simply wrap, and an argument list routinely spans
// lines. Accepted gap item 4b7ce26d78e7e924 names this exact limitation -- "a statement that SPANS
// LINES ... where the splitter is line-oriented because VBScript is" -- and it is what left the
// five plaintext InvokeMember cells dark after every sink and source they need was already modelled:
//
//	t.InvokeMember("Start", BindingFlags.InvokeMethod, null, null,
//	               new object[]{"cmd.exe", "/c " + CMD});
//
// The rule is language-neutral and additive: join only while a bracket is open. VBScript keeps its
// own `_` continuation and is unaffected, because a VBScript line with unbalanced brackets is a
// syntax error rather than a continuation. Depth is counted OUTSIDE string literals -- a `(` inside
// a quoted payload is data, and counting it would swallow the rest of the file.
func joinUnbalanced(text string) string {
	lines := strings.Split(text, "\n")
	var out []string
	var cur strings.Builder
	depth := 0
	for _, ln := range lines {
		if cur.Len() > 0 {
			cur.WriteByte(' ')
		}
		cur.WriteString(ln)
		depth += bracketDelta(ln)
		if depth <= 0 {
			depth = 0
			out = append(out, cur.String())
			cur.Reset()
		}
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return strings.Join(out, "\n")
}

// bracketDelta counts unmatched openers on one line, ignoring anything inside a string literal.
// Both quote styles are handled because the pass serves VBScript (double only) and C#/JScript
// (both); a lone apostrophe in prose would otherwise open a string that never closes.
func bracketDelta(ln string) int {
	depth, inD, inS := 0, false, false
	for i := 0; i < len(ln); i++ {
		c := ln[i]
		switch {
		case inD:
			if c == '"' {
				inD = false
			}
		case inS:
			if c == '\'' {
				inS = false
			}
		case c == '"':
			inD = true
		case c == '(' || c == '[' || c == '{':
			depth++
		case c == ')' || c == ']' || c == '}':
			depth--
		}
	}
	return depth
}

func joinContinuations(text string) string {
	text = strings.ReplaceAll(text, "\r\n", "\n")
	var b strings.Builder
	for i := 0; i < len(text); i++ {
		if text[i] == '_' {
			j := i + 1
			for j < len(text) && (text[j] == ' ' || text[j] == '\t' || text[j] == '\r') {
				j++
			}
			if j < len(text) && text[j] == '\n' {
				b.WriteByte(' ')
				i = j
				continue
			}
		}
		b.WriteByte(text[i])
	}
	return b.String()
}

// stripComment cuts a line at the first `'` outside a string, or at a REM keyword.
func stripComment(line string) string {
	inString := false
	for i := 0; i < len(line); i++ {
		switch line[i] {
		case '"':
			inString = !inString
		case '\'':
			if !inString {
				return line[:i]
			}
		case 'r', 'R':
			if inString || i+3 > len(line) {
				continue
			}
			if !strings.EqualFold(line[i:min(i+3, len(line))], "rem") {
				continue
			}
			// A word-bounded REM only: `Premium` is not a comment.
			if i > 0 && isWordByte(line[i-1]) {
				continue
			}
			if i+3 < len(line) && isWordByte(line[i+3]) {
				continue
			}
			return line[:i]
		}
	}
	return line
}

// splitStatements splits on `:` outside string literals. A URL's `://` lives inside a string, so
// tracking quote state is enough.
func splitStatements(line string) []string {
	var out []string
	inString := false
	start := 0
	for i := 0; i < len(line); i++ {
		switch line[i] {
		case '"':
			inString = !inString
		case ':':
			if !inString {
				out = append(out, line[start:i])
				start = i + 1
			}
		}
	}
	return append(out, line[start:])
}

func isWordByte(b byte) bool {
	return b == '_' || (b >= '0' && b <= '9') || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// assignment is one left-hand name and the right-hand expression text.
type assignment struct {
	lhs string
	rhs string
}

func assignmentsIn(stmt string) []assignment {
	// A condition's `=` is a comparison. The `If ... Then stmt` tail was already emitted as its own
	// statement by `statements`, so dropping the whole conditional here loses nothing.
	if condRe.MatchString(stmt) {
		return nil
	}
	if m := forEachRe.FindStringSubmatch(stmt); m != nil {
		return []assignment{{lhs: m[1], rhs: m[2]}}
	}
	if m := elemAssignRe.FindStringSubmatch(stmt); m != nil {
		return []assignment{{lhs: m[1], rhs: m[2]}}
	}
	// Reflection property-set is an assignment to its FIRST argument, not to the statement's left
	// side -- `psi.GetProperty("Arguments").SetValue(si, "/c " + CMD, null)` puts request data into
	// `si`. Without this the object reaches Process.Start carrying a payload nothing observed it
	// receive, which is how 25 of the generated process-start cells stayed dark while the plaintext
	// five were caught: the plaintext form passes the payload through the constructor, where the
	// ordinary assignment rule already sees it.
	if m := setValueRe.FindStringSubmatch(stmt); m != nil {
		return []assignment{{lhs: m[1], rhs: m[2]}}
	}
	if m := assignRe.FindStringSubmatch(stmt); m != nil {
		return []assignment{{lhs: m[1], rhs: m[2]}}
	}
	return nil
}

func namesIn(s string) map[string]bool {
	out := map[string]bool{}
	for _, m := range nameRe.FindAllStringSubmatch(s, -1) {
		out[strings.ToLower(m[1])] = true
	}
	return out
}

func intersects(a, b map[string]bool) bool {
	for k := range a {
		if b[k] {
			return true
		}
	}
	return false
}

// scopeOf assigns every statement a routine scope id: 0 for the file body, 1..n for each Sub or
// Function. Also returns, per scope, the names that scope OWNS -- its parameters and its Dim'd
// locals.
//
// This exists because of three measured false positives on zblogasp, all the same shape: a routine
// parameter named `Object` or `s` or a local named `Field`, colliding with a request-derived
// variable in a different routine, and inheriting its taint. Without scoping every common
// identifier is a shared channel between unrelated routines.
func scopeOf(stmts []string) ([]int, []map[string]bool) {
	ids := make([]int, len(stmts))
	owned := []map[string]bool{{}}
	cur := 0
	for i, stmt := range stmts {
		if routineCloseRe.MatchString(stmt) {
			ids[i] = cur
			cur = 0
			continue
		}
		if m := routineOpenRe.FindStringSubmatch(stmt); m != nil {
			owned = append(owned, map[string]bool{})
			cur = len(owned) - 1
			// Parameters. `ByRef`/`ByVal` are modifiers, not names.
			for _, n := range nameRe.FindAllStringSubmatch(m[2], -1) {
				low := strings.ToLower(n[1])
				if low == "byref" || low == "byval" {
					continue
				}
				owned[cur][low] = true
			}
			ids[i] = cur
			continue
		}
		ids[i] = cur
		if cur != 0 {
			if m := localDeclRe.FindStringSubmatch(stmt); m != nil {
				for _, n := range nameRe.FindAllStringSubmatch(m[1], -1) {
					owned[cur][strings.ToLower(n[1])] = true
				}
			}
		}
	}
	return ids, owned
}

// key resolves a name to the scope it actually refers to: the routine's own if the routine owns it,
// otherwise the file body's.
func key(scope int, owned []map[string]bool, name string) string {
	if scope != 0 && scope < len(owned) && owned[scope][name] {
		return fmt.Sprintf("%d|%s", scope, name)
	}
	return "0|" + name
}

// taintedNames runs the forward fixpoint over the statement list, scope-aware. Names are lower-cased
// throughout: VBScript is case-insensitive, and `A` and `a` are one variable.
func taintedNames(stmts []string) (map[string]bool, []int, []map[string]bool) {
	ids, owned := scopeOf(stmts)
	type edge struct {
		lhs     string
		names   []string
		sourced bool
	}
	var edges []edge
	for i, stmt := range stmts {
		for _, a := range assignmentsIn(stmt) {
			if sanitizedRe.MatchString(a.rhs) {
				continue // coerced to a number: it cannot carry a payload
			}
			var rhs []string
			for n := range namesIn(a.rhs) {
				rhs = append(rhs, key(ids[i], owned, n))
			}
			edges = append(edges, edge{
				lhs:     key(ids[i], owned, strings.ToLower(a.lhs)),
				names:   rhs,
				sourced: sourceExpr.MatchString(a.rhs),
			})
		}
	}

	tainted := map[string]bool{}
	for round := 0; round < maxRounds; round++ {
		grew := false
		for _, e := range edges {
			if !e.sourced {
				any := false
				for _, n := range e.names {
					if tainted[n] {
						any = true
						break
					}
				}
				if !any {
					continue
				}
			}
			if !tainted[e.lhs] {
				tainted[e.lhs] = true
				grew = true
			}
		}
		if !grew {
			break
		}
	}
	return tainted, ids, owned
}

// isDeclaration reports whether a match sits on a statement that DECLARES a routine, so a page
// defining `Function Eval(x)` is not mistaken for a call to the sink it shares a name with.
func isDeclaration(stmt string) bool {
	t := strings.TrimSpace(stmt)
	for _, kw := range []string{"sub ", "function ", "private ", "public ", "class ", "dim ", "end "} {
		if len(t) >= len(kw) && strings.EqualFold(t[:len(kw)], kw) {
			return true
		}
	}
	return false
}

// isCodeTemplate reports whether a sink argument begins with a string literal, meaning the program
// being executed was authored by the page and the tainted value supplies a fragment of it -- an
// identifier, an index, a variable name.
//
// That distinction is the difference between a vulnerability and a webshell, and this is a webshell
// scanner. `Execute "Response.Write Ubound(" & s & ")"` with s from Request.Form is a real
// code-injection flaw in zblogasp; `Execute a` with a from Request is a shell. Measured over the
// whole Classic ASP corpus: 2 of 2 benign hits were the template form, 63 of 75 malicious hits were
// the bare form.
//
// The cost is stated rather than hidden: a shell that writes `Execute("On Error Resume Next:" & c)`
// is not reported by this pass. The rule layer still sees such a file, and the two benign flows this
// removes are published in the run-set as the vulnerabilities they are.
func isCodeTemplate(arg string) bool {
	a := strings.TrimSpace(arg)
	return strings.HasPrefix(a, `"`)
}

// Analyze reports one finding per distinct sink kind whose argument carries request-derived data.
func Analyze(src []byte) []Finding {
	if len(src) == 0 || len(src) > maxInput {
		return nil
	}
	text := string(src)
	if !sourceExpr.MatchString(text) {
		return nil // no request accessor anywhere: nothing can be tainted
	}

	stmts := statements(text)
	tainted, ids, owned := taintedNames(stmts)
	// The COM object map is built from FOLDED ProgIDs, so an assembled
	// `Server.CreateObject(Chr(87) & ...)` binds its variable exactly as a literal one does.
	objects := comObjects(stmts)
	// ...and from server-side `<object>` declarations, which are NOT in a script region and so are
	// not in `stmts` at all. That is why three real samples carrying a fully modelled technique
	// scored 0: nothing bound the receiver, so the gate rejected the sink. See objecttag.go.
	for name, prog := range objectTagObjects(text) {
		if _, already := objects[name]; !already {
			objects[name] = prog
		}
	}

	// The file-drop pass runs alongside the sink table rather than inside it: a dropper spans two
	// statements (a handle bound to a destination, then a tainted write through it), which a
	// single-statement sink pattern cannot express. See filedrop.go.
	drops := fileDrops(stmts, tainted, ids, owned, objects)

	hit := map[string]string{}
	for _, s := range sinks {
		if _, seen := hit[s.name]; seen {
			continue
		}
		for i, stmt := range stmts {
			if isDeclaration(stmt) {
				continue
			}
			loc := s.re.FindStringSubmatchIndex(stmt)
			if loc == nil || 2*s.arg+1 >= len(loc) || loc[2*s.arg] < 0 {
				continue
			}
			// A method-form sink fires only when its receiver holds the right COM object. This is
			// the narrowing that replaces the file-wide `ScriptControl` literal test.
			if s.owner != "" {
				if s.recv == 0 || 2*s.recv+1 >= len(loc) || loc[2*s.recv] < 0 {
					continue
				}
				if !objectIs(objects, stmt[loc[2*s.recv]:loc[2*s.recv+1]], s.owner) {
					continue
				}
			}
			arg := stmt[loc[2*s.arg]:loc[2*s.arg+1]]
			// A request accessor appearing IN the executed text is a direct dispatch however the
			// text is quoted -- `ExecuteStatement("ev"&"al(request(""c""))")` is the split-string
			// evasion, and treating it as an application's code template would hand the technique a
			// free pass. Only a template whose tainted part arrives through a VARIABLE is excused.
			direct := sourceExpr.MatchString(arg)
			// The code-template excuse applies ONLY to the bare Execute/Eval family, where an
			// application legitimately builds its own code and a leading literal is evidence of
			// that. It must NOT apply to a COM execution object: `sh.Exec("cmd.exe /c " & CMD)`
			// begins with a literal for the ordinary reason that a command line has a prefix, and
			// excusing it silences the entire technique. Measured -- with the excuse applied to
			// these sinks, all 60 COM dispatch cells stayed dark even with the ProgID resolved.
			if s.templateExcuse && !direct && isCodeTemplate(arg) {
				continue
			}
			argTainted := false
			for n := range namesIn(arg) {
				if tainted[key(ids[i], owned, n)] {
					argTainted = true
					break
				}
			}
			if direct || argTainted {
				hit[s.name] = trim(strings.TrimSpace(arg), 80)
				break
			}
		}
	}
	if len(hit) == 0 {
		// A dropper need not reach an execution sink at all -- that is the whole point of the
		// capability class, and 46 of the 49 real Classic ASP samples the incumbent caught and this
		// package missed carry no exec sink of any kind.
		return drops
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
			Family:   "GenericWebshell",
			Rule:     "asptaint:sink-on-request",
			Evidence: fmt.Sprintf("request-derived data reaches %s(%s)", n, hit[n]),
		})
	}
	return append(out, drops...)
}

func trim(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
