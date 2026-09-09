package asptaint

import (
	"strings"
	"testing"
)

func analyze(t *testing.T, src string) []Finding {
	t.Helper()
	return Analyze([]byte(src))
}

func mustFind(t *testing.T, src, why string) {
	t.Helper()
	if got := analyze(t, src); len(got) == 0 {
		t.Fatalf("%s: expected a finding, got none\n---\n%s", why, src)
	}
}

func mustNotFind(t *testing.T, src, why string) {
	t.Helper()
	if got := analyze(t, src); len(got) != 0 {
		t.Fatalf("%s: expected no finding, got %+v\n---\n%s", why, got, src)
	}
}

// The measurement this package exists for. Both samples are real, from the phase 5 gap list.
func TestTheTwoSamplesThatBeatUs(t *testing.T) {
	mustFind(t, `<%a=request("leon1942")%><%execute(a)%>`,
		"e8d68e0c1416, 39 bytes, the commonest shape a Classic ASP shell takes")

	mustFind(t, `<%
dim play
'
''''''''''''''''''
'''''''''

play = request("5kik")

%>
what's your name
<%
execute(play)

%>`, "097a5e87c1c0 -- and its comment block must not stop the flow")
}

func TestTheAdjacentFormStillReports(t *testing.T) {
	// The rules already catch this; the pass must not disagree with them about the same file.
	mustFind(t, `<%Execute(Request("c"))%>`, "adjacent dispatch")
}

func TestScriptControl(t *testing.T) {
	// 534d12698f5b, the sample whose cell this project had recorded the INCUMBENT as blind to.
	mustFind(t, `<%
set ms = server.CreateObject("MSScriptControl.ScriptControl.1")
ms.Language="VBScript"
ms.AddObject "Response", Response
ms.ExecuteStatement(request("8090sec"))
%>`, "MSScriptControl.ExecuteStatement on a request value")
}

func TestVBScriptStatementForms(t *testing.T) {
	cases := []struct{ name, src string }{
		{"no parentheses", `<% a = Request("c")
Execute a %>`},
		{"colon-separated one-liner", `<% a = Request("c") : Execute a %>`},
		{"ExecuteGlobal", `<% p = Request.Form("x")
ExecuteGlobal p %>`},
		{"Eval", `<% q = Request.QueryString("x")
Eval(q) %>`},
		{"Set assignment", `<% Set a = Request("c")
Execute a %>`},
		{"line continuation", `<% a = _
   Request("c")
Execute a %>`},
		{"two hops", `<% a = Request("c")
b = a
c = b & ""
Execute c %>`},
		{"case insensitivity", `<% AbC = rEqUeSt("c")
eXeCuTe(abc) %>`},
		{"concatenation", `<% a = "x" & Request("c") & "y"
Execute a %>`},
		{"ServerVariables source", `<% a = Request.ServerVariables("HTTP_CMD")
Execute a %>`},
		{"session-staged", `<% Session("payload") = Request("c")
Execute Session("payload") %>`},
		{"For Each over a tainted collection", `<% items = Request.Form
For Each it In items
Execute it
Next %>`},
		{"If ... Then on one line", `<% If Len(Request("c")) > 0 Then a = Request("c")
Execute a %>`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) { mustFind(t, c.src, c.name) })
	}
}

// Everything below is a way the pass could be WRONG in the direction that costs precision, which is
// the only thing this release actually sells.
func TestPrecision(t *testing.T) {
	cases := []struct{ name, src string }{
		{"no source at all", `<% a = "dir"
Execute a %>`},
		{"source but no execution sink", `<% a = Request.Form("name")
Response.Write a %>`},
		{"sink on a literal", `<% x = Request("c")
Execute "Response.Write 1" %>`},
		{"commented-out assignment", `<% Dim a
' a = Request("c")
Execute a %>`},
		{"REM comment", `<% Dim a
REM a = Request("c")
Execute a %>`},
		{"database Execute is a different sink", `<% sql = Request("q")
Set conn = Server.CreateObject("ADODB.Connection")
conn.Execute(sql) %>`},
		{"Server.Execute is not the VBScript statement", `<% f = Request("f")
Server.Execute(f) %>`},
		{"comparison is not assignment", `<% If a = Request("c") Then
Response.Write "hi"
End If
Execute a %>`},
		{"While comparison is not assignment", `<% While a = Request("c")
Wend
Execute a %>`},
		{"numeric coercion sanitises", `<% n = CInt(Request("n"))
Execute n %>`},
		{"Len sanitises", `<% n = Len(Request("c"))
Execute n %>`},
		{"a declared routine is not a call", `<% x = Request("c")
Function Eval(v)
Eval = v
End Function %>`},
		{"unrelated variable with a similar name", `<% cmdline = Request("c")
Execute cmd %>`},
		{"ScriptControl methods need the ProgID", `<% a = Request("c")
Set o = Server.CreateObject("Some.Other.Object")
o.AddCode(a) %>`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) { mustNotFind(t, c.src, c.name) })
	}
}

// A `'` inside a string literal is an apostrophe, not a comment. Getting this wrong silently
// truncates half the statements in a file that builds HTML with single quotes -- which is most of
// them.
func TestApostropheInsideAStringIsNotAComment(t *testing.T) {
	mustFind(t, `<% Response.Write "<form action='' method='post'>"
a = Request("c")
Execute a %>`, "an apostrophe in an HTML attribute must not eat the rest of the line")
}

// A URL's colon lives inside a string literal, so statement splitting must not cut there.
func TestColonInsideAStringDoesNotSplit(t *testing.T) {
	mustNotFind(t, `<% Response.Redirect "http://example.invalid/a" %>`,
		"a redirect is not a flow, and the URL must not be read as two statements")
}

func TestEvidenceNamesTheSinkAndTheArgument(t *testing.T) {
	got := analyze(t, `<% a = Request("c")
Execute a %>`)
	if len(got) != 1 {
		t.Fatalf("expected one finding, got %d", len(got))
	}
	if got[0].Score != 85 {
		t.Errorf("score = %d, want 85 (the confirmed band this pass exists to earn)", got[0].Score)
	}
	if got[0].Rule != "asptaint:sink-on-request" {
		t.Errorf("rule = %q", got[0].Rule)
	}
	if !strings.Contains(got[0].Evidence, "Execute") {
		t.Errorf("evidence does not name the sink: %q", got[0].Evidence)
	}
}

// One finding per sink KIND: three Execute calls in one shell are one fact about that file.
func TestOneFindingPerSinkKind(t *testing.T) {
	got := analyze(t, `<% a = Request("c")
Execute a
Execute a
Execute(a) %>`)
	if len(got) != 1 {
		t.Fatalf("expected 1 finding for 3 occurrences of one sink kind, got %d", len(got))
	}
}

func TestBounds(t *testing.T) {
	if got := Analyze(nil); got != nil {
		t.Errorf("nil input: %+v", got)
	}
	if got := Analyze([]byte{}); got != nil {
		t.Errorf("empty input: %+v", got)
	}
	big := append([]byte(`<% a = Request("c") `), make([]byte, maxInput)...)
	if got := Analyze(big); got != nil {
		t.Errorf("oversize input analysed: %+v", got)
	}
}

// The pass must terminate on a cyclic assignment graph rather than spin.
func TestCyclicAssignmentsTerminate(t *testing.T) {
	mustFind(t, `<% a = b
b = c
c = a & Request("x")
Execute a %>`, "a cycle must reach a fixpoint, not loop")
}

// Scoping. A routine's parameters and Dim'd locals are ITS OWN, and must not inherit taint from a
// same-named variable elsewhere in the file. Measured before this existed: three false positives on
// zblogasp, all of this exact shape --
//
//	Function GetFieldValue(Byref Object, FieldName)
//	    Dim Field
//	    For Each Field In Object.YTARRAY
//	        Execute("GetFieldValue=Object." & Field)
//
// where `Field` never touches Request and was tainted only because the name collided with a
// request-derived variable in a different routine. VBScript has no block scope but it does have
// routine scope, and ignoring it makes every common identifier a shared channel.
func TestRoutineLocalsDoNotInheritTaint(t *testing.T) {
	mustNotFind(t, `<%
a = Request("c")
Function Helper(a)
  Execute a
End Function
%>`, "a parameter shadows the global of the same name")

	mustNotFind(t, `<%
Field = Request("c")
Function GetFieldValue(Byref Object, FieldName)
  Dim Field
  For Each Field In Object.YTARRAY
    Execute("GetFieldValue=Object." & Field)
  Next
End Function
%>`, "zblogasp YT.Lib.asp, reduced -- the real false positive this closes")

	mustNotFind(t, `<%
s = Request("c")
Sub Dump(s)
  Execute("Response.Write Ubound(" & s & ")")
End Sub
%>`, "zblogasp PluginInterface, reduced")
}

// The other half: scoping must not become a way to LOSE a real flow.
func TestScopingDoesNotHideRealFlows(t *testing.T) {
	mustFind(t, `<%
Function Go()
  p = Request("c")
  Execute p
End Function
%>`, "a flow entirely inside one routine")

	mustFind(t, `<%
p = Request("c")
Sub Run()
  Execute p
End Sub
%>`, "a global tainted variable IS visible inside a routine that does not shadow it")

	mustFind(t, `<%
Function Grab()
  Grab = Request("c")
End Function
x = Grab()
Execute x
%>`, "a routine returning request data taints its caller through the routine name")
}

// `End Sub` must actually CLOSE the routine, and until 2026-08-24 it did not: `routineCloseRe`
// shipped in HEAD as `^\s*End\s+(?:Sub|Function)` followed by a literal 0x08 BACKSPACE where a `\b`
// was intended -- the heredoc-escape trap this project has recorded three times -- so the pattern
// could never match and `scopeOf` never returned to module scope.
//
// Every existing test in this file passed with the regex dead, which is why this one exists. The
// cost is a MISS, and it needs all three of: a module-level flow that straddles a routine, and a
// routine that declares a local of the same name. Then `key()` routes the post-routine `Execute a`
// into the routine's scope, where the module's taint on `0|a` is not visible.
//
// This is a positive control, not a regression test: re-break the anchor and this case fails while
// the rest of the file still passes.
func TestEndSubClosesTheRoutineScope(t *testing.T) {
	mustFind(t, `<%
a = Request("c")
Sub Helper()
  Dim a
  a = "safe"
End Sub
Execute a
%>`, "module-level taint, consumed after a routine that shadows the name")

	mustFind(t, `<%
p = Request("c")
Function Helper(q)
  Dim p
  p = q
End Function
Execute p
%>`, "same shape with a Function and a parameter")
}

// A sink whose argument BEGINS with a string literal is executing a program the page authored, with
// a tainted value spliced into it. That is a code-injection vulnerability in the application; it is
// not a webshell, and this is a webshell scanner. When the argument begins with the value itself,
// the program IS the attacker's.
//
// Measured over the whole ASP corpus before this rule existed: 2 of 2 benign hits were the template
// form and 63 of 75 malicious hits were the bare form. The two benign ones are real flows -- zblogasp
// does `s = LCase(Request.Form("interface"))` and then `Execute "Response.Write Ubound("&s&")"` --
// so they are reported honestly as vulnerabilities in the run-set rather than relabelled to make
// the number look better.
func TestALiteralCodeTemplateIsNotAWebshell(t *testing.T) {
	mustNotFind(t, `<%
s = LCase(Request.Form("interface"))
Execute "Response.Write Ubound(" & s & ")"
%>`, "zblogasp ZBDK -- a real injection flaw, not a shell")

	mustNotFind(t, `<%
Dim aryElement
s = Request.QueryString("view")
aryElement = Split(s, "=")
Execute("j=" & aryElement(0))
%>`, "zblogasp c_html_js -- same shape")

	// And the other side: the payload itself must still report.
	mustFind(t, `<% a = Request("c")
Execute a %>`, "a bare tainted argument is the shell form")
	mustFind(t, `<% Execute(Request("c")) %>`, "a bare request accessor is the shell form")
}

// The split-string evasion. `"ev"&"al(request(""c""))"` begins with a string literal, so the
// code-template rule would excuse it -- but the request accessor is INSIDE the executed text, which
// makes it a direct dispatch however it is quoted. Sample 534d12698f5b in the phase 5 gap list is
// exactly this, and it is one of the twelve the incumbent caught and we did not.
func TestASplitStringLiteralIsStillADirectDispatch(t *testing.T) {
	mustFind(t, `<%
set ms = server.CreateObject("MSScriptControl.ScriptControl.1")
ms.Language="VBScript"
ms.ExecuteStatement("ev"&"al(request(""8090sec""))")
%>`, "the request accessor is in the executed text, not spliced in through a variable")

	// And the excuse still applies when the tainted part really does arrive via a variable.
	mustNotFind(t, `<%
s = LCase(Request.Form("interface"))
Execute "Response.Write Ubound(" & s & ")"
%>`, "an application splicing a value into its own code template")
}
