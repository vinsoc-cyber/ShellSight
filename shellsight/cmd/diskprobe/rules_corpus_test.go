package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"shellsight/internal/javadisk"
)

// ruleMatches scans a single in-memory PHP file with the bundled yr + repo rules and
// reports the set of rule knowledge-refs that matched it. Used for fast per-rule TDD
// (the corpus-wide efficacy is measured separately by cmd/measure).
func ruleMatches(t *testing.T, content string) map[string]bool {
	t.Helper()
	yr := yrPath()
	if yr == "" {
		t.Skip("yr binary not found")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "s.php"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	findings, ok, failed := scanWebrootDirs(yr, rulesDir(), []string{dir}, "T")
	if ok == 0 && len(failed) > 0 {
		t.Skip("yr scan blocked (AV/OS) on temp files — covered by cmd/measure")
	}
	got := map[string]bool{}
	for _, f := range findings {
		got[f.Detection.KnowledgeRef] = true
	}
	return got
}

// ruleMatchesDeobf is like ruleMatches but routes through scanWithDeobf so the deobfuscation +
// phptaint resolved layers are scanned too. Use this for tests that depend on a resolved/decoded
// layer rather than the raw source.
func ruleMatchesDeobf(t *testing.T, content string) map[string]bool {
	t.Helper()
	yr := yrPath()
	if yr == "" {
		t.Skip("yr binary not found")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "s.php"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	findings, _, failed, _ := scanWithDeobf(context.Background(), yr, rulesDir(), false, []string{dir}, "T", javadisk.DefaultOptions())
	if len(failed) > 0 {
		t.Skip("yr scan blocked (AV/OS) on temp files — covered by cmd/measure")
	}
	got := map[string]bool{}
	for _, f := range findings {
		got[f.Detection.KnowledgeRef] = true
	}
	return got
}

func ruleMatchesNamedFile(t *testing.T, name, content string) map[string]bool {
	t.Helper()
	yr := yrPath()
	if yr == "" {
		t.Skip("yr binary not found")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	findings, ok, failed := scanWebrootDirs(yr, rulesDir(), []string{dir}, "T")
	if ok == 0 && len(failed) > 0 {
		t.Skip("yr scan blocked (AV/OS) on temp files")
	}
	got := map[string]bool{}
	for _, f := range findings {
		got[f.Detection.KnowledgeRef] = true
	}
	return got
}

func TestCommandExecRuleMatchesShellAndNotBenign(t *testing.T) {
	mal := ruleMatches(t, `<?php system($_GET["cmd"]); ?>`)
	if !mal["kb:yara/php_command_exec_webshell"] {
		t.Fatalf("want php_command_exec_webshell on system($_GET), got %v", mal)
	}
	// Indirection: request input assigned to a var, then passed to the sink (small file).
	mal2 := ruleMatches(t, `<?php $c=$_POST['c']; system($c); ?>`)
	if !mal2["kb:yara/php_command_exec_webshell"] {
		t.Fatalf("want php_command_exec_webshell on $c=$_POST; system($c), got %v", mal2)
	}
	// Benign: exec on a constant argument with no request input -> must NOT match.
	ben := ruleMatches(t, `<?php exec("ls -la /var/log", $out); ?>`)
	if ben["kb:yara/php_command_exec_webshell"] {
		t.Fatalf("false positive on constant-arg exec: %v", ben)
	}
}

func TestVarfuncRequestRule(t *testing.T) {
	mal := ruleMatches(t, `<?php $f=$_GET['f']; $f($_GET['c']); ?>`)
	if !mal["kb:yara/php_varfunc_request_webshell"] {
		t.Fatalf("want php_varfunc_request_webshell on $f($_GET[..]), got %v", mal)
	}
	ben := ruleMatches(t, `<?php $q=$_GET['q']; echo htmlspecialchars($q); ?>`)
	if ben["kb:yara/php_varfunc_request_webshell"] {
		t.Fatalf("false positive on read-only superglobal use: %v", ben)
	}
}

func TestReflectionRule(t *testing.T) {
	mal := ruleMatches(t, `<?php $r=new ReflectionFunction($_GET['f']); echo $r->invokeArgs(array($_GET['c'])); ?>`)
	if !mal["kb:yara/php_reflection_webshell"] {
		t.Fatalf("want php_reflection_webshell on ReflectionFunction($_GET), got %v", mal)
	}
	ben := ruleMatches(t, `<?php $m=new ReflectionMethod('AuthenticationCookie','setUp'); $m->invoke($this->object); ?>`)
	if ben["kb:yara/php_reflection_webshell"] {
		t.Fatalf("false positive on reflection of a hard-coded class: %v", ben)
	}
}

func TestFilterCallbackRule(t *testing.T) {
	mal := ruleMatches(t, `<?php filter_var($_REQUEST['pass'], FILTER_CALLBACK, array('options'=>'assert')); ?>`)
	if !mal["kb:yara/php_filter_callback_webshell"] {
		t.Fatalf("want php_filter_callback_webshell on filter_var+FILTER_CALLBACK+assert, got %v", mal)
	}
	ben := ruleMatches(t, `<?php $id=filter_var($_GET['id'], FILTER_VALIDATE_INT); ?>`)
	if ben["kb:yara/php_filter_callback_webshell"] {
		t.Fatalf("false positive on FILTER_VALIDATE_INT: %v", ben)
	}
}

func TestSqlExecRule(t *testing.T) {
	// Request input passed directly INTO the query call (the tightened, request-in-call form).
	mal := ruleMatches(t, `<?php mysqli_query($conn,$_POST['q']); ?>`)
	if !mal["kb:yara/php_sql_exec_webshell"] {
		t.Fatalf("want php_sql_exec_webshell on mysqli_query($conn,$_POST), got %v", mal)
	}
	// Benign: constant query (no request in the call) -> must NOT match.
	ben := ruleMatches(t, `<?php mysqli_query($conn,"SELECT 1"); ?>`)
	if ben["kb:yara/php_sql_exec_webshell"] {
		t.Fatalf("false positive on constant query: %v", ben)
	}
	// Benign: ->query on a constant with request elsewhere in the file -> must NOT match
	// (the co-presence form that caused 9 FP on real apps).
	ben2 := ruleMatches(t, `<?php $db->query("SELECT 1"); $x=$_GET['x']; echo $x; ?>`)
	if ben2["kb:yara/php_sql_exec_webshell"] {
		t.Fatalf("false positive on ->query(constant) + request elsewhere: %v", ben2)
	}
}

func TestFilemanagerRule(t *testing.T) {
	mal := ruleMatches(t, `<?php unlink($_POST['file']); ?>`)
	if !mal["kb:yara/php_filemanager_webshell"] {
		t.Fatalf("want php_filemanager_webshell on unlink($_POST), got %v", mal)
	}
	ben := ruleMatches(t, `<?php unlink('/tmp/old_cache.txt'); ?>`)
	if ben["kb:yara/php_filemanager_webshell"] {
		t.Fatalf("false positive on constant-arg unlink: %v", ben)
	}
}

// TestResolvedVarSinkDetectedViaMirror checks the full deobf+resolve pipeline: a shell whose sink
// name is built at runtime ($ohx resolves to "assert" via chr+concat) has no literal assert(, but
// after phptaint resolves $ohx( -> assert( in the decoded mirror, php_eval_request_webshell fires.
func TestResolvedVarSinkDetectedViaMirror(t *testing.T) {
	src := `<?php $ohx=chr(97)."s".chr(115)."ert"; @$ohx(@$_POST["data"]); ?>`
	got := ruleMatchesDeobf(t, src)
	if !got["kb:yara/php_eval_request_webshell"] {
		t.Fatalf("want php_eval_request_webshell on resolved assert($_POST), got %v", got)
	}
}

// TestPhpTaintArrayKeyDispatchViaScan checks the Tier 2 AST pass end-to-end: array-key dispatch
// $item['k']($_POST[..]) (where $item['k']='assert') is NOT matched by any YARA rule, but the AST
// taint pass resolves the array key to 'assert' and flags phptaint:sink-on-request.
func TestPhpTaintArrayKeyDispatchViaScan(t *testing.T) {
	src := `<?php $item['k']='assert'; $item['k']($_POST['d']); ?>`
	got := ruleMatchesDeobf(t, src)
	if !got["phptaint:sink-on-request"] {
		t.Fatalf("want phptaint:sink-on-request on array-key dispatch, got %v", got)
	}
}

func TestASPRulesDoNotLeakIntoBenignJSP(t *testing.T) {
	src := `<%@ page language="java" %>
<html>
<head><script type="text/javascript">function validate(){ return true; }</script></head>
<body>
<% String q = request.getParameter("q"); out.print(org.apache.commons.text.StringEscapeUtils.escapeHtml4(q)); %>
</body>
</html>`
	got := ruleMatchesNamedFile(t, "view.jsp", src)
	if got["kb:yara/asp_html_hybrid_webshell"] || got["kb:yara/asp_jscript_server_webshell"] {
		t.Fatalf("ASP-family rules leaked into benign JSP: %v", got)
	}
}

func TestBenignASPXClientScriptDoesNotTriggerJScriptServerRule(t *testing.T) {
	src := `<%@ Page Language="C#" %>
<html>
<head><script type="text/javascript">function validate(){ return Page_ClientValidate(); }</script></head>
<body><asp:TextBox runat="server" ID="Name" /></body>
</html>`
	got := ruleMatchesNamedFile(t, "Default.aspx", src)
	if got["kb:yara/asp_jscript_server_webshell"] {
		t.Fatalf("client-side script triggered server JScript rule: %v", got)
	}
}

func TestMaliciousASPHybridStillMatches(t *testing.T) {
	src := `<html><body>
<% cmd = Request("cmd") : Set s = CreateObject("WScript.Shell") : s.Exec(cmd) %>
</body></html>`
	got := ruleMatchesNamedFile(t, "shell.asp", src)
	if !got["kb:yara/asp_html_hybrid_webshell"] {
		t.Fatalf("want asp_html_hybrid_webshell on ASP Request+WScript shell, got %v", got)
	}
}

func TestMaliciousServerJScriptStillMatches(t *testing.T) {
	src := `<script runat="server" language="JScript">
function Page_Load(){ eval(Request["cmd"]); }
</script>`
	got := ruleMatchesNamedFile(t, "shell.aspx", src)
	if !got["kb:yara/asp_jscript_server_webshell"] {
		t.Fatalf("want asp_jscript_server_webshell on server JScript eval(Request), got %v", got)
	}
}

// A real benign page, reduced from gh:zblogcn/zblogasp -- a Chinese ASP blog CMS that supplied FIVE
// of this rule's benign hits, and the ONLY application that produced any.
//
// The rule required a server-side JScript block, the word `Request` ANYWHERE in the file, and an
// eval/exec/file sink ANYWHERE in the file. A CMS admin page legitimately has all three: a JScript
// helper block, a `Request` read for its own parameters, and an `eval(` or `execute(` somewhere in
// several kilobytes of unrelated code. Nothing connected them.
//
// This is the same defect `asp_html_hybrid_webshell` already had and already fixed, with the same
// fix: require the request to REACH the sink. Measured over the Classic ASP corpus, the rule was the
// sole detector for ZERO of 349 malicious samples while costing 5 benign hits, and it contributed
// nothing on the ASPX, PHP, Java or Perl/Python corpora either -- so the co-occurrence form was pure
// cost. Tightening rather than deleting keeps the server-JScript capability the test above pins.
func TestBenignCMSServerJScriptHelperDoesNotTriggerJScriptServerRule(t *testing.T) {
	src := `<%
Dim strName
strName = Request("name")
Response.Write "<h1>" & strName & "</h1>"
%>
<script language="javascript" type="text/javascript" runat="server">
	var exists=function(s,b){return b?(/BUILD_[A-Z]+/.test(s)?s:false):false;};
</script>
<!--#include file="admin_header.asp"-->
<%
' unrelated, hundreds of lines away in the real file
Function Calc(expr)
	Calc = eval(expr)
End Function
%>`
	got := ruleMatchesNamedFile(t, "YT.Config.asp", src)
	if got["kb:yara/asp_jscript_server_webshell"] {
		t.Fatalf("a server JScript helper plus an unrelated Request and an unrelated eval is not a "+
			"webshell; the request must reach the sink: %v", got)
	}
}

func TestASPXSQLExecRuleStillMatches(t *testing.T) {
	src := `<%@ Page Language="C#" %>
<% var c = new SqlConnection(txtConnection.Text);
   var cmd = new SqlCommand(txtSql.Text, c);
   cmd.ExecuteNonQuery(); %>`
	got := ruleMatchesNamedFile(t, "sql.aspx", src)
	if !got["kb:yara/asp_sql_exec_webshell"] {
		t.Fatalf("want asp_sql_exec_webshell on ASPX SqlCommand shell, got %v", got)
	}
}

func TestASPXActiveXShellStillMatchesClassicASPRule(t *testing.T) {
	src := `<%@ Page Language="C#" %>
<% var command = Request.Item["cmd"];
   var r = new ActiveXObject("WScript.Shell").Exec("cmd /c " + command); %>`
	got := ruleMatchesNamedFile(t, "xslt.aspx", src)
	if !got["kb:yara/classic_asp_shell"] {
		t.Fatalf("want classic_asp_shell on ASPX ActiveX/WScript command shell, got %v", got)
	}
}

func TestJavaDiskSemanticFindingViaScan(t *testing.T) {
	yr := yrPath()
	if yr == "" {
		t.Skip("yr binary not found")
	}
	dir := t.TempDir()
	src := `<% String c=request.getParameter("cmd"); Runtime.getRuntime().exec(c); %>`
	if err := os.WriteFile(filepath.Join(dir, "semantic.jsp"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	findings, _, failed, _ := scanWithDeobf(context.Background(), yr, rulesDir(), false, []string{dir}, "T", javadisk.DefaultOptions())
	if len(failed) > 0 {
		t.Skip("yr scan blocked (AV/OS) on temp files")
	}
	got := map[string]bool{}
	for _, f := range findings {
		got[f.Detection.KnowledgeRef] = true
	}
	if !got["javadisk:request-exec"] {
		t.Fatalf("want javadisk:request-exec, got %v", got)
	}
}

// Guards the full path: rule match AND language gate. A build without ctxPerl in inferFileContext
// silently discards every Perl match (langCompatible falls to `ctx != ctxUnknown`), which is exactly
// what the stale bin/ bundle did — 0 Perl findings with no error.
func TestPerlCmdExecRuleSurvivesTheLanguageGate(t *testing.T) {
	mal := ruleMatchesNamedFile(t, "shell.pl", `#!/usr/bin/perl
use CGI;
my $q = CGI->new;
my $cmd = $q->param('cmd');
print "Content-type: text/html\n\n";
print system($cmd);
`)
	if !mal["kb:yara/perl_cmd_exec_webshell"] {
		t.Fatalf("want perl_cmd_exec_webshell on CGI param -> system(), got %v", mal)
	}
	// Benign: an exec sink with no request source must NOT match.
	ben := ruleMatchesNamedFile(t, "build.pl", `#!/usr/bin/perl
system("make all");
`)
	if ben["kb:yara/perl_cmd_exec_webshell"] {
		t.Fatalf("false positive on constant-arg system() with no request source: %v", ben)
	}
}

// .cgi is genuinely ambiguous between Perl and Python, so BOTH languages' rules must be allowed to
// fire on it. A gate that picked one language would blind the other on every .cgi shell.
func TestPerlRuleFiresOnAmbiguousCgiExtension(t *testing.T) {
	mal := ruleMatchesNamedFile(t, "shell.cgi", "#!/usr/bin/perl\nprint \"Content-type: text/html\\n\\n\";\nmy $c = $ENV{'QUERY_STRING'};\nprint `$c`;\n")
	if !mal["kb:yara/perl_cmd_exec_webshell"] {
		t.Fatalf("want perl_cmd_exec_webshell on .cgi QUERY_STRING -> backtick, got %v", mal)
	}
}

func TestPythonCmdExecRuleSurvivesTheLanguageGate(t *testing.T) {
	mal := ruleMatchesNamedFile(t, "shell.py", `import cgi, subprocess
form = cgi.FieldStorage()
cmd = form.getvalue("cmd")
print(subprocess.check_output(cmd, shell=True))
`)
	if !mal["kb:yara/python_cmd_exec_webshell"] {
		t.Fatalf("want python_cmd_exec_webshell on FieldStorage -> subprocess, got %v", mal)
	}
	// Benign: ordinary automation reading os.environ["PATH"] and shelling out with a constant.
	// This shape false-positived 98 Python stdlib files before the source pattern was tightened to
	// CGI meta-variables; it must stay clean.
	ben := ruleMatchesNamedFile(t, "tool.py", `import os, subprocess
p = os.environ["PATH"]
subprocess.run(["ls", "-la"])
`)
	if ben["kb:yara/python_cmd_exec_webshell"] {
		t.Fatalf("false positive on os.environ['PATH'] + constant-arg subprocess: %v", ben)
	}
}

// A Perl rule must not fire on a Python file and vice versa — the gate's whole job.
func TestPerlAndPythonRulesDoNotLeakAcrossLanguages(t *testing.T) {
	onPy := ruleMatchesNamedFile(t, "x.py", `#!/usr/bin/perl
my $c = $ENV{'QUERY_STRING'};
system($c);
`)
	if onPy["kb:yara/perl_cmd_exec_webshell"] {
		t.Fatalf("perl rule leaked onto a .py file: %v", onPy)
	}
	onPl := ruleMatchesNamedFile(t, "x.pl", `import cgi, os
form = cgi.FieldStorage()
os.system(form.getvalue("c"))
`)
	if onPl["kb:yara/python_cmd_exec_webshell"] {
		t.Fatalf("python rule leaked onto a .pl file: %v", onPl)
	}
}
