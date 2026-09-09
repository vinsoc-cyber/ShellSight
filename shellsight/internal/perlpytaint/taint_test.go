package perlpytaint

import (
	"strings"
	"testing"
)

// Source-to-sink taint for Perl and Python, as a CONFIRMED-BAND ESCALATOR.
//
// Measured in docs/measurements/2026-08-18-perl-python-taint. The shipped rules fire on
// `(any sink) AND (any source)` anywhere in the file, which produces 14 of the 20 benign false
// positives: defaulttags.py has `eval(` at line 326 and `request.GET` at line 1294; server.py has
// `subprocess.Popen(` at line 14 and `QUERY_STRING` at line 1134. Sink and source are unrelated code.
//
// This pass does NOT replace those rules -- prototyped against the corpus it reaches 9/24 real
// samples against their 21/24, because real shells route request data through parameter-parsing
// subs that a parser-free pass cannot follow without tainting so broadly that the precision is lost.
// What it does instead is supply the evidence for the `confirmed` band, which on these languages is
// currently empty: 2 of 24 real samples and 0 of 1,008 synthetic reach >=85 today. Prototyped, this
// signal carries 1,104 synthetic detections at 5 false positives in 5,592 benign files.
//
// Prior art: WTA (Applied Sciences 11(16):7763, 2021) -- taint from externally imported sources to
// dangerous-function sinks. WTA is interprocedural over ZendVM Oplines; neither Perl nor Python has
// a pure-Go parser, so this is deliberately the intraprocedural, flow-insensitive approximation.

func ruleSet(fs []Finding) map[string]bool {
	out := map[string]bool{}
	for _, f := range fs {
		out[f.Rule] = true
	}
	return out
}

// --- the positive cases -------------------------------------------------------------------------

func TestPerlDirectSourceToSystem(t *testing.T) {
	src := []byte("#!/usr/bin/perl\nmy $CMD = $ENV{'QUERY_STRING'};\nsystem($CMD);\n")
	got := Analyze(src, "perl")
	if len(got) == 0 {
		t.Fatalf("no finding for a direct QUERY_STRING -> system() flow")
	}
}

func TestPythonDirectSourceToOsSystem(t *testing.T) {
	src := []byte("import cgi\ncmd = cgi.FieldStorage().getvalue(\"c\")\nimport os\nos.system(cmd)\n")
	if len(Analyze(src, "python")) == 0 {
		t.Fatalf("no finding for a direct FieldStorage -> os.system flow")
	}
}

func TestTaintPropagatesThroughAnIntermediateVariable(t *testing.T) {
	src := []byte("my $a = $ENV{'QUERY_STRING'};\nmy $b = $a;\nsystem($b);\n")
	if len(Analyze(src, "perl")) == 0 {
		t.Fatalf("taint did not propagate through an intermediate assignment")
	}
}

func TestTaintPropagatesThroughStringInterpolation(t *testing.T) {
	src := []byte("my $c = $ENV{'QUERY_STRING'};\nmy $cmd = \"ls $c\";\nsystem($cmd);\n")
	if len(Analyze(src, "perl")) == 0 {
		t.Fatalf("taint did not survive interpolation into another string")
	}
}

func TestPerlHashElementIsTaintedWhenTheHashIs(t *testing.T) {
	// list.pl's shape: %FORM = parse_parameters($ENV{'QUERY_STRING'}); ... $FORM{'path'}
	src := []byte("my %FORM = parse_parameters($ENV{'QUERY_STRING'});\nsystem($FORM{'cmd'});\n")
	if len(Analyze(src, "perl")) == 0 {
		t.Fatalf("hash-element access did not inherit the hash's taint")
	}
}

func TestPythonSubprocessSink(t *testing.T) {
	src := []byte("from flask import request\ncmd = request.args.get('c')\n" +
		"import subprocess\nsubprocess.Popen(cmd, shell=True)\n")
	if len(Analyze(src, "python")) == 0 {
		t.Fatalf("no finding for request.args -> subprocess.Popen")
	}
}

func TestPerlBacktickSink(t *testing.T) {
	src := []byte("my $c = $ENV{'QUERY_STRING'};\nmy $out = `$c`;\nprint $out;\n")
	if len(Analyze(src, "perl")) == 0 {
		t.Fatalf("no finding for a tainted backtick")
	}
}

// --- the negative cases, which are the entire point ---------------------------------------------

func TestNoFindingWhenTheSinkArgumentIsNotTainted(t *testing.T) {
	// This is the co-occurrence false positive in miniature: both a source and a sink are present,
	// and they have nothing to do with each other.
	src := []byte("my $x = $ENV{'QUERY_STRING'};\nprint $x;\nsystem(\"ls -la\");\n")
	if got := Analyze(src, "perl"); len(got) != 0 {
		t.Fatalf("flagged an untainted sink: %+v", got)
	}
}

func TestNoFindingForADistantUnrelatedSourceAndSink(t *testing.T) {
	// Shaped like defaulttags.py: eval() early, request.GET ~970 lines later.
	var b strings.Builder
	b.WriteString("import os\nos.system('ls')\n")
	for i := 0; i < 400; i++ {
		b.WriteString("x = 1\n")
	}
	b.WriteString("from django.http import request\nval = request.GET.get('q')\nprint(val)\n")
	if got := Analyze([]byte(b.String()), "python"); len(got) != 0 {
		t.Fatalf("flagged an unrelated distant source/sink pair: %+v", got)
	}
}

func TestNoFindingWithASinkAndNoSourceAtAll(t *testing.T) {
	if got := Analyze([]byte("import os\nos.system('ls -la')\n"), "python"); len(got) != 0 {
		t.Fatalf("flagged a sink with no request source: %+v", got)
	}
}

func TestNoFindingWithASourceAndNoSink(t *testing.T) {
	if got := Analyze([]byte("my $x = $ENV{'QUERY_STRING'};\nprint $x;\n"), "perl"); len(got) != 0 {
		t.Fatalf("flagged a source with no sink: %+v", got)
	}
}

// A variable that merely shares a name prefix with a tainted one must not inherit taint.
func TestNamePrefixDoesNotLeakTaint(t *testing.T) {
	src := []byte("my $cmd = $ENV{'QUERY_STRING'};\nsystem($cmdline);\n")
	if got := Analyze(src, "perl"); len(got) != 0 {
		t.Fatalf("taint leaked from $cmd to $cmdline: %+v", got)
	}
}

// --- contract -----------------------------------------------------------------------------------

func TestFindingScoresInTheConfirmedBand(t *testing.T) {
	got := Analyze([]byte("my $c = $ENV{'QUERY_STRING'};\nsystem($c);\n"), "perl")
	if len(got) == 0 {
		t.Fatalf("expected a finding")
	}
	for _, f := range got {
		if f.Score < 85 {
			t.Fatalf("this pass exists to supply CONFIRMED-band evidence; got score %d", f.Score)
		}
	}
}

func TestFindingCarriesRuleAndEvidence(t *testing.T) {
	got := Analyze([]byte("my $c = $ENV{'QUERY_STRING'};\nsystem($c);\n"), "perl")
	if len(got) == 0 {
		t.Fatalf("expected a finding")
	}
	f := got[0]
	if !strings.HasPrefix(f.Rule, "perlpytaint:") {
		t.Fatalf("rule must be a namespaced knowledge-ref, got %q", f.Rule)
	}
	if f.Evidence == "" {
		t.Fatalf("finding carries no evidence string")
	}
	if !strings.Contains(f.Evidence, "system") {
		t.Fatalf("evidence should name the sink reached; got %q", f.Evidence)
	}
}

func TestOneFindingPerSinkKindNotPerOccurrence(t *testing.T) {
	src := []byte("my $c = $ENV{'QUERY_STRING'};\nsystem($c);\nsystem($c);\nsystem($c);\n")
	if got := Analyze(src, "perl"); len(got) != 1 {
		t.Fatalf("expected one finding for three identical sinks, got %d", len(got))
	}
}

func TestUnknownLanguageAnalysesNothing(t *testing.T) {
	if got := Analyze([]byte("my $c = $ENV{'QUERY_STRING'};\nsystem($c);\n"), "ruby"); len(got) != 0 {
		t.Fatalf("analysed an unsupported language: %+v", got)
	}
}

func TestEmptyInput(t *testing.T) {
	if got := Analyze(nil, "perl"); len(got) != 0 {
		t.Fatalf("expected no findings for empty input")
	}
}

// Input is attacker-controlled, so the fixpoint must terminate and the pass must stay bounded.
func TestTerminatesOnPathologicalInput(t *testing.T) {
	var b strings.Builder
	b.WriteString("my $a0 = $ENV{'QUERY_STRING'};\n")
	for i := 0; i < 20000; i++ {
		b.WriteString("my $a" + string(rune('a'+i%26)) + " = $a0;\n")
	}
	b.WriteString("system($a0);\n")
	_ = Analyze([]byte(b.String()), "perl") // must return, not hang
}

func TestVeryLargeInputIsSkipped(t *testing.T) {
	big := make([]byte, maxInput+1)
	for i := range big {
		big[i] = 'a'
	}
	if got := Analyze(big, "perl"); len(got) != 0 {
		t.Fatalf("did not skip an oversized file")
	}
}

// --- interprocedural summary --------------------------------------------------------------------
//
// The dominant reason real shells stay below `confirmed`: request data is parsed into a hash inside
// a subroutine, and used at a sink in the caller. Measured on the corpus this is the single largest
// miss class, and it is the standard CGI idiom rather than an exotic form.
//
// The summary is deliberately NARROWER than the prototype's, which tainted every name assigned
// inside any source-touching sub and cost 12 extra false positives. This one runs the same fixpoint
// INSIDE the body and exports only the names that actually became tainted there.

func TestSummaryExportsAHashFilledFromRequestDataInASub(t *testing.T) {
	// GO.cgi.pl's exact shape.
	src := []byte(`sub read_param {
$buffer = "$ENV{'QUERY_STRING'}";
@pairs = split(/&/, $buffer);
foreach $pair (@pairs) {
  ($name, $value) = split(/=/, $pair);
  $param{$name} = $value;
}
}
&read_param();
open(FILEHANDLE, "cd $param{dir}&&$param{cmd}|");
`)
	if len(Analyze(src, "perl")) == 0 {
		t.Fatalf("hash filled from the request inside a sub did not reach the caller's sink")
	}
}

func TestSummaryDoesNotExportUntaintedLocalsOfASourceTouchingSub(t *testing.T) {
	// $tmp is local scaffolding in a sub that also reads the request. Exporting it -- which the
	// broad version did -- taints the caller's unrelated sink and buys false positives.
	src := []byte(`sub handler {
my $q = $ENV{'QUERY_STRING'};
my $tmp = "/var/log/app.log";
print $q;
}
system($tmp);
`)
	if got := Analyze(src, "perl"); len(got) != 0 {
		t.Fatalf("exported an untainted local from a source-touching sub: %+v", got)
	}
}

func TestSummaryIgnoresSubsThatNeverTouchRequestData(t *testing.T) {
	src := []byte(`sub helper {
my $path = "/etc/passwd";
$cfg{file} = $path;
}
system($cfg{file});
`)
	if got := Analyze(src, "perl"); len(got) != 0 {
		t.Fatalf("exported from a sub with no request source: %+v", got)
	}
}

func TestPythonFunctionSummary(t *testing.T) {
	src := []byte(`import cgi
def parse():
    global cmd
    cmd = cgi.FieldStorage().getvalue("c")

parse()
import os
os.system(cmd)
`)
	if len(Analyze(src, "python")) == 0 {
		t.Fatalf("python function summary did not export the tainted global")
	}
}

func TestSummaryTerminatesOnUnbalancedBraces(t *testing.T) {
	// Perl bodies are brace-matched without a parser, so malformed or string-embedded braces must
	// not run away or hang.
	src := []byte("sub broken {\nmy $q = $ENV{'QUERY_STRING'};\nprint \"{{{{\";\nsystem($q);\n")
	_ = Analyze(src, "perl") // must return
}

func TestPerlForeachBindsTaintFromAList(t *testing.T) {
	src := []byte("my @args = split(/&/, $ENV{'QUERY_STRING'});\nforeach my $a (@args) {\n  system($a);\n}\n")
	if len(Analyze(src, "perl")) == 0 {
		t.Fatalf("foreach did not bind taint from a tainted list")
	}
}

func TestPythonForInBindsTaintFromAnIterable(t *testing.T) {
	src := []byte("import cgi\nvals = cgi.FieldStorage().getvalue('c')\nimport os\nfor v in vals:\n    os.system(v)\n")
	if len(Analyze(src, "python")) == 0 {
		t.Fatalf("for-in did not bind taint from a tainted iterable")
	}
}

func TestElementAssignmentTaintsItsContainer(t *testing.T) {
	src := []byte("my $q = $ENV{'QUERY_STRING'};\n$store{key} = $q;\nsystem($store{key});\n")
	if len(Analyze(src, "perl")) == 0 {
		t.Fatalf("assignment to a hash element did not taint the container")
	}
}

func TestAnUntaintedLoopDoesNotTaintItsVariable(t *testing.T) {
	src := []byte("my @files = ('a', 'b');\nforeach my $f (@files) {\n  system($f);\n}\nmy $q = $ENV{'QUERY_STRING'};\n")
	if got := Analyze(src, "perl"); len(got) != 0 {
		t.Fatalf("loop over a clean list produced taint: %+v", got)
	}
}

// A METHOD named eval is not Python's eval(). django's defaulttags.py calls
// `condition.eval(context)` on a template object; reading that as the builtin promoted a template
// evaluator to a confirmed webshell.
func TestMethodCalledEvalIsNotTheBuiltin(t *testing.T) {
	src := []byte("from django.http import request\nargs = [request.GET]\n" +
		"for d in args:\n    match = condition.eval(d)\n")
	if got := Analyze(src, "python"); len(got) != 0 {
		t.Fatalf("treated a method named eval as the builtin: %+v", got)
	}
}

func TestBareEvalIsStillASink(t *testing.T) {
	src := []byte("from flask import request\ncmd = request.args.get('c')\neval(cmd)\n")
	if len(Analyze(src, "python")) == 0 {
		t.Fatalf("bare eval() is still a sink and must fire")
	}
}

// Declaring a function named like a sink is not calling it. django's defaulttags.py has
// `def eval(self, context):`, whose parameter list was read as a tainted argument list.
func TestFunctionDefinitionNamedLikeASinkIsNotACall(t *testing.T) {
	src := []byte("from flask import request\ncontext = request.args\nclass C:\n    def eval(self, context):\n        return 1\n")
	if got := Analyze(src, "python"); len(got) != 0 {
		t.Fatalf("treated a def named eval as a call: %+v", got)
	}
}

func TestPerlSubDefinitionNamedLikeASinkIsNotACall(t *testing.T) {
	src := []byte("my $q = $ENV{'QUERY_STRING'};\nsub system { my $q = shift; return $q; }\n")
	if got := Analyze(src, "perl"); len(got) != 0 {
		t.Fatalf("treated a sub named system as a call: %+v", got)
	}
}
