package ssitaint

import "testing"

// Every malicious string below is copied from one of the two real shtml samples in the corpus
// (gh:RubyRose281/HackTools .../ssishell.shtml and gh:itzBawantha/shtml-shell:shell.shtml), and
// every benign string from the 245 candidates harvested on 2026-09-07. Nothing here is invented,
// because a taint model designed against imagined syntax is a model of the imagination.

// ---------------------------------------------------------------------------------------------
// The flow both real samples use, and the one the shipped rule cannot distinguish from benign.

func TestSetFromQueryStringReachingExecCmd(t *testing.T) {
	// Verbatim from ssishell.shtml. Note the UNQUOTED attribute values on both edges.
	src := []byte(`<!--#config errmsg="[Error in shell]"-->
<!--#set var="zero" value="" -->
<!--#if expr="$QUERY_STRING_UNESCAPED = \$zero" -->
<!--#set var="shl" value="ls -al" -->
<!--#else -->
<!--#set var="shl" value=$QUERY_STRING_UNESCAPED -->
<!--#endif -->
<!--#exec cmd=$shl -->`)
	got := Analyze(src)
	if len(got) == 0 {
		t.Fatal("no finding: the flow both real samples use was not detected")
	}
	if got[0].Score < 85 {
		t.Errorf("score %d, want >=85 (confirmed band)", got[0].Score)
	}
	if got[0].Family != "SSIExec" {
		t.Errorf("family %q, want SSIExec", got[0].Family)
	}
}

func TestTaintedIncludeVirtual(t *testing.T) {
	src := []byte(`<!--#set var="inc" value=$QUERY_STRING_UNESCAPED -->
<!--#include virtual=$inc -->`)
	got := Analyze(src)
	if len(got) == 0 {
		t.Fatal("no finding for a tainted #include virtual (arbitrary file read / subrequest)")
	}
	if got[0].Family != "SSIInclude" {
		t.Errorf("family %q, want SSIInclude", got[0].Family)
	}
}

func TestSourceDirectlyInsideAQuotedSinkArgument(t *testing.T) {
	// gh:JoshData/thunderbird-spf -- legitimate software with a genuine injection. Apache
	// documents that substitution happens inside quoted attribute strings, so this is a flow.
	src := []byte(`<!--#exec cmd="dig +short -x $QUERY_STRING_UNESCAPED" -->`)
	if len(Analyze(src)) == 0 {
		t.Fatal("a source substituted directly into a quoted sink argument is still a flow")
	}
}

func TestMultiHopPropagation(t *testing.T) {
	src := []byte(`<!--#set var="a" value=$DOCUMENT_ARGS -->
<!--#set var="b" value="$a" -->
<!--#exec cmd=$b -->`)
	if len(Analyze(src)) == 0 {
		t.Fatal("taint must propagate through more than one #set")
	}
}

func TestPropagationWhenAssignmentsAreOutOfOrder(t *testing.T) {
	// The case that actually needs the fixpoint. With `b` declared BEFORE the `a` it depends on,
	// a single pass sees `b <- $a` while `a` is still clean and stops there. Declaration order is
	// not execution order in a document an attacker may also have edited, and the in-order version
	// of this test passes with one round -- so it was proving nothing about the loop.
	src := []byte(`<!--#set var="b" value="$a" -->
<!--#set var="a" value=$QUERY_STRING_UNESCAPED -->
<!--#exec cmd=$b -->`)
	if len(Analyze(src)) == 0 {
		t.Fatal("taint did not reach a fixpoint: out-of-order #set chain was missed")
	}
}

// ---------------------------------------------------------------------------------------------
// The benign hard cases. These are the whole reason the pass exists: the shipped YARA rule scores
// every one of them 80, identically to the real shells above.

func TestHardcodedExecIsNotAFlow(t *testing.T) {
	for _, tc := range []struct{ name, src string }{
		{"digi sdk log.cgi", `<!--#exec cmd="/log.cgi"--> `},
		{"digi sdk audit", `<!--#exec cmd="audit"--> `},
		{"nco openssl checksum", `<!--#exec cmd="openssl dgst -md5 src/nco-5.3.9.tar.gz"--> `},
		{"dcmi metawriter", `<!--#exec cgi="/cgi-bin/metawriter.cgi"--> `},
		{"chaperone ps", `<!--#exec cmd="ps -axf --width 100 -o pid,user,stat,cmd"--> `},
		{"fenris counter", `<!--#exec cgi="../count.cgi"--> `},
	} {
		if got := Analyze([]byte(tc.src)); len(got) != 0 {
			t.Errorf("%s: hardcoded command reported as a flow: %+v", tc.name, got[0])
		}
	}
}

func TestCoOccurrenceIsNotFlow(t *testing.T) {
	// The lesson recorded in perlpytaint: django's defaulttags.py has `eval(` at line 326 and
	// `request.GET` at line 1294. A source somewhere in the file and a sink somewhere else are
	// unrelated code sharing a document. Both real samples ECHO request-ish variables far from
	// their exec, so this case is live rather than hypothetical.
	src := []byte(`<!--#echo var=DOCUMENT_URI -->
<!--#echo var=QUERY_STRING_UNESCAPED -->
<p>hello</p>
<!--#exec cmd="/usr/bin/uptime" -->`)
	if got := Analyze(src); len(got) != 0 {
		t.Errorf("co-occurrence tainted an unrelated hardcoded sink: %+v", got[0])
	}
}

func TestServerMetadataIsNotASource(t *testing.T) {
	// Apache documents these as document/server metadata, not request data. DOCUMENT_NAME is the
	// filename; both real samples echo it benignly.
	for _, v := range []string{"DOCUMENT_NAME", "DATE_GMT", "DATE_LOCAL", "LAST_MODIFIED", "USER_NAME"} {
		src := []byte("<!--#set var=\"x\" value=$" + v + " -->\n<!--#exec cmd=$x -->")
		if got := Analyze(src); len(got) != 0 {
			t.Errorf("%s treated as a request source: %+v", v, got[0])
		}
	}
}

// ---------------------------------------------------------------------------------------------
// Syntax the vendor documents, which the field's published literal misses.

func TestSpacingAndCaseVariants(t *testing.T) {
	for _, src := range []string{
		`<!--#set var="s" value=$QUERY_STRING_UNESCAPED --><!--#exec cmd=$s -->`,
		`<!-- #SET VAR="s" VALUE=$QUERY_STRING_UNESCAPED --><!-- #EXEC CMD=$s -->`,
		`<!--  #  set  var = "s"  value = $QUERY_STRING_UNESCAPED  --><!--  #  exec  cmd = $s  -->`,
	} {
		if len(Analyze([]byte(src))) == 0 {
			t.Errorf("missed a documented spelling: %s", src)
		}
	}
}

func TestBraceVariableReference(t *testing.T) {
	src := []byte(`<!--#set var="s" value="${QUERY_STRING_UNESCAPED}" -->
<!--#exec cmd="${s}" -->`)
	if len(Analyze(src)) == 0 {
		t.Fatal("Apache's ${NAME} reference form was not followed")
	}
}

func TestCgiEnvironmentHeadersAreSources(t *testing.T) {
	// S9: "The include variables are available to the command, in addition to the usual set of
	// CGI variables." Independently confirms OWASP WSTG's "headers and cookies".
	for _, v := range []string{"HTTP_USER_AGENT", "HTTP_COOKIE", "HTTP_REFERER", "QUERY_STRING",
		"REQUEST_URI", "PATH_INFO", "DOCUMENT_PATH_INFO"} {
		src := []byte("<!--#set var=\"x\" value=$" + v + " -->\n<!--#exec cmd=$x -->")
		if len(Analyze(src)) == 0 {
			t.Errorf("%s not treated as a request source", v)
		}
	}
}

func TestAnyRequestHeaderIsASource(t *testing.T) {
	// The named HTTP_* entries above are all in the explicit map, so they exercise the map and not
	// the prefix rule -- deleting the prefix rule left that test green. A header nobody enumerated
	// is the case the prefix exists for, and an attacker picks the header.
	for _, v := range []string{"HTTP_X_CUSTOM_THING", "HTTP_ACCEPT_LANGUAGE", "HTTP_HOST"} {
		src := []byte("<!--#set var=\"x\" value=$" + v + " -->\n<!--#exec cmd=$x -->")
		if len(Analyze(src)) == 0 {
			t.Errorf("%s not treated as a request source; the HTTP_* prefix rule is not working", v)
		}
	}
}

// ---------------------------------------------------------------------------------------------
// Shape and bounds.

func TestNoDirectivesNoFindings(t *testing.T) {
	if got := Analyze([]byte("<html><body>plain page</body></html>")); len(got) != 0 {
		t.Errorf("findings on a page with no SSI at all: %+v", got)
	}
}

func TestEmptyAndOversizeInput(t *testing.T) {
	if got := Analyze(nil); len(got) != 0 {
		t.Errorf("findings on nil input: %+v", got)
	}
	big := make([]byte, maxInput+1)
	for i := range big {
		big[i] = 'a'
	}
	if got := Analyze(big); len(got) != 0 {
		t.Errorf("oversize input must be skipped, got %+v", got)
	}
}

func TestFindingCarriesEvidenceAndRule(t *testing.T) {
	got := Analyze([]byte(`<!--#set var="s" value=$QUERY_STRING_UNESCAPED --><!--#exec cmd=$s -->`))
	if len(got) == 0 {
		t.Fatal("no finding")
	}
	f := got[0]
	if f.Rule == "" {
		t.Error("Rule is empty; an operator cannot cite the finding")
	}
	if f.Evidence == "" {
		t.Error("Evidence is empty; the point of a taint finding is naming the flow")
	}
}

func TestOneFindingPerSinkNotPerSource(t *testing.T) {
	src := []byte(`<!--#set var="a" value=$QUERY_STRING_UNESCAPED -->
<!--#set var="b" value=$QUERY_STRING_UNESCAPED -->
<!--#exec cmd=$a -->`)
	if got := Analyze(src); len(got) != 1 {
		t.Errorf("want 1 finding for 1 reached sink, got %d", len(got))
	}
}

func TestManySinksOfOneFamilyCollapseToOneFinding(t *testing.T) {
	// The real shape, from shell.shtml: six variables set from the query string and FIVE separate
	// `#exec cmd` directives. The previous test has a single sink, so it passed with the dedupe
	// deleted and proved nothing. Reporting five identical findings would bury the one fact an
	// operator needs.
	src := []byte(`<!--#set var="a" value=$QUERY_STRING_UNESCAPED -->
<!--#set var="b" value=$QUERY_STRING_UNESCAPED -->
<!--#set var="c" value=$QUERY_STRING_UNESCAPED -->
<!--#exec cmd=$a -->
<!--#exec cmd=$b -->
<!--#exec cmd=$c -->`)
	if got := Analyze(src); len(got) != 1 {
		t.Errorf("want 1 SSIExec finding for 3 exec sinks, got %d", len(got))
	}
}

func TestBothFamiliesReportSeparately(t *testing.T) {
	// ssishell.shtml reaches both an exec sink and an include sink. They are different
	// capabilities -- command execution and arbitrary file read -- so collapsing across families
	// would lose one of them.
	src := []byte(`<!--#set var="s" value=$QUERY_STRING_UNESCAPED -->
<!--#exec cmd=$s -->
<!--#include virtual=$s -->`)
	got := Analyze(src)
	if len(got) != 2 {
		t.Fatalf("want 2 findings (SSIExec + SSIInclude), got %d", len(got))
	}
	fams := map[string]bool{got[0].Family: true, got[1].Family: true}
	if !fams["SSIExec"] || !fams["SSIInclude"] {
		t.Errorf("families %v, want SSIExec and SSIInclude", fams)
	}
}
