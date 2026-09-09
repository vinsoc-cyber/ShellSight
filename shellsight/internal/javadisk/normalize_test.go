package javadisk

import (
	"strings"
	"testing"
)

func TestNormalizeJSPExtractsServerCodeAndDropsComments(t *testing.T) {
	src := []byte(`<%-- hidden Runtime.getRuntime().exec(request.getParameter("x")) --%>
<html><% String cmd = request.getParameter("cmd"); Runtime.getRuntime().exec(cmd); %></html>`)
	got := normalizeText("shell.jsp", src)
	if strings.Contains(got, "hidden Runtime") {
		t.Fatalf("JSP comments must be removed, got %q", got)
	}
	if !strings.Contains(got, `request.getParameter("cmd")`) || !strings.Contains(got, "Runtime.getRuntime().exec") {
		t.Fatalf("server code not preserved, got %q", got)
	}
}

func TestDecodeJavaEscapes(t *testing.T) {
	got := decodeJavaEscapes(`Runtime\u002egetRuntime()\u002eexec("cmd\x2ee\x78e")`)
	want := `Runtime.getRuntime().exec("cmd.exe")`
	if got != want {
		t.Fatalf("decodeJavaEscapes=%q want %q", got, want)
	}
}

func TestAnalyzeJSPXDocumentSyntax(t *testing.T) {
	src := []byte(`<jsp:root xmlns:jsp="http://java.sun.com/JSP/Page"><jsp:scriptlet>
		String cmd=request.getParameter(&quot;cmd&quot;); Runtime.getRuntime().exec(cmd);
	</jsp:scriptlet></jsp:root>`)
	findings := Analyze("shell.jspx", src)
	for _, finding := range findings {
		if finding.Rule == "javadisk:request-exec" {
			return
		}
	}
	t.Fatalf("findings=%+v", findings)
}

func TestJSPXDocumentSyntaxExtractsAllServerBodiesAndCDATA(t *testing.T) {
	src := []byte(`<jsp:root xmlns:jsp="http://java.sun.com/JSP/Page">
		<jsp:declaration><![CDATA[String prefix="cmd";]]></jsp:declaration>
		<div>Runtime.getRuntime().exec("ignored")</div>
		<jsp:expression>request.getParameter(&quot;x&quot;)</jsp:expression>
		<jsp:scriptlet><![CDATA[Runtime.getRuntime().exec(request.getParameter("x"));]]></jsp:scriptlet>
	</jsp:root>`)
	got := normalizeText("shell.jspx", src)
	for _, want := range []string{`String prefix="cmd";`, `request.getParameter("x")`, `Runtime.getRuntime().exec`} {
		if !strings.Contains(got, want) {
			t.Fatalf("normalizeText omitted %q: %q", want, got)
		}
	}
	if strings.Contains(got, "ignored") || strings.Contains(got, "<div>") {
		t.Fatalf("normalizeText retained template content: %q", got)
	}
}

func TestJSPXMalformedDocumentUsesCollectedPrefix(t *testing.T) {
	src := []byte(`<jsp:root xmlns:jsp="http://java.sun.com/JSP/Page"><jsp:scriptlet>
		Runtime.getRuntime().exec(request.getParameter(&quot;x&quot;));
	</jsp:scriptlet><broken`)
	findings := Analyze("shell.jspx", src)
	for _, finding := range findings {
		if finding.Rule == "javadisk:request-exec" {
			return
		}
	}
	t.Fatalf("findings=%+v", findings)
}

func TestJSPXMalformedDocumentWithoutBodyFallsBackToNormalizedText(t *testing.T) {
	src := []byte(`<jsp:root><broken <% Runtime.getRuntime().exec(request.getParameter("x")); %>`)
	got := normalizeText("shell.jspx", src)
	if !strings.Contains(got, "Runtime.getRuntime().exec") {
		t.Fatalf("malformed JSPX was normalized to empty text: %q", got)
	}
}

func TestJSPAliasesAreRecognized(t *testing.T) {
	for _, path := range []string{"shell.jsw", "shell.jsv", "shell.jhtml"} {
		if !isJSPPath(path) {
			t.Errorf("isJSPPath(%q)=false", path)
		}
	}
}
