package asptaint

import "testing"

// The <object runat="server"> binding, and why it was invisible.
//
// `scriptRegions` keeps only what lies between `<%` and `%>`. A server-side object declaration is
// in the HTML body, so it is not part of any statement, never reaches `comObjects`, and the
// receiver gate rejects a sink whose object the analysis never saw bound. The technique is fully
// modelled and scored 0 on three real corpus samples for that reason alone.

func TestObjectTag_CLSIDBindsWScriptShell(t *testing.T) {
	// Reduced from d0de79f0d3221c9c8 (583 B) and 8ee371812cfe177e2 (732 B), both real, both caught
	// by the incumbent and scored 0 here before this bound.
	src := `<object runat=server id=oScriptlhn scope=page classid="clsid:72C24DD5-D70A-438B-8A42-98424B88AFB8"></object>
<%
response.write oScriptlhn.exec("cmd.exe /c" & request("c")).stdout.readall
%>`
	got := Analyze([]byte(src))
	if len(got) == 0 {
		t.Fatalf("an object-tag-bound WScript.Shell reaching a request value must be reported")
	}
}

func TestObjectTag_TheSecondWScriptCLSIDAlsoBinds(t *testing.T) {
	// wshom.ocx registers two: 72C24DD5 (446 files in this corpus) and F935DC22 (369). A table
	// with only the first would miss 369 files, so the second is not decoration.
	src := `<object runat="server" id="sh" scope="page" classid="clsid:F935DC22-1CF0-11D0-ADB9-00C04FD58A0B"></object>
<% sh.Run request("cmd") %>`
	if len(Analyze([]byte(src))) == 0 {
		t.Fatalf("F935DC22 is the same control as 72C24DD5 and must bind identically")
	}
}

func TestObjectTag_ProgIDFormBinds(t *testing.T) {
	// Microsoft's grammar permits either spelling. Zero of this corpus's 936 server-side object
	// tags use PROGID -- attackers pick CLSID because it defeats ProgID string matching -- but the
	// vendor documents it and an attacker moving between spellings must gain nothing.
	src := `<object runat=server id=sh scope=page progid="WScript.Shell"></object>
<% sh.Exec request("c") %>`
	if len(Analyze([]byte(src))) == 0 {
		t.Fatalf("the documented PROGID spelling must bind as CLASSID does")
	}
}

func TestObjectTag_ClientSideTagDoesNotBind(t *testing.T) {
	// No runat=server: the browser resolves this and nothing is instantiated on the server.
	// Binding it would flag a page for an ActiveX control it merely embeds.
	src := `<object id=oScriptlhn classid="clsid:72C24DD5-D70A-438B-8A42-98424B88AFB8"></object>
<% response.write oScriptlhn.exec(request("c")) %>`
	for _, f := range Analyze([]byte(src)) {
		if f.Rule == "asptaint:sink-on-request" {
			t.Fatalf("a client-side <object> instantiates nothing server-side: %+v", f)
		}
	}
}

func TestObjectTag_UnknownCLSIDDoesNotBind(t *testing.T) {
	// Flash and MSXML are the CLSIDs the benign pool actually carries. An unmapped CLSID must not
	// bind to anything, or the gate becomes "any object tag at all".
	src := `<object runat=server id=x scope=page classid="clsid:D27CDB6E-AE6D-11CF-96B8-444553540000"></object>
<% x.Exec request("c") %>`
	for _, f := range Analyze([]byte(src)) {
		if f.Rule == "asptaint:sink-on-request" {
			t.Fatalf("an unmapped CLSID must not satisfy the receiver gate: %+v", f)
		}
	}
}

func TestObjectTag_LiteralArgumentIsStillNotAFinding(t *testing.T) {
	// The binding is a gate, not a signal. Binding the object must not by itself make a page a
	// finding -- the argument still has to be request-derived.
	src := `<object runat=server id=sh scope=page classid="clsid:72C24DD5-D70A-438B-8A42-98424B88AFB8"></object>
<% sh.Run "notepad.exe" %>`
	if len(Analyze([]byte(src))) != 0 {
		t.Fatalf("a literal argument is not a flow: %+v", Analyze([]byte(src)))
	}
}

func TestObjectTagObjects_IgnoresATagWithNoID(t *testing.T) {
	// Defensive: an object tag with no ID binds nothing and must not panic or bind the empty name.
	if got := objectTagObjects(`<object runat=server classid="clsid:72C24DD5-D70A-438B-8A42-98424B88AFB8">`); len(got) != 0 {
		t.Fatalf("a tag with no ID binds nothing, got %v", got)
	}
}
