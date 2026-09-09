package asptaint

import (
	"regexp"
	"strings"
)

// ---- server-side <object> declarations ------------------------------------------------------
//
// `<OBJECT RUNAT="Server" SCOPE="Page" ID="x" CLASSID="clsid:...">` binds an identifier to a COM
// class exactly as `Server.CreateObject` does. Microsoft's reference gives the grammar as
//
//	<OBJECT RUNAT=Server SCOPE=Scope ID=Identifier {PROGID="progID"| CLASSID="ClassID"}>
//
// and states that "either ProgID or ClassID must be specified" and that "ClassID specifies a unique
// identifier for a COM class object" (Microsoft Learn, *OBJECT Declarations*, IIS 6.0 SDK,
// ms525754, retrieved 2026-09-06).
//
// WHY THIS NEEDS THE RAW TEXT AND NOT `stmts`, which is the actual root cause and not a missing
// table entry: `scriptRegions` keeps only what lies between `<%` and `%>`, so an object declaration
// in the HTML body is never part of a statement and never reaches `comObjects`. The receiver gate
// then rejects `oScript.Exec(request("cmd"))` because nothing bound `oScript` -- and a technique
// this package fully models scores 0.
//
// Measured 2026-09-06: 3 real Classic ASP samples that the incumbent catches and this package
// scored **0** on, all three of this shape, e.g.
//
//	<object runat=server id=oScriptlhn scope=page classid="clsid:72C24DD5-...-98424B88AFB8">
//	response.write oScriptlhn.exec("cmd.exe /c" & request("c")).stdout.readall
//
// THE CORPUS SAYS THIS IS THE FORM ATTACKERS USE. Of 936 server-side `<object runat=...>` tags
// across the Classic ASP trees, **936 declare CLASSID and 0 declare PROGID** -- the CLSID spelling
// is chosen precisely because it defeats matching on the ProgID string, which is the technique this
// package's ProgID folding already exists to defeat one level down. Both spellings are handled
// anyway: the vendor documents both, and the PROGID branch is free once the tag is parsed.
//
// FALSE-POSITIVE COST: none measured. No benign file in the ASP pool declares any CLSID below --
// swept over staging/benign-classic-asp, staging/langkit/asp-benign and both acquisition rounds'
// benign trees. The two benign files that do carry a `classid:` declare Flash and MSXML, neither of
// which is a sink this package gates.
var objectTagRe = regexp.MustCompile(`(?is)<\s*object\b([^>]{0,600})>`)

var (
	objRunatRe  = regexp.MustCompile(`(?i)\brunat\s*=\s*["']?\s*server\b`)
	objIDRe     = regexp.MustCompile(`(?i)\bid\s*=\s*["']?([A-Za-z_]\w*)`)
	objCLSIDRe  = regexp.MustCompile(`(?i)\bclassid\s*=\s*["']?\s*clsid:\s*\{?\s*([0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})`)
	objProgIDRe = regexp.MustCompile(`(?i)\bprogid\s*=\s*["']?([A-Za-z0-9_.]+)`)
)

// CLSID -> the ProgID this package already gates on. A CLSID is a registry identity an intruder
// cannot rename, which is what makes it as sound a gate as the ProgID it stands for. Each entry
// was verified against the component's own registration on 2026-09-06; the file each resolves to
// is named because that, not the GUID, is what makes the mapping checkable.
var objectCLSIDs = map[string]string{
	// wshom.ocx -- Windows Script Host Shell Object. Two CLSIDs, both shipped by the same control:
	// 72C24DD5 is the coclass and F935DC22 the WshShell class. Both appear in this corpus (446 and
	// 369 files), and a table with only one of them would miss 369 files.
	"72c24dd5-d70a-438b-8a42-98424b88afb8": progWScriptShell,
	"f935dc22-1cf0-11d0-adb9-00c04fd58a0b": progWScriptShell,
	// shell32.dll -- Shell Automation Service, the `Shell.Application` object. 26 files.
	"13709620-c279-11ce-a49e-444553540000": progShellApp,
	// msscript.ocx -- MSScriptControl.ScriptControl. Not observed in this corpus as an object tag,
	// and included because the ProgID form of the same sink IS observed and an attacker who moves
	// from one spelling to the other should not gain anything by it.
	"0e59f1d5-1fbe-11d0-8ff2-00a0d10038bc": progScriptCtl,
	// ADODB.Stream -- the binary-write half of a dropper, gated by filedrop.go's SaveToFile.
	"00000566-0000-0010-8000-00aa006d2ea4": progADODBStream,
}

// objectTagObjects binds identifiers declared by server-side <object> tags in the RAW page text.
//
// Returns the same shape as comObjects so the two merge, and deliberately does NOT report a tag
// without `runat=server`: a client-side <object> is markup the browser resolves, it instantiates
// nothing on the server, and treating it as a binding would let a page be flagged for an ActiveX
// control it merely embeds.
func objectTagObjects(text string) map[string]string {
	out := map[string]string{}
	for _, m := range objectTagRe.FindAllStringSubmatch(text, -1) {
		attrs := m[1]
		if !objRunatRe.MatchString(attrs) {
			continue
		}
		id := objIDRe.FindStringSubmatch(attrs)
		if id == nil {
			continue
		}
		if c := objCLSIDRe.FindStringSubmatch(attrs); c != nil {
			if prog, ok := objectCLSIDs[strings.ToLower(c[1])]; ok {
				out[strings.ToLower(id[1])] = prog
			}
			continue
		}
		if p := objProgIDRe.FindStringSubmatch(attrs); p != nil {
			out[strings.ToLower(id[1])] = strings.ToLower(p[1])
		}
	}
	return out
}
