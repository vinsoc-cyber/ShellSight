package asptaint

import (
	"fmt"
	"regexp"
	"strings"
)

// Request-derived CONTENT written to a file.
//
// WHY THIS IS A SEPARATE PASS FROM `sinks`. Every sink in that table is a single statement whose
// ARGUMENT must be tainted. A dropper is not one statement and its tainted value is not the path:
//
//	shell = request("txt")
//	Set TextFile = FileObject.CreateTextFile(Server.MapPath("up1oad.asp"))
//	TextFile.Write(shell)
//
// The destination is a fixed literal and the content is what the attacker supplies, so the handle
// has to be carried from where it was opened to where it is written. `taxonomy/asp.yaml` predicted
// exactly this on accepted gap item 7059d529604f169c: "a detector keyed on a tainted PATH still
// misses it: the destination is FIXED and what is tainted is the CONTENT."
//
// WHY NOT THE OBVIOUS PREDICATE INSTEAD. "A file operation on a request-derived PATH" was measured
// on perl/python on 2026-08-18 and DECLINED at precision 0.053 (2 new true positives against 36
// benign), because a file manager is behaviourally indistinguishable from a framework upload
// handler. Re-measured on Classic ASP's own pools on 2026-09-06 it confirms: 2 new true positives
// against 21 benign, precision 0.087. Per-sink decomposition found only `SaveToFile` earning
// anything, and receiver-gating that to ADODB.Stream cut the false positives 8->2 while dropping
// the real true positives to ZERO. That predicate is not built here and should not be.
//
// WHAT IS BUILT, AND WHAT IT COST, measured over the 1,144 benign real Classic ASP rows and the
// rows ShellSight missed at the time (2026-09-06):
//
//	tier A -- destination is server-executable, or the destination itself is request-derived:
//	          3 real + 64 generated new detections, 0 false positives.  precision 1.000
//	tier B -- any destination:
//	          21 real + 196 generated new detections, 9 false positives. precision 0.700 on real
//
// The two tiers are ONE analysis with one gate between them, not two detectors, because B is A with
// a looser destination test and shipping them apart would cost two full re-measurement cycles.
//
// PRIOR ART, and this is a reuse rather than an invention: the same method already ships here for
// two other languages and was validated on their corpora -- `javadisk:file-drop-on-request`
// ("writes request-controlled data to executable web/class path", score 85, family FileDrop) and
// `phptaint:arbitrary-file-write` (score 85, family FileDrop). Java's version binds a writer to an
// executable path and asks whether the written data is input-controlled; this is that, in VBScript.
// The family name is deliberately the same so a cross-language triage groups them.
var (
	// `Set h = <obj>.CreateTextFile(dest, ...)`. The receiver is not gated on a ProgID: unlike
	// `.Eval(` or `.Run(`, these are not ordinary method names that collide with application code,
	// and requiring the FileSystemObject to be resolvable would hand the technique a free pass to
	// any assembled ProgID -- the same defeat `comObjects` exists to close.
	openForWriteRe = regexp.MustCompile(
		`(?i)^\s*Set\s+([A-Za-z_]\w*)\s*=\s*[A-Za-z_][\w.]*\s*\.\s*` +
			`(?:CreateTextFile|OpenTextFile|OpenAsTextStream)\s*\(\s*([^,)]+)`)

	// ADODB.Stream splits the two halves across statements: content arrives at `.Write`, the
	// destination only later at `.SaveToFile`. The receiver IS gated here, because `SaveToFile` is
	// a name applications genuinely define for themselves -- measured: 7 of the 8 benign hits for
	// an ungated `SaveToFile` were Z-BlogASP's own four-argument `Call SaveToFile(...)` helper and
	// one was that function's `Public Function SaveToFile(...)` definition, none of them ADO.
	saveToFileRe = regexp.MustCompile(`(?i)\b([A-Za-z_]\w*)\s*\.\s*SaveToFile\s*\(?\s*([^,)\n]+)`)

	// A write through a handle. VBScript permits the call with or without parentheses and shells
	// use both, so the argument is captured to end-of-statement and the taint test runs over it.
	writeThroughRe = regexp.MustCompile(
		`(?i)\b([A-Za-z_]\w*)\s*\.\s*(?:WriteLine|WriteText|WriteBlankLines|Write)\s*\(?\s*(\S[^\n]*)`)

	// Server-executable destinations. A page that writes attacker content to one of these is
	// planting code, which is what separates tier A from an application that caches a form value.
	// `.asa`/`.cer`/`.cdx` are Classic ASP's other server-parsed extensions and are handled by
	// asp.dll exactly as `.asp` is; omitting them is the narrow-routing mistake recorded against
	// the incumbent, whose shtml extension list is a single element.
	execDestRe = regexp.MustCompile(
		`(?i)\.(?:asp|asa|asax|ascx|ashx|asmx|aspx|cdx|cer|cshtml|vbhtml|php|phtml|jsp|jspx|` +
			`cgi|pl|pm|py|exe|dll|com|bat|cmd|vbs|js|jse|wsf|hta|war|jar)\b`)
)

// fileDrops reports request-derived content reaching a file write, tiered by destination.
func fileDrops(stmts []string, tainted map[string]bool, ids []int, owned []map[string]bool,
	objects map[string]string) []Finding {

	dest := map[string]string{}
	for _, stmt := range stmts {
		if m := openForWriteRe.FindStringSubmatch(stmt); m != nil {
			dest[strings.ToLower(m[1])] = m[2]
		}
		// The ADODB.Stream receiver is resolved through `comObjects`, which folds an assembled
		// ProgID -- so `Server.CreateObject(Chr(65) & "DODB.Stream")` binds exactly as a literal
		// does. Gating on a file-wide "ADODB.Stream" literal instead would be defeated by the same
		// assembly this package already closes for WScript.Shell.
		if m := saveToFileRe.FindStringSubmatch(stmt); m != nil {
			if objectIs(objects, m[1], progADODBStream) {
				dest[strings.ToLower(m[1])] = m[2]
			}
		}
	}
	if len(dest) == 0 {
		return nil
	}

	bestExec, evidence := false, ""
	found := false
	for i, stmt := range stmts {
		if isDeclaration(stmt) {
			continue
		}
		for _, m := range writeThroughRe.FindAllStringSubmatch(stmt, -1) {
			handle := strings.ToLower(m[1])
			d, ok := dest[handle]
			if !ok {
				continue
			}
			arg := m[2]
			if !sourceExpr.MatchString(arg) {
				argTainted := false
				for n := range namesIn(arg) {
					if tainted[key(ids[i], owned, n)] {
						argTainted = true
						break
					}
				}
				if !argTainted {
					continue
				}
			}
			// A request-derived destination counts as executable for tiering: the attacker chose
			// the path, so the extension is theirs to pick. That is the shape of accepted gap item
			// 1b7451ed70e836b4, whose own form field is labelled "absolute path to save the file
			// (including filename, e.g. D:\web\x.asp)".
			isExec := execDestRe.MatchString(d) || sourceExpr.MatchString(d)
			if !found || (isExec && !bestExec) {
				found, bestExec = true, isExec
				evidence = fmt.Sprintf("request-derived content written to %s via %s",
					trim(strings.TrimSpace(d), 60), trim(strings.TrimSpace(m[0]), 40))
			}
			if bestExec {
				break
			}
		}
	}
	if !found {
		return nil
	}
	if bestExec {
		return []Finding{{
			Score:    score,
			Family:   "FileDrop",
			Rule:     "asptaint:file-drop-on-request",
			Evidence: evidence,
		}}
	}
	return []Finding{{
		Score:    scoreFileWrite,
		Family:   "FileDrop",
		Rule:     "asptaint:request-content-file-write",
		Evidence: evidence,
	}}
}
