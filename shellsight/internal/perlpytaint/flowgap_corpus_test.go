package perlpytaint

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The question T101's CGI review left open for phase 5, answered.
//
// `sourceExpr` recognises `<STDIN>` but not `read(STDIN, $buf, $ENV{CONTENT_LENGTH})`, which is the
// canonical Perl CGI POST idiom (RFC 3875 section 4.2). Counted over the 24 real samples, that form
// appears in 10 of them -- and all ten ALSO carry a source the pass already recognises, so at FILE
// level adding it gains nothing. The open question was whether it is also inert at FLOW level: a
// file can carry $ENV{QUERY_STRING} in one code path while the payload arrives through
// read(STDIN,...) in another, and only running the pass can tell.
//
// This test is the measurement. It reports, per real sample, whether a body read is present and
// what the pass actually finds. Skipped without the corpus, like every other corpus test here.
func TestBodyReadSourceGapOnTheRealCorpus(t *testing.T) {
	root := os.Getenv("SHELLSIGHT_CORPUS")
	if root == "" {
		root = filepath.Join("..", "..", "..", "shellsight-corpus")
	}
	base := filepath.Join(root, "curated", "disk", "perl-python")
	if _, err := os.Stat(base); err != nil {
		t.Skip("corpus not present on this machine")
	}
	bodyRead := regexp.MustCompile(
		`\b(?:read|sysread)\s*\(\s*STDIN\s*,|\bsys\.stdin\s*\.\s*(?:read|buffer)`)

	var withBody, withBodyNothingFound []string
	for _, lang := range []string{"perl", "python", "cgi"} {
		entries, err := os.ReadDir(filepath.Join(base, lang))
		if err != nil {
			continue
		}
		for _, e := range entries {
			p := filepath.Join(base, lang, e.Name())
			data, err := os.ReadFile(p)
			if err != nil {
				continue
			}
			found := Analyze(data, lang)
			var sinks []string
			for _, f := range found {
				sinks = append(sinks, f.Rule+":"+strings.TrimSpace(f.Evidence))
			}
			sort.Strings(sinks)
			body := bodyRead.Match(data)
			if body {
				withBody = append(withBody, e.Name())
				if len(found) == 0 {
					withBodyNothingFound = append(withBodyNothingFound, e.Name())
				}
			}
			t.Logf("%-7s %-32s body-read=%-5v findings=%d", lang, e.Name(), body, len(found))
		}
	}
	t.Logf("samples containing a CGI body read: %d", len(withBody))
	t.Logf("  of which the pass currently finds NOTHING: %d %v",
		len(withBodyNothingFound), withBodyNothingFound)

	// Not an assertion about the answer -- an assertion that the answer stays visible. If a future
	// change makes a body-read sample findable, or unfindable, this count moves and the log says so.
	if len(withBody) == 0 {
		t.Skip("no body-read sample in the corpus on this machine")
	}
}
