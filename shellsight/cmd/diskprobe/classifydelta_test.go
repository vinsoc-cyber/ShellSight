package main

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// legacyInferFileContext is the pre-008 classifier, kept verbatim so the change can be MEASURED
// rather than asserted. It is test-only: nothing in the shipped binary calls it.
//
// It reads only the final suffix (`filepath.Ext`) and knows nothing of .phar, .jsw, .jsv, .jhtml,
// .asax, .cshtml, .vbhtml, .master, .svc or .cdx.
func legacyInferFileContext(path string) fileContext {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".php", ".php3", ".php4", ".php5", ".php7", ".phtml", ".pht", ".inc":
		return ctxPHP
	case ".jsp", ".jspx", ".jspf":
		return ctxJSP
	case ".asp", ".asa", ".cer":
		return ctxASP
	case ".aspx", ".ascx", ".ashx", ".asmx":
		return ctxASPX
	case ".pl", ".pm", ".plx", ".pl6":
		return ctxPerl
	case ".py", ".pyw", ".py3", ".pyi", ".pyp", ".pyx":
		return ctxPython
	case ".cgi", ".fcgi":
		return ctxCGI
	case ".shtml", ".shtm", ".stm":
		return ctxShtml
	case ".config":
		return ctxConfig
	case ".html", ".htm", ".js", ".css":
		return ctxStatic
	default:
		return ctxUnknown
	}
}

// The new classifier may only ever WIDEN: a file the old one understood must classify identically.
// This is the mechanical half of SC-004 -- it bounds the behaviour change to names the previous
// release did not recognise, over whatever corpus is present rather than over a handful of examples.
func TestClassificationOnlyWidens(t *testing.T) {
	root := corpusRootForClassifyDelta(t)
	changed := map[string]int{}
	var examples []string
	total := 0

	_ = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil //nolint:nilerr // an unreadable entry is not this test's business
		}
		total++
		old, now := legacyInferFileContext(p), inferFileContext(p)
		if old == now {
			return nil
		}
		if old != ctxUnknown {
			t.Errorf("NARROWED: %s was %q, is now %q -- a file the previous release understood "+
				"must classify identically (SC-004)", p, old, now)
			return nil
		}
		key := strings.ToLower(filepath.Ext(p)) + " -> " + string(now)
		changed[key]++
		if len(examples) < 12 {
			examples = append(examples, filepath.Base(p)+" ("+key+")")
		}
		return nil
	})

	keys := make([]string, 0, len(changed))
	for k := range changed {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	t.Logf("corpus files walked: %d", total)
	t.Logf("classification changed for %d distinct (extension -> context) pairs:", len(keys))
	for _, k := range keys {
		t.Logf("    %-28s %d file(s)", k, changed[k])
	}
	for _, e := range examples {
		t.Logf("    e.g. %s", e)
	}
}

// corpusRootForClassifyDelta locates the corpus, skipping when it is absent -- it is gitignored, so
// a clean clone has none and this test must not fail there.
func corpusRootForClassifyDelta(t *testing.T) string {
	t.Helper()
	for _, rel := range []string{
		filepath.Join("..", "..", "..", "shellsight-corpus", "curated"),
		filepath.Join("..", "..", "shellsight-corpus", "curated"),
	} {
		if st, err := os.Stat(rel); err == nil && st.IsDir() {
			return rel
		}
	}
	t.Skip("corpus not present (gitignored); classification delta not measured here")
	return ""
}
