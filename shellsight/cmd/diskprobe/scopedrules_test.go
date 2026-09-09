package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"shellsight/internal/weblang"
)

// TestTheTwoFormerlyHardcodedRulesStayScoped replaces TestRuleCompatibleKnownNoisyRules.
//
// `ruleCompatible` used to hard-code two identifiers -- asp_html_hybrid_webshell and
// asp_jscript_server_webshell -- to ASP/ASPX, because they were measured badly cross-language:
// asp_jscript_server_webshell alone supplied 23 of the 24 .NET benign false positives in the
// 2026-08-07 A/B. That branch is now DELETED, because both rules declare
// `shellsight_lang = "asp-family"` and the declared-language path returns before the identifier
// switch could be reached. It was unreachable code asserting a live guarantee.
//
// The old test constructed `yaraxRuleMatch{Identifier: ...}` with NO metadata, so it passed only
// because of that branch and said nothing about what the rules actually declare. This one reads the
// shipped rule tree, so deleting a declaration from either rule fails here.
func TestTheTwoFormerlyHardcodedRulesStayScoped(t *testing.T) {
	declared := declaredLangOfShippedRule(t,
		"asp_html_hybrid_webshell", "asp_jscript_server_webshell")

	mustRefuse := []string{
		filepath.FromSlash("C:/tomcat/webapps/ROOT/view.jsp"),
		filepath.FromSlash("C:/web/a.php"),
		filepath.FromSlash("C:/web/x.pl"),
		filepath.FromSlash("C:/web/index.html"),
	}
	mustAccept := []string{
		filepath.FromSlash("C:/inetpub/wwwroot/legacy.asp"),
		filepath.FromSlash("C:/inetpub/wwwroot/page.aspx"),
		filepath.FromSlash("C:/inetpub/wwwroot/web.config"),
	}

	for name, lang := range declared {
		if lang == "" {
			t.Errorf("%s declares no language; it is measured cross-language and must stay scoped", name)
			continue
		}
		for _, p := range mustRefuse {
			if langCompatible(lang, inferFileContext(p)) {
				t.Errorf("%s (declares %q) is compatible with %s; it must not be", name, lang, p)
			}
		}
		for _, p := range mustAccept {
			if !langCompatible(lang, inferFileContext(p)) {
				t.Errorf("%s (declares %q) must stay compatible with %s", name, lang, p)
			}
		}
	}
}

// declaredLangOfShippedRule reads `shellsight_lang` for the named rules out of the real rule tree.
func declaredLangOfShippedRule(t *testing.T, names ...string) map[string]string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(rulesDir(), "own", "shellsight-heuristics.yar"))
	if err != nil {
		t.Skipf("rule tree unreadable: %v", err)
	}
	text := strings.ReplaceAll(string(data), "\r\n", "\n")
	out := map[string]string{}
	for _, name := range names {
		i := strings.Index(text, "rule "+name+" {")
		if i < 0 {
			t.Errorf("rule %s not found in the shipped tree", name)
			continue
		}
		body := text[i:]
		if j := strings.Index(body, "\n    strings:"); j > 0 {
			body = body[:j]
		}
		lang := ""
		for _, line := range strings.Split(body, "\n") {
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "shellsight_lang") {
				continue
			}
			if k := strings.Index(line, `"`); k >= 0 {
				if l := strings.LastIndex(line, `"`); l > k {
					lang = strings.ToLower(line[k+1 : l])
				}
			}
		}
		out[name] = lang
	}
	return out
}

// declaredWeblangs and langCompatible describe the same grouping in two forms -- one for the sign
// gate, one for the recognised-extension gate. They must not drift: a language present in one and
// absent from the other means a rule is admitted by content but refused by name, or the reverse.
func TestDeclaredWeblangsMirrorsLangCompatible(t *testing.T) {
	ctxFor := map[weblang.Lang]fileContext{
		weblang.PHP: ctxPHP, weblang.JSP: ctxJSP, weblang.ASP: ctxASP, weblang.ASPX: ctxASPX,
		weblang.Perl: ctxPerl, weblang.Python: ctxPython, weblang.CGI: ctxCGI,
		weblang.Shtml: ctxShtml,
	}
	for _, lang := range []string{
		"php", "jsp", "java", "asp", "aspx", "dotnet", "asp-family", "web-generic",
		"perl", "python", "shtml",
	} {
		got := declaredWeblangs(lang)
		if len(got) == 0 {
			t.Errorf("declaredWeblangs(%q) is empty; a recognised value must name at least one language", lang)
			continue
		}
		for _, wl := range got {
			ctx, ok := ctxFor[wl]
			if !ok {
				t.Errorf("declaredWeblangs(%q) names %q, which has no file context", lang, wl)
				continue
			}
			if !langCompatible(lang, ctx) {
				t.Errorf("declaredWeblangs(%q) names %q but langCompatible refuses its context %q "+
					"-- the two gates disagree", lang, wl, ctx)
			}
		}
	}
	// An unrecognised value names nothing for the sign gate: there is no content test to run when
	// we do not know what the author meant.
	if got := declaredWeblangs("madeup"); len(got) != 0 {
		t.Errorf("declaredWeblangs(madeup) = %v, want empty", got)
	}
}
