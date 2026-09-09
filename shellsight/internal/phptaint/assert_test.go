package phptaint

// Spec 007 US4 / research R5: `assert()` stays a code-execution sink -- assertion-based webshells for
// PHP <= 7 are real and in the corpus -- but an argument whose KIND cannot be a string was never code
// on any PHP version, and PHP 8 removed string evaluation altogether (php.net, function.assert:
// "assert() will no longer evaluate string arguments"). Measured 2026-08-26 on the curated benign tree:
// phpMyAdmin `assert($statement instanceof SelectStatement);` scored 85, the tier the runbook maps to
// "isolate host".

import (
	"strings"
	"testing"
)

func assertFindings(t *testing.T, src string) []Finding {
	t.Helper()
	var out []Finding
	for _, f := range Analyze([]byte(src)) {
		if strings.Contains(f.Evidence, "assert(...)") {
			out = append(out, f)
		}
	}
	return out
}

func TestAssertWithABooleanKindArgumentIsNotASink(t *testing.T) {
	cases := []struct{ name, src string }{
		{"instanceof (phpMyAdmin shape)", `<?php $s = $_POST['q']; assert($s instanceof SelectStatement);`},
		{"equality", `<?php assert($_GET['a'] == 'x');`},
		{"identity", `<?php assert($_GET['a'] === 'x');`},
		{"comparison", `<?php assert($_POST['n'] < 10);`},
		{"negation", `<?php assert(!$_REQUEST['flag']);`},
		{"isset", `<?php assert(isset($_GET['id']));`},
		{"empty", `<?php assert(empty($_GET['id']));`},
		{"bool cast", `<?php assert((bool)$_GET['x']);`},
		{"int cast", `<?php assert((int)$_GET['x']);`},
		{"logical and", `<?php assert($_GET['a'] && $_GET['b']);`},
		{"logical or", `<?php assert($_GET['a'] || $_GET['b']);`},
		{"xor", `<?php assert($_GET['a'] xor $_GET['b']);`},
		{"parenthesised comparison", `<?php assert(($_GET['a'] != 1));`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if fs := assertFindings(t, tc.src); len(fs) != 0 {
				t.Fatalf("an argument that cannot be a string is not code; got %v", fs)
			}
		})
	}
}

func TestAssertWithAStringCapableArgumentStillFires(t *testing.T) {
	cases := []struct{ name, src string }{
		{"request accessor", `<?php assert($_POST['x']);`},
		{"variable", `<?php $c = $_GET['c']; assert($c);`},
		{"concatenation", `<?php assert("echo " . $_GET['c']);`},
		{"ternary", `<?php assert($_GET['a'] ? $_GET['a'] : 'true');`},
		{"function call", `<?php assert(trim($_GET['c']));`},
		{"string cast", `<?php assert((string)$_GET['c']);`},
		{"silenced", `<?php @assert($_REQUEST['c']);`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fs := assertFindings(t, tc.src)
			if len(fs) == 0 {
				t.Fatalf("a string-capable argument is the classic PHP<=7 webshell; must still fire")
			}
			for _, f := range fs {
				if f.Rule != "phptaint:sink-on-request" || f.Score != 85 ||
					f.Evidence != "AST taint: assert(...) called with request input" {
					t.Fatalf("the firing case must be unchanged (rule, score, evidence -- fingerprints depend on it), got %+v", f)
				}
			}
		})
	}
}

func TestAssertSecondArgumentIsNotASink(t *testing.T) {
	// assert(assertion, description): the description was never evaluated on any PHP version.
	if fs := assertFindings(t, `<?php assert(true, $_POST['msg']);`); len(fs) != 0 {
		t.Fatalf("the description argument is never code, got %v", fs)
	}
}

func TestAssertReachedThroughAResolvedNameKeepsTheKindRule(t *testing.T) {
	// `$f = 'assert'; $f(...)` is the same sink by another route; the kind rule applies there too.
	if fs := assertFindings(t, `<?php $f = 'assert'; $f($_GET['a'] instanceof Foo);`); len(fs) != 0 {
		t.Fatalf("resolved-name assert with a boolean-kind argument is not code, got %v", fs)
	}
	if fs := assertFindings(t, `<?php $f = 'assert'; $f($_GET['a']);`); len(fs) == 0 {
		t.Fatalf("resolved-name assert with a string-capable argument must still fire")
	}
}
