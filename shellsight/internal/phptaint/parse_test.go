package phptaint

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParsePHPValid(t *testing.T) {
	root, ok := parsePHP([]byte(`<?php $x = $_GET['x']; system($x);`))
	if !ok || root == nil {
		t.Fatalf("expected a parsed AST for valid PHP, got ok=%v root=%v", ok, root != nil)
	}
}

func TestParsePHPSizeGuard(t *testing.T) {
	// nil/empty/oversize are refused by the size guard without parsing.
	for _, src := range [][]byte{nil, []byte("")} {
		if _, ok := parsePHP(src); ok {
			t.Fatalf("expected (nil,false) for nil/empty input")
		}
	}
	big := make([]byte, maxParseSize+1)
	if _, ok := parsePHP(big); ok {
		t.Fatal("oversize input must be refused without parsing")
	}
}

// TestParsePHPRecoversLexerPanic asserts the per-file recover wrapper works on a REAL panic
// input: VKCOM/php-parser v0.8.2 lexer panics (index-out-of-range) on ~6 obfuscated corpus files.
// Without recover this crashes the whole process; parsePHP must return (nil, false).
func TestParsePHPRecoversLexerPanic(t *testing.T) {
	// The fixture is a LIVE WEBSHELL and is deliberately NOT committed: no malware sample belongs in
	// a repository handed to an analyst team. Resolved the way the sibling corpus tests resolve
	// theirs (internal/perlpytaint/fpcost_corpus_test.go) -- SHELLSIGHT_CORPUS if set, else the
	// conventional sibling directory -- so this file carries no absolute path to one workstation.
	root := os.Getenv("SHELLSIGHT_CORPUS")
	if root == "" {
		root = filepath.Join("..", "..", "..", "shellsight-corpus")
	}
	// curated/disk/php, not the old disk-php: the corpus was restructured after this path was
	// written, so the test had been skipping silently rather than exercising the recover wrapper.
	panicFile := filepath.Join(root, "curated", "disk", "php", "hannousse", "extracted",
		"cleaned_dataset", "webshell", "4f88e50b853645c95d3da087aecca5b9.php")
	src, err := os.ReadFile(panicFile)
	if err != nil {
		t.Skipf("panic fixture not present (%v); recover behavior is also covered by the M2.6 measure run over the full corpus", err)
	}
	if _, ok := parsePHP(src); ok {
		t.Fatal("known panic-inducing input must return (nil,false) via recover, not crash")
	}
}
