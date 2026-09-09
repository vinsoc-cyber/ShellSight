package phptaint

import (
	"github.com/VKCOM/php-parser/pkg/ast"
	"github.com/VKCOM/php-parser/pkg/conf"
	"github.com/VKCOM/php-parser/pkg/errors"
	"github.com/VKCOM/php-parser/pkg/parser"
	"github.com/VKCOM/php-parser/pkg/version"
)

const maxParseSize = 1 << 20 // 1 MiB cap: pathological large benign files are skipped.

// php8Version parses at PHP 8.0 (a near-superset of PHP 5/7); webshells overwhelmingly use 5/7
// syntax, which 8.0 accepts. nil only if version.New fails (unreachable for "8.0").
var php8Version = func() *version.Version {
	v, err := version.New("8.0")
	if err != nil {
		return nil
	}
	return v
}()

// parsePHP parses src into a PHP AST. It wraps parser.Parse in a per-file recover because
// VKCOM/php-parser v0.8.2's lexer panics (index-out-of-range in internal/php8/lexer.ret) on ~6 of
// 5743 corpus files of malformed/obfuscated input — a bare panic would crash a whole scan. Returns
// (root, true) when a usable tree was produced (partial trees with recoverable errors are accepted);
// (nil, false) on panic, hard error, oversize, or no tree. On false the caller falls back to the
// byte-level YARA rules + the Tier 1 resolver, so a parse failure is a graceful degradation, not a
// miss.
func parsePHP(src []byte) (ast.Vertex, bool) {
	if len(src) == 0 || len(src) > maxParseSize || php8Version == nil {
		return nil, false
	}
	panicked := false
	var root ast.Vertex
	var perr error
	func() {
		defer func() {
			if r := recover(); r != nil {
				panicked = true
			}
		}()
		root, perr = parser.Parse(src, conf.Config{
			Version:          php8Version,
			ErrorHandlerFunc: func(*errors.Error) {}, // tolerate partial-tree errors
		})
	}()
	if panicked || perr != nil || root == nil {
		return nil, false
	}
	return root, true
}
