package weblang

import (
	"path/filepath"
	"strings"
	"testing"
)

var sinkLang Lang
var sinkBool bool

// The pre-008 shape: one ToLower over the extension, then a switch.
func oldStyle(p string) bool {
	switch strings.ToLower(filepath.Ext(p)) {
	case ".php", ".php3", ".php4", ".php5", ".php7", ".phtml", ".pht", ".inc":
		return true
	}
	return false
}

var paths = []string{
	`C:\web\wp-includes\class-wp-query.php`,
	`C:\web\wp-content\themes\twentytwentyone\assets\css\style.css`,
	`C:\web\wp-admin\js\common.min.js`,
	`C:\web\wp-content\uploads\2021\07\logo.png`,
	`C:\web\readme.html`,
}

func BenchmarkClassify(b *testing.B) {
	for i := 0; i < b.N; i++ {
		sinkLang = Classify(paths[i%len(paths)])
	}
}

func BenchmarkOldStyleExtSwitch(b *testing.B) {
	for i := 0; i < b.N; i++ {
		sinkBool = oldStyle(paths[i%len(paths)])
	}
}
