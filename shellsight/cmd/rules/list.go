package rules

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func runList(args []string, w io.Writer) int {
	dir := rulesDir(args)
	layers := []struct{ name, subdir string }{
		{"foundation", "foundation"},
		{"own", "own"},
		{"custom", "custom"},
	}
	fmt.Fprintf(w, "%-12s  %-8s  %-10s  %s\n", "LAYER", "RULES", "VERSION", "PATH")
	fmt.Fprintln(w, strings.Repeat("-", 60))
	for _, l := range layers {
		path := filepath.Join(dir, l.subdir)
		count := countYaraFiles(path)
		version := readVersion(filepath.Join(path, "VERSION"))
		fmt.Fprintf(w, "%-12s  %-8d  %-10s  %s\n", l.name, count, version, path)
	}
	printMemContractsSection(dir, w)
	return 0
}

func countYaraFiles(dir string) int {
	n := 0
	filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			ext := strings.ToLower(filepath.Ext(p))
			if ext == ".yar" || ext == ".yara" {
				n++
			}
		}
		return nil
	})
	return n
}

func readVersion(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(b))
}
