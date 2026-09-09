package rules

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// Run dispatches shellsight rules subcommands. Returns an exit code.
func Run(args []string) int {
	return RunWithWriter(args, os.Stdout)
}

// RunWithWriter is the testable form; output goes to w instead of os.Stdout.
func RunWithWriter(args []string, w io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(w, "usage: shellsight rules <list|update|validate|export|import>")
		return 1
	}
	switch args[0] {
	case "list":
		return runList(args[1:], w)
	case "validate":
		return runValidate(args[1:], w)
	case "update":
		return runUpdate(args[1:], w)
	case "export":
		return runExport(args[1:], w)
	case "import":
		return runImport(args[1:], w)
	default:
		fmt.Fprintf(w, "unknown rules command %q\n", args[0])
		return 1
	}
}

// rulesDir resolves the active rules directory (beside the binary, or --rules-dir flag).
func rulesDir(args []string) string {
	for i, a := range args {
		if a == "--rules-dir" && i+1 < len(args) {
			return args[i+1]
		}
	}
	exe, _ := os.Executable()
	return filepath.Join(filepath.Dir(exe), "kb", "rules")
}
