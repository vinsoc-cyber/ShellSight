// Command jvmprobe is the Linux memory view.
//
// Phase 2 implements Stage 0 (discovery) and Stage 1 (external triage) only: it never attaches and
// never injects code into the target. Later stages add the in-JVM path.
package main

import (
	"encoding/json"
	"os"

	"shellsight/internal/finding"
)

func main() {
	var spec finding.TargetSpec
	// A probe reads its spec from stdin. Empty stdin means "scan this host", which is the common
	// IR case, so a decode error is not fatal.
	_ = json.NewDecoder(os.Stdin).Decode(&spec)

	out := run(spec)
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(out); err != nil {
		os.Exit(1)
	}
}
