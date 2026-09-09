//go:build !windows

package main

import (
	"encoding/json"
	"os"

	"shellsight/internal/finding"
)

// On non-Windows, the native-memory view cannot run. Emit honest n/a coverage so `go build ./...`
// and the orchestrator behave cross-platform.
func main() {
	out, _ := json.Marshal(finding.ProbeOutput{
		Findings: []finding.Finding{},
		Coverage: &finding.ProbeCoverage{Status: finding.CovNA, Reason: "native-mem view is Windows-only"},
	})
	os.Stdout.Write(out)
}
