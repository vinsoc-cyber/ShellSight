package rules

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

type memContractsFile struct {
	Version string          `json:"version"`
	Java    javaMCSection   `json:"java"`
	Dotnet  dotnetMCSection `json:"dotnet"`
}

type javaMCSection struct {
	PipelineContracts []string `json:"pipeline_contracts"`
	TypeNeedles       []string `json:"type_needles"`
	StringNeedles     []string `json:"string_needles"`
}

type dotnetMCSection struct {
	PipelineContracts []string `json:"pipeline_contracts"`
	CapabilityApis    []string `json:"capability_apis"`
	StringNeedles     []string `json:"string_needles"`
}

func readMemContracts(path string) (*memContractsFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var mc memContractsFile
	if err := json.Unmarshal(data, &mc); err != nil {
		return nil, err
	}
	return &mc, nil
}

// printMemContractsSection appends the mem-contracts summary to the rules list output.
func printMemContractsSection(dir string, w io.Writer) {
	path := memContractsPath(dir)
	mc, err := readMemContracts(path)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Memory probe contracts  (mem-contracts.json):")
	if err != nil {
		fmt.Fprintf(w, "  not found — run 'shellsight rules validate' for details (%s)\n", path)
		return
	}
	fmt.Fprintf(w, "  java:    %d pipeline contracts  %d type needles  %d string needles\n",
		len(mc.Java.PipelineContracts), len(mc.Java.TypeNeedles), len(mc.Java.StringNeedles))
	fmt.Fprintf(w, "  dotnet:  %d pipeline contracts  %d capability APIs  %d string needles\n",
		len(mc.Dotnet.PipelineContracts), len(mc.Dotnet.CapabilityApis), len(mc.Dotnet.StringNeedles))
}

// validateMemContracts checks mem-contracts.json for required structure.
// Returns true on success, false on any error (messages written to w).
func validateMemContracts(dir string, w io.Writer) bool {
	path := memContractsPath(dir)
	mc, err := readMemContracts(path)
	if os.IsNotExist(err) {
		fmt.Fprintf(w, "validate: mem-contracts.json not found at %s\n", path)
		return false
	}
	if err != nil {
		fmt.Fprintf(w, "validate: mem-contracts.json invalid JSON: %v\n", err)
		return false
	}
	var issues []string
	if len(mc.Java.PipelineContracts) == 0 {
		issues = append(issues, "java.pipeline_contracts is empty")
	}
	if len(mc.Java.TypeNeedles) == 0 {
		issues = append(issues, "java.type_needles is empty")
	}
	if len(mc.Java.StringNeedles) == 0 {
		issues = append(issues, "java.string_needles is empty")
	}
	if len(mc.Dotnet.PipelineContracts) == 0 {
		issues = append(issues, "dotnet.pipeline_contracts is empty")
	}
	if len(mc.Dotnet.CapabilityApis) == 0 {
		issues = append(issues, "dotnet.capability_apis is empty")
	}
	if len(mc.Dotnet.StringNeedles) == 0 {
		issues = append(issues, "dotnet.string_needles is empty")
	}
	for _, section := range [][]string{mc.Java.PipelineContracts, mc.Java.TypeNeedles, mc.Java.StringNeedles,
		mc.Dotnet.PipelineContracts, mc.Dotnet.CapabilityApis, mc.Dotnet.StringNeedles} {
		for _, v := range section {
			if strings.TrimSpace(v) == "" {
				issues = append(issues, "empty string entry found in a needle/contract list")
				break
			}
		}
	}
	if len(issues) > 0 {
		fmt.Fprintf(w, "validate: mem-contracts.json FAIL — %s\n", strings.Join(issues, "; "))
		return false
	}
	fmt.Fprintln(w, "validate: mem-contracts.json OK")
	return true
}

func memContractsPath(rulesDir string) string {
	return rulesDir + string(os.PathSeparator) + "mem-contracts.json"
}
