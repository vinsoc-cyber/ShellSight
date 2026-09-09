package agentgen

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// contractPath is the golden both modules test against. agentgen sits exactly three directories
// below the repo root, as does shellsight/internal/agentcfg.
func contractPath(t *testing.T) string {
	t.Helper()
	p := filepath.Join("..", "..", "..", "contracts", "agent.json")
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("the cross-module contract is missing at %s: %v", p, err)
	}
	return p
}

func contractConfig() AgentConfig {
	return AgentConfig{
		BuildID: "b-7f3a91",
		Views:   []string{"disk"},
		// The baked DEFAULT scan scope. Present in the golden, so the renderer must emit it.
		ScanScope: []string{"/var/www", "/srv/http"},
		RuleSet: AgentRuleSet{
			Name:       "sweep-acme",
			Version:    3,
			Yarc:       "rules/set.yarc",
			YarcSHA256: "aeabf48ad4390ab86aae9ec4dbcccb5fd331f93d36bc6b45b4966b0166149353",
		},
		OutputFormat:    "json",
		ProcessPriority: "low",
		GeneratedAt:     "2026-09-04T12:00:00Z",
		GeneratedBy:     "v.quannh67",
		Release:         "v1.0.0-488-gdd02888",
	}
}

// The console side of the contract: these exact bytes, not merely something that parses.
func TestTheConsoleWritesTheContractBytes(t *testing.T) {
	got, err := RenderAgentJSON(contractConfig())
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	want, err := os.ReadFile(contractPath(t))
	if err != nil {
		t.Fatal(err)
	}
	// The repo checks out CRLF on Windows for tracked text, so compare with line endings normalised
	// -- otherwise this fails on one host and passes on another for a reason that is not the format.
	if norm(string(got)) != norm(string(want)) {
		t.Errorf("agent.json does not match contracts/agent.json.\n got:\n%s\nwant:\n%s", got, want)
	}
}

func norm(s string) string { return strings.ReplaceAll(strings.TrimSpace(s), "\r\n", "\n") }

// An unspecified choice must be null, not "". The scanner rejects an empty string -- it is a value
// the field does not recognise -- while null means "not chosen" and lets the built-in default win.
func TestAnUnchosenSettingIsNullNotEmpty(t *testing.T) {
	cfg := contractConfig()
	cfg.OutputFormat = ""
	cfg.ProcessPriority = ""
	raw, err := RenderAgentJSON(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var probe map[string]any
	if err := json.Unmarshal(raw, &probe); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"output_format", "process_priority"} {
		v, present := probe[k]
		if !present {
			t.Errorf("%s is absent; the field must be present and null", k)
		}
		if v != nil {
			t.Errorf("%s = %#v, want null", k, v)
		}
	}
}

func TestAnUnrecognisedSettingIsRefusedRatherThanWritten(t *testing.T) {
	for _, tc := range []struct{ field, value string }{
		{"output_format", "yaml"},
		{"process_priority", "realtime"},
		{"output_format", "JSON"},
		// Case is significant in the scanner (validateChoice's comment says so explicitly), so a
		// folded spelling of a real value is as unwritable as an invented one.
		{"process_priority", "Low"},
	} {
		cfg := contractConfig()
		if tc.field == "output_format" {
			cfg.OutputFormat = tc.value
		} else {
			cfg.ProcessPriority = tc.value
		}
		if _, err := RenderAgentJSON(cfg); err == nil {
			t.Errorf("%s=%q was written; the scanner rejects it, so writing it produces an agent that "+
				"refuses its own configuration on the host", tc.field, tc.value)
		}
	}
}

// A memory-only build carries no rule set, and its rule_set block must be empty rather than naming
// a rules/set.yarc that is not in the archive.
func TestAMemoryOnlyBuildNamesNoRuleSet(t *testing.T) {
	cfg := contractConfig()
	cfg.Views = []string{"java-mem"}
	cfg.RuleSet = AgentRuleSet{}
	raw, err := RenderAgentJSON(cfg)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if strings.Contains(string(raw), "set.yarc") {
		t.Errorf("a memory-only agent.json names a rule blob it does not carry:\n%s", raw)
	}
}

// The carried-forward gap from Tasks 3 and 4: RenderAgentJSON validated the two Choice fields and
// nothing else, so it could still render a document the scanner refuses ON THE HOST -- which is the
// exact failure the choice validation exists to prevent, one field over.
//
// agentcfg.Load rejects an empty view list (agentcfg.go:208), a name that is blank after
// TrimSpace (:223) and a name containing a comma (:227, because the CLI path joins this list with
// one). Resolve guarantees a good list on the real path, but this function is exported and Build is
// not the only thing that may ever call it.
func TestAViewListTheScannerWouldRefuseIsNotWritten(t *testing.T) {
	for _, tc := range []struct {
		name  string
		views []string
	}{
		{"no views at all", nil},
		{"an empty list", []string{}},
		{"a blank name", []string{""}},
		{"a whitespace name", []string{" "}},
		{"a tab name", []string{"\t"}},
		{"a comma-joined pair", []string{"disk,java-mem"}},
		{"one good name and one blank", []string{"disk", ""}},
	} {
		cfg := contractConfig()
		cfg.Views = tc.views
		raw, err := RenderAgentJSON(cfg)
		if err == nil {
			t.Errorf("%s: written, and the scanner refuses it on the host:\n%s", tc.name, raw)
		}
	}
}

// The control: the view names a real release actually uses still render.
func TestARealViewListStillRenders(t *testing.T) {
	cfg := contractConfig()
	cfg.Views = []string{"disk", "java-mem", "dotnet-mem-x86"}
	if _, err := RenderAgentJSON(cfg); err != nil {
		t.Errorf("a legitimate view list was refused: %v", err)
	}
}

// Unlike the rules above, this one has no counterpart in the scanner -- agentcfg reads build_id and
// validates nothing about it (agentcfg.go:158 is the only mention). It is refused here anyway
// because build_id is the ONLY identifier inside the artefact: an agent carrying an empty one
// cannot be traced back to the build row that produced it, and provenance is the point of writing
// it at all.
func TestAnAgentJSONWithNoBuildIDIsNotWritten(t *testing.T) {
	cfg := contractConfig()
	cfg.BuildID = ""
	if raw, err := RenderAgentJSON(cfg); err == nil {
		t.Errorf("written with no build id, so the artefact names nothing:\n%s", raw)
	}
}
