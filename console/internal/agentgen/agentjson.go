package agentgen

import (
	"encoding/json"
	"fmt"
	"strings"
)

// AgentSchemaVersion must equal agentcfg.SchemaVersion in the scanner. It cannot be imported --
// console/go.mod records why the two modules share no code -- so contracts/agent.json is the golden
// both sides test against.
const AgentSchemaVersion = "1"

// Recognised values for the two settings the console bakes as a build's DEFAULT. The scanner
// REJECTS anything else rather than coercing it, so writing an unrecognised value produces an agent
// that refuses its own configuration on the host.
//
// Case is significant, and deliberately so on both sides: the scanner's validateChoice does not
// fold, because a case-insensitive read would be a second, quieter spelling of a field whose whole
// job is to say exactly one thing. So "JSON" is refused here rather than lowercased.
var (
	outputFormats     = map[string]bool{"json": true, "text": true}
	processPriorities = map[string]bool{"low": true, "normal": true}
)

// AgentRuleSet is agent.json's rule_set block.
//
// The zero value is legal, not missing: a memory-only build ships no YARA rules at all (G8), so its
// rule_set names nothing.
type AgentRuleSet struct {
	Name       string `json:"name"`
	Version    int    `json:"version"`
	Yarc       string `json:"yarc"`
	YarcSHA256 string `json:"yarc_sha256"`
}

// AgentConfig is what the console writes into a generated agent.
//
// GeneratedAt and GeneratedBy are fields rather than something read from a clock or a session,
// because G6 requires identical inputs to produce identical archive bytes and a timestamp read
// inside the renderer would make that impossible to test.
type AgentConfig struct {
	BuildID string
	Views   []string
	// ScanScope is the webroot list baked as this build's DEFAULT. Empty means the build bakes
	// none, and the agent auto-discovers unless the operator passes -path. It cannot restrict
	// anything: the host flag overrides it in either direction.
	ScanScope []string
	RuleSet AgentRuleSet
	// OutputFormat and ProcessPriority are "" when the analyst chose nothing, which renders as JSON
	// null. Not "": an empty string is a value the scanner does not recognise and rejects, while
	// null means nothing was chosen and lets the built-in default win.
	OutputFormat    string
	ProcessPriority string
	GeneratedAt     string
	GeneratedBy     string
	Release         string
}

// agentDocument is the wire shape. Separate from AgentConfig so the JSON field names and their
// order live in one place, and so a Go field rename cannot silently change the file format.
type agentDocument struct {
	SchemaVersion   string       `json:"schema_version"`
	BuildID         string       `json:"build_id"`
	Views           []string     `json:"views"`
	ScanScope       []string     `json:"scan_scope,omitempty"`
	RuleSet         AgentRuleSet `json:"rule_set"`
	OutputFormat    *string      `json:"output_format"`
	ProcessPriority *string      `json:"process_priority"`
	GeneratedAt     string       `json:"generated_at"`
	GeneratedBy     string       `json:"generated_by"`
	Release         string       `json:"release"`
}

// RenderAgentJSON produces the bytes of a generated agent's agent.json.
//
// The scanner reads this file on a host under investigation and rejects what it does not
// understand rather than repairing it, so anything it would reject is refused HERE -- while an
// operator is still at a console and can fix it -- instead of becoming an agent that refuses its
// own configuration after it has been copied to the target.
//
// contracts/agent.json is the golden this is tested against byte for byte, because the console
// cannot import the scanner's agentcfg and two independent descriptions of one format drift.
func RenderAgentJSON(cfg AgentConfig) ([]byte, error) {
	// Views and BuildID are validated for the same reason the two Choice fields are, and the reason
	// is not symmetry. The scanner rejects an empty view list (agentcfg.go:208), a name blank after
	// TrimSpace (:223) and a name carrying the comma it joins the list with (:227) -- so writing any
	// of them here produces an agent that refuses its own configuration on a host under
	// investigation, which is the failure this whole function exists to move forward in time.
	//
	// Resolve already guarantees a good list on the real path. This function is exported, and the
	// guarantee of a caller is not a property of the format.
	if len(cfg.Views) == 0 {
		return nil, fmt.Errorf(
			"an agent must declare at least one view; the scanner refuses a configuration that names " +
				"none, because the coverage record is what makes a reported absence mean anything")
	}
	for index, view := range cfg.Views {
		if strings.TrimSpace(view) == "" {
			return nil, fmt.Errorf(
				"views[%d] = %q names no view; the scanner rejects it rather than trimming it, because a "+
					"blank entry declares a view count the build does not have", index, view)
		}
		if strings.Contains(view, ",") {
			return nil, fmt.Errorf(
				"views[%d] = %q cannot contain a comma: the scanner joins this list with one, so the "+
					"entry would be two views to the CLI and one opaque string to the coverage check",
				index, view)
		}
	}
	// The scanner does not check this one -- it reads build_id and validates nothing about it. It is
	// refused here because build_id is the only identifier INSIDE the artefact: an agent carrying an
	// empty one cannot be traced back to the build that produced it.
	if cfg.BuildID == "" {
		return nil, fmt.Errorf(
			"an agent must carry a build id; it is the only identifier inside the archive, and without " +
				"it a build cannot be traced back from a host to the record that produced it")
	}
	if cfg.OutputFormat != "" && !outputFormats[cfg.OutputFormat] {
		return nil, fmt.Errorf(
			"output_format %q is not one of json, text; the scanner rejects an unrecognised value "+
				"rather than coercing it, so writing this produces an agent that refuses its own "+
				"configuration", cfg.OutputFormat)
	}
	if cfg.ProcessPriority != "" && !processPriorities[cfg.ProcessPriority] {
		return nil, fmt.Errorf(
			"process_priority %q is not one of low, normal; the scanner rejects an unrecognised value "+
				"rather than coercing it", cfg.ProcessPriority)
	}
	doc := agentDocument{
		SchemaVersion:   AgentSchemaVersion,
		BuildID:         cfg.BuildID,
		Views:           cfg.Views,
		ScanScope:       cfg.ScanScope,
		RuleSet:         cfg.RuleSet,
		OutputFormat:    optional(cfg.OutputFormat),
		ProcessPriority: optional(cfg.ProcessPriority),
		GeneratedAt:     cfg.GeneratedAt,
		GeneratedBy:     cfg.GeneratedBy,
		Release:         cfg.Release,
	}
	body, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(body, '\n'), nil
}

// optional renders "" as JSON null rather than an empty string.
func optional(v string) *string {
	if v == "" {
		return nil
	}
	return &v
}
