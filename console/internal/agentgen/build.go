package agentgen

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// Request is everything a build needs. The caller resolves it from the database and the blob store;
// this package touches neither.
type Request struct {
	// Files is the release's contents.
	Files Files
	// Views is the analyst's selection.
	Views []string
	// ScanScope is the webroot list to bake as this build's DEFAULT. Empty bakes none.
	ScanScope []string
	// Release is the version string, for agent.json's provenance.
	Release string

	// RuleSetName, RuleSetVer, ResolvedRules and Yarc describe the frozen rule set. All are zero for
	// a memory-only build, which carries no YARA at all.
	RuleSetName   string
	RuleSetVer    int
	ResolvedRules int
	Yarc          []byte

	// OutputFormat and Priority are the baked defaults; "" means the analyst chose nothing.
	OutputFormat string
	Priority     string

	// GeneratedAt and GeneratedBy are parameters, not a clock and a session read in here. G6 needs
	// identical inputs to reproduce identical bytes, and a timestamp taken inside this function
	// would make that impossible to test.
	GeneratedAt string
	GeneratedBy string
}

// Result is the archive and the facts the caller records.
type Result struct {
	Archive []byte
	// BuildID is derived from the request, so the same request yields the same id.
	BuildID string
	// SHA256 is the archive's hash, which is also its blob-store key.
	SHA256 string
	// AgentJSON is returned alongside the archive so the build row can record the configuration
	// verbatim rather than a paraphrase of it.
	AgentJSON  []byte
	Views      []string
	NeedsRules bool
}

// Build assembles a generated agent.
func Build(req Request) (Result, error) {
	doc, err := LoadComponents(req.Files)
	if err != nil {
		return Result{}, err
	}
	sel, err := Resolve(doc, req.Views)
	if err != nil {
		return Result{}, err
	}

	// The refusals, before any assembly. Each one exists because the alternative is an agent that
	// fails on a customer's host for a reason decided here.
	if sel.NeedsRules {
		if req.ResolvedRules == 0 {
			return Result{}, fmt.Errorf(
				"this rule set applies no rules, so the agent would scan every file and report " +
					"nothing; refused before assembly")
		}
		if len(req.Yarc) == 0 {
			return Result{}, fmt.Errorf(
				"this rule set has no compiled blob, so it is not frozen and there is nothing for " +
					"the agent to carry; freeze it first")
		}
	} else if len(req.Yarc) != 0 || req.RuleSetName != "" {
		return Result{}, fmt.Errorf(
			"the selected views carry no YARA at all, so a rule set cannot be part of this build; " +
				"agent.json would name a rules/set.yarc the archive does not hold")
	}

	staged, err := Stage(req.Files, sel)
	if err != nil {
		return Result{}, err
	}

	cfg := AgentConfig{
		Views:           sel.Views,
		ScanScope:       req.ScanScope,
		OutputFormat:    req.OutputFormat,
		ProcessPriority: req.Priority,
		GeneratedAt:     req.GeneratedAt,
		GeneratedBy:     req.GeneratedBy,
		Release:         req.Release,
	}
	if sel.NeedsRules {
		yarcSum := sha256.Sum256(req.Yarc)
		cfg.RuleSet = AgentRuleSet{
			Name:       req.RuleSetName,
			Version:    req.RuleSetVer,
			Yarc:       RulesPath,
			YarcSHA256: hex.EncodeToString(yarcSum[:]),
		}
		staged = append(staged, StagedFile{Path: RulesPath, Body: req.Yarc})
	}

	// The id is derived from the request so that the same request yields the same archive -- G6.
	// A random or time-based id would change agent.json, and agent.json is inside the zip.
	cfg.BuildID = deriveBuildID(cfg, sel, doc.Target)

	agentJSON, err := RenderAgentJSON(cfg)
	if err != nil {
		return Result{}, err
	}
	staged = append(staged, StagedFile{Path: AgentPath, Body: agentJSON})

	manifest, err := RenderManifest(staged)
	if err != nil {
		return Result{}, err
	}
	staged = append(staged, StagedFile{Path: ManifestPath, Body: manifest})

	archive, err := WriteArchive(staged)
	if err != nil {
		return Result{}, err
	}
	sum := sha256.Sum256(archive)
	return Result{
		Archive:    archive,
		BuildID:    cfg.BuildID,
		SHA256:     hex.EncodeToString(sum[:]),
		AgentJSON:  agentJSON,
		Views:      sel.Views,
		NeedsRules: sel.NeedsRules,
	}, nil
}

// deriveBuildID hashes the build's identity into a short readable id.
//
// Derived rather than random because agent.json carries it and agent.json is inside the archive: a
// random id would make every build's bytes differ and G6 untestable. The inputs are exactly the
// things that make two builds different artefacts.
//
// target is one of them, and it is not in the AgentConfig. agent.json records the release VERSION,
// and a version string alone is not unique across targets -- (version, target) is the natural key
// in `releases`. linux-amd64 and linux-arm64 declare the identical component PATHS, so without the
// target in here two agents holding different machine code, for different processors, would carry
// the same id.
func deriveBuildID(cfg AgentConfig, sel Selection, target string) string {
	h := sha256.New()
	for _, part := range []string{
		cfg.Release, target, cfg.RuleSet.Name, cfg.RuleSet.YarcSHA256,
		cfg.OutputFormat, cfg.ProcessPriority, cfg.GeneratedAt, cfg.GeneratedBy,
	} {
		h.Write([]byte(part))
		h.Write([]byte{0})
	}
	fmt.Fprintf(h, "%d", cfg.RuleSet.Version)
	h.Write([]byte{0})
	for _, v := range sel.Views {
		h.Write([]byte(v))
		h.Write([]byte{0})
	}
	// The baked scope is part of the build's identity, because it is part of agent.json and
	// agent.json is inside the archive: two builds differing only in scope are different artefacts
	// with different bytes. Leaving it out would give them the same id and different hashes, which
	// RecordBuild refuses as a collision -- so the second build would be rejected rather than
	// recorded, for a reason that is not true.
	for _, p := range cfg.ScanScope {
		h.Write([]byte(p))
		h.Write([]byte{0})
	}
	for _, f := range sel.Files {
		h.Write([]byte(f))
		h.Write([]byte{0})
	}
	// 12 hex characters, not 6. At 6 the id is 24 bits, and two DIFFERENT builds share one with
	// probability ~2.9% by a thousand builds and ~53% by five thousand -- and a collision is not
	// cosmetic, because the record layer keys on this: a build id that already exists is read as
	// "the same request produced the same artefact", so a collision would return a DIFFERENT
	// agent's row and hand a responder the wrong archive. 48 bits puts that at ~1.8e-9 for the
	// same thousand builds.
	//
	// Result.SHA256 remains the real identity; this stays short enough to quote in a report.
	return "b-" + hex.EncodeToString(h.Sum(nil))[:12]
}
