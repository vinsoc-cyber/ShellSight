// Package agentgen assembles a generated agent from bytes the console already holds.
//
// Assembly, never compilation (G2 of the agent-generation design). Every executable byte in the
// output is copied from a published release, located through release_files and fetched from the
// content-addressed blob store. This package has no Go toolchain and never compiles scanner code.
//
// It also never carries its own list of what a view needs (G5). That list is emitted by the scanner
// into the release's own components.json, and read back here. The console holding a second copy is
// how the two silently diverge -- this repo already paid for that once, which is why
// internal/weblang exists.
package agentgen

import (
	"encoding/json"
	"fmt"
)

// ComponentsPath is where the scanner's packaging puts the declaration inside a release.
const ComponentsPath = "components.json"

// ComponentsSchema is the only schema version this console understands.
const ComponentsSchema = "1"

// Files is a release's contents: the release_files index and the blob store, seen as one lookup.
//
// An interface so resolution is testable with neither Postgres nor a blob directory. The generator's
// decisions are all pure functions of a declaration and a file set; only recording a build needs a
// database, and that is a different package.
type Files interface {
	// File returns the bytes of one path inside the release, and whether the release holds it.
	File(path string) ([]byte, bool)
}

// ViewComponents is what one view needs, as the scanner declares it.
type ViewComponents struct {
	Binaries []string `json:"binaries,omitempty"`
	Data     []string `json:"data,omitempty"`
	// Rules reports whether this view scans with YARA. When true, Data names the rule layers the
	// compiled blob REPLACES rather than files to stage -- see Resolve.
	Rules        bool   `json:"rules"`
	HostRequires string `json:"host_requires,omitempty"`
}

// Components is the release's declaration for one target.
type Components struct {
	SchemaVersion string                    `json:"schema_version"`
	Target        string                    `json:"target"`
	Release       string                    `json:"release"`
	Always        []string                  `json:"always"`
	Views         map[string]ViewComponents `json:"views"`
}

// LoadComponents reads the declaration out of a release.
func LoadComponents(files Files) (Components, error) {
	raw, ok := files.File(ComponentsPath)
	if !ok {
		return Components{}, fmt.Errorf(
			"this release carries no %s, so nothing states what each view needs; it predates agent "+
				"generation and cannot be built from", ComponentsPath)
	}
	var doc Components
	if err := json.Unmarshal(raw, &doc); err != nil {
		return Components{}, fmt.Errorf("%s in this release is not valid JSON: %w", ComponentsPath, err)
	}
	if doc.SchemaVersion != ComponentsSchema {
		return Components{}, fmt.Errorf(
			"%s declares schema_version %q and this console understands only %q; a newer document may "+
				"mean something different by the same field, so it is refused rather than guessed at",
			ComponentsPath, doc.SchemaVersion, ComponentsSchema)
	}
	if len(doc.Views) == 0 {
		return Components{}, fmt.Errorf("%s declares no views at all", ComponentsPath)
	}
	if len(doc.Always) == 0 {
		// Every agent needs the orchestrator: the probes are launched by it, so a build without one
		// carries detectors nothing can run.
		//
		// Checked here because nothing upstream checks it alone. The scanner's own package-time
		// verification gates the CONJUNCTION -- `len(Always) == 0 && len(Views) == 0`
		// (cmd/shellsight/components.go:284) -- so a declaration with views and an empty `always`
		// passes that, passes every other gate here, and resolves to a file set with no
		// orchestrator in it. Task 3's release_files cross-check cannot catch it either: nothing is
		// missing from the release, the orchestrator is simply undeclared.
		return Components{}, fmt.Errorf(
			"%s names no always-present component, so a build from it would carry probes with no "+
				"orchestrator to run them", ComponentsPath)
	}
	return doc, nil
}
