package agentgen

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// ManifestPath is where the manifest lands inside a generated agent.
const ManifestPath = "manifest.json"

// AgentPath is where the configuration lands inside a generated agent.
const AgentPath = "agent.json"

// RulesPath is where a disk build's compiled rule set lands. It matches agent.json's rule_set.yarc,
// which is what the scanner passes to -rules-blob.
const RulesPath = "rules/set.yarc"

// ManifestSchema is the manifest's own schema version, independent of the agent config's.
const ManifestSchema = "1"

type manifestDocument struct {
	SchemaVersion string            `json:"schema_version"`
	Files         map[string]string `json:"files"`
}

// RenderManifest lists the SHA-256 of every file in the archive.
//
// encoding/json sorts map keys, so the output is deterministic without sorting here -- and a test
// renders it twenty times to keep that true. It matters because the manifest goes inside the zip
// whose bytes G6 requires to be reproducible.
//
// The manifest never lists itself: its own hash is unknowable before it is written.
func RenderManifest(staged []StagedFile) ([]byte, error) {
	doc := manifestDocument{SchemaVersion: ManifestSchema, Files: map[string]string{}}
	for _, f := range staged {
		if f.Path == ManifestPath {
			continue
		}
		sum := sha256.Sum256(f.Body)
		doc.Files[f.Path] = hex.EncodeToString(sum[:])
	}
	body, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(body, '\n'), nil
}
