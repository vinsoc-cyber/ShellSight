package agentgen

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func TestTheManifestHashesEveryFileInTheArchive(t *testing.T) {
	staged := []StagedFile{
		{Path: "shellsight", Body: []byte("orchestrator")},
		{Path: "rules/set.yarc", Body: []byte("compiled")},
	}
	raw, err := RenderManifest(staged)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	var got struct {
		SchemaVersion string            `json:"schema_version"`
		Files         map[string]string `json:"files"`
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Files) != 2 {
		t.Fatalf("manifest lists %d files, want 2: %v", len(got.Files), got.Files)
	}
	sum := sha256.Sum256([]byte("orchestrator"))
	if got.Files["shellsight"] != hex.EncodeToString(sum[:]) {
		t.Errorf("shellsight hash = %q", got.Files["shellsight"])
	}
}

// The manifest must not list itself: its own hash cannot be known before it is written, and a
// self-referential entry would be wrong every time.
//
// The staged list HANDED IN carries a manifest.json, and that is the whole test. Measured
// 2026-09-04: with the plan's fixture -- a single "shellsight" entry -- deleting the skip inside
// RenderManifest killed no test, because nothing in the input could have been skipped. A gate whose
// branch the test cannot reach is not a gate under test. So the entry is put in, and the assertion
// is on the parsed key set as well as the raw bytes.
func TestTheManifestDoesNotListItself(t *testing.T) {
	raw, err := RenderManifest([]StagedFile{
		{Path: "shellsight", Body: []byte("x")},
		{Path: ManifestPath, Body: []byte("a stale manifest from an earlier pass")},
	})
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Files map[string]string `json:"files"`
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if _, listed := got.Files[ManifestPath]; listed {
		t.Errorf("the manifest lists itself, and that entry is wrong every time it is written:\n%s",
			raw)
	}
	if len(got.Files) != 1 {
		t.Errorf("manifest lists %d files, want only shellsight: %v", len(got.Files), got.Files)
	}
	if strings.Contains(string(raw), ManifestPath) {
		t.Errorf("the manifest names itself somewhere in its bytes:\n%s", raw)
	}
}

func TestTheManifestIsByteIdenticalForTheSameInput(t *testing.T) {
	staged := []StagedFile{
		{Path: "b", Body: []byte("two")},
		{Path: "a", Body: []byte("one")},
	}
	first, err := RenderManifest(staged)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		again, err := RenderManifest(staged)
		if err != nil {
			t.Fatal(err)
		}
		if string(again) != string(first) {
			t.Fatalf("run %d differs; map iteration has leaked into the output and G6 is unachievable",
				i)
		}
	}
}
