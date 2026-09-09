// Package report parses a ShellSight scanner run folder.
//
// The wire format is the scanner's native report.json, not the OCSF findings.ndjson beside it.
// report.json is the only file carrying the verdict, per-view coverage and the skip counts, and a
// verdict without its coverage is how a scanner tells a comfortable lie.
//
// The types below MIRROR shellsight/internal/finding rather than importing it. The console is a
// separate Go module from the scanner on purpose -- the scanner's dependency surface is kept tiny
// because it is copied onto hosts assumed to be compromised -- so this package pays a small
// duplication to avoid re-coupling them. SchemaVersion is carried so a drift is detectable.
package report

import (
	"encoding/json"
	"fmt"
)

type Report struct {
	SchemaVersion string     `json:"schema_version"`
	Scan          Scan       `json:"scan"`
	Verdict       Verdict    `json:"verdict"`
	Coverage      []Coverage `json:"coverage"`
	Findings      []Finding  `json:"findings"`
}

type Scan struct {
	Host        string `json:"host"`
	Started     string `json:"started"`
	Finished    string `json:"finished"`
	ToolVersion string `json:"tool_version"`
	KBVersion   string `json:"kb_version,omitempty"`
	RunID       string `json:"run_id"`
	Operator    string `json:"operator,omitempty"`
	Invocation  string `json:"invocation,omitempty"`
	// BuildID and RuleSet arrive with stage 2's agent generation. Reports produced by a
	// hand-run scanner carry neither, so both are optional and their absence is not an error.
	BuildID string `json:"build_id,omitempty"`
	RuleSet string `json:"rule_set,omitempty"`
}

type Verdict struct {
	Tier       string `json:"tier"`
	Score      int    `json:"score"`
	Incomplete bool   `json:"incomplete"`
}

type ScanSkips struct {
	NonRegular         int `json:"non_regular"`
	Unreadable         int `json:"unreadable"`
	OversizeSkipped    int `json:"oversize_skipped"`
	NoLanguageDetector int `json:"no_language_detector"`
}

// Total is the number of enumerated files no detector examined in full.
func (s ScanSkips) Total() int {
	return s.NonRegular + s.Unreadable + s.OversizeSkipped + s.NoLanguageDetector
}

type Coverage struct {
	View           string          `json:"view"`
	Status         string          `json:"status"`
	Reason         string          `json:"reason,omitempty"`
	TargetsScanned int             `json:"targets_scanned"`
	Skipped        *ScanSkips      `json:"skipped,omitempty"`
	Discovery      json.RawMessage `json:"discovery,omitempty"`
	Scratch        string          `json:"scratch,omitempty"`
}

type File struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256,omitempty"`
}

type Target struct {
	Kind string `json:"kind"`
	File *File  `json:"file,omitempty"`
}

type Artifact struct {
	Kind     string `json:"kind"`
	Identity string `json:"identity"`
	Location string `json:"location,omitempty"`
}

type Detection struct {
	Basis        string `json:"basis"`
	KnowledgeRef string `json:"knowledge_ref,omitempty"`
	Evidence     string `json:"evidence,omitempty"`
	Allowlisted  bool   `json:"allowlisted"`
}

type Finding struct {
	SchemaVersion string            `json:"schema_version"`
	ID            string            `json:"id"`
	Host          string            `json:"host"`
	View          string            `json:"view"`
	Target        Target            `json:"target"`
	Artifact      Artifact          `json:"artifact"`
	Detection     Detection         `json:"detection"`
	Score         int               `json:"score"`
	Tier          string            `json:"tier"`
	Context       map[string]string `json:"context,omitempty"`
	Mitre         []string          `json:"mitre,omitempty"`
	Fingerprint   string            `json:"fingerprint,omitempty"`
}

// ContentKey is what triage groups and records decisions against.
//
// It is the FILE CONTENT HASH, deliberately -- not Finding.Fingerprint. The fingerprint is
// Host|View|path|Basis|KnowledgeRef|Evidence|family, so it embeds the host and the path: the same
// webshell in two directories gets two fingerprints, and every rule that fires gets one of its own.
// Keying triage on it would give MORE items per webshell and nothing shared across hosts, which is
// the opposite of what triage is for. The fingerprint's real job is a suppression, where being
// host- and path-specific is correct.
//
// Memory-view findings have no file, so they fall back to the artifact identity -- a class or
// module name. Disk-only reports never take that branch, but it must not panic when they do.
func ContentKey(f Finding) string {
	if f.Target.File != nil && f.Target.File.SHA256 != "" {
		return "sha256:" + f.Target.File.SHA256
	}
	if f.Artifact.Identity != "" {
		return "artifact:" + f.Artifact.Identity
	}
	return "finding:" + f.ID
}

// Parse decodes a report.json.
func Parse(b []byte) (Report, error) {
	var r Report
	if err := json.Unmarshal(b, &r); err != nil {
		return Report{}, fmt.Errorf("report is not valid JSON: %w", err)
	}
	// RunID is the ingest idempotency key -- re-importing the same run must not create a second
	// scan -- so a report without one cannot be stored safely.
	if r.Scan.RunID == "" {
		return Report{}, fmt.Errorf("report has no scan.run_id")
	}
	if r.Scan.Host == "" {
		return Report{}, fmt.Errorf("report has no scan.host")
	}
	return r, nil
}
