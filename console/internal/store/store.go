// Package store is the console's only data-access surface.
//
// Everything above it depends on the Store interface, never on PostgreSQL. That boundary is the
// whole point: it keeps SQL out of the domain packages and makes a later change of database a
// substitution rather than a rewrite.
package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"time"
)

type Release struct {
	ID          int64     `json:"id"`
	Version     string    `json:"version"`
	Target      string    `json:"target"`
	PublishedAt time.Time `json:"published_at"`
	PublishedBy string    `json:"published_by"`
}

type ReleaseFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// Build is one generated agent, as recorded.
//
// AgentJSON is the configuration verbatim rather than parsed columns: it is the artefact's own
// statement of what it is, and re-serialising it from columns would let the row and the archive
// disagree about the same build.
type Build struct {
	ID          int64     `json:"id"`
	BuildID     string    `json:"build_id"`
	ReleaseID   int64     `json:"release_id"`
	RuleSetID   *int64    `json:"rule_set_id"`
	Views       []string  `json:"views"`
	SHA256      string    `json:"sha256"`
	SizeBytes   int64     `json:"size_bytes"`
	AgentJSON   []byte    `json:"agent_json"`
	GeneratedAt time.Time `json:"generated_at"`
	GeneratedBy string    `json:"generated_by"`
}

// Sum64 is the hex SHA-256 of s, for tests and callers that need a well-formed CHAR(64).
func Sum64(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

type Rule struct {
	ID         int64  `json:"id"`
	Identifier string `json:"identifier"`
	Layer      string `json:"layer"`
	SourcePack string `json:"source_pack,omitempty"`
}

// RuleIndexRow is one rule as the browser needs it: enough to search and filter, and NOT the rule
// text. Text is the bulk of the payload and the browser never shows it; it stays reachable per rule
// through GetRule.
type RuleIndexRow struct {
	ID          int64  `json:"id"`
	Identifier  string `json:"identifier"`
	Layer       string `json:"layer"`
	SourcePack  string `json:"source_pack,omitempty"`
	Score       *int   `json:"score,omitempty"`
	Description string `json:"description,omitempty"`
}

type RuleRevision struct {
	ID        int64     `json:"id"`
	RuleID    int64     `json:"rule_id"`
	Revision  int       `json:"revision"`
	Text      string    `json:"text"`
	Lang      string    `json:"lang,omitempty"`
	Author    string    `json:"author"`
	CreatedAt time.Time `json:"created_at"`

	// Parsed from Text's meta: block on write. Nil Score means the rule declared none, which is
	// 422 of the shipped library's 5,872 rules -- not a failure to read it.
	Description string            `json:"description,omitempty"`
	Score       *int              `json:"score,omitempty"`
	Meta        map[string]string `json:"meta,omitempty"`
}

type RuleSet struct {
	ID         int64      `json:"id"`
	Name       string     `json:"name"`
	Version    *int       `json:"version"`
	CreatedBy  string     `json:"created_by"`
	FrozenAt   *time.Time `json:"frozen_at"`
	FrozenBy   string     `json:"frozen_by,omitempty"`
	YarcSHA256 string     `json:"yarc_sha256,omitempty"`
}

type Exclusion struct {
	RuleID     int64     `json:"rule_id"`
	Identifier string    `json:"identifier"`
	Reason     string    `json:"reason"`
	Author     string    `json:"author"`
	CreatedAt  time.Time `json:"created_at"`
}

// FrozenMember names one rule pinned into a frozen set, WITHOUT its text. FrozenMembers carries
// the text because the compile path needs it; a browser does not, and at 5,872 rules that
// difference is megabytes.
type FrozenMember struct {
	RuleID     int64  `json:"rule_id"`
	Identifier string `json:"identifier"`
	Layer      string `json:"layer"`
	Revision   int    `json:"revision"`
}

// Selection is a draft rule set's choices: whole layers plus individually named rules.
type Selection struct {
	Layers []string `json:"layers"`
	Rules  []int64  `json:"rules"`
}

type CoverageRecord struct {
	View               string `json:"view"`
	Status             string `json:"status"`
	Reason             string `json:"reason,omitempty"`
	TargetsScanned     int    `json:"targets_scanned"`
	NonRegular         int    `json:"non_regular"`
	Unreadable         int    `json:"unreadable"`
	OversizeSkipped    int    `json:"oversize_skipped"`
	NoLanguageDetector int    `json:"no_language_detector"`
}

type FindingRecord struct {
	ID           int64    `json:"id"`
	Ref          string   `json:"ref"`
	ContentKey   string   `json:"content_key"`
	Host         string   `json:"host"`
	View         string   `json:"view"`
	FilePath     string   `json:"file_path,omitempty"`
	FileSHA256   string   `json:"file_sha256,omitempty"`
	ArtifactKind string   `json:"artifact_kind,omitempty"`
	ArtifactID   string   `json:"artifact_id,omitempty"`
	Basis        string   `json:"basis"`
	KnowledgeRef string   `json:"knowledge_ref,omitempty"`
	Evidence     string   `json:"evidence,omitempty"`
	Score        int      `json:"score"`
	Tier         string   `json:"tier"`
	Mitre        []string `json:"mitre,omitempty"`
	Fingerprint  string   `json:"fingerprint,omitempty"`
}

type ScanRecord struct {
	ID          int64            `json:"id"`
	RunID       string           `json:"run_id"`
	Host        string           `json:"host"`
	Started     *time.Time       `json:"started,omitempty"`
	Finished    *time.Time       `json:"finished,omitempty"`
	ToolVersion string           `json:"tool_version,omitempty"`
	Operator    string           `json:"operator,omitempty"`
	Invocation  string           `json:"invocation,omitempty"`
	BuildID     string           `json:"build_id,omitempty"`
	RuleSet     string           `json:"rule_set,omitempty"`
	Tier        string           `json:"tier"`
	Score       int              `json:"score"`
	Incomplete  bool             `json:"incomplete"`
	Integrity   string           `json:"integrity"`
	Source      string           `json:"source,omitempty"`
	ImportedAt  time.Time        `json:"imported_at"`
	Coverage    []CoverageRecord `json:"coverage,omitempty"`
	Findings    []FindingRecord  `json:"findings,omitempty"`
}

type Case struct {
	ID        int64     `json:"id"`
	Name      string    `json:"name"`
	CreatedBy string    `json:"created_by"`
	CreatedAt time.Time `json:"created_at"`
}

// MetaCoverage is what a backfill run found. It is REPORTED, never asserted against 100%: 5,450
// of the 5,872 rules in the shipped library declare a score and 17 have no meta block at all, so a
// test or a gate demanding full coverage would be a statement about the packs, not about the parser.
type MetaCoverage struct {
	Revisions   int            `json:"revisions"`
	Description int            `json:"description"`
	Score       int            `json:"score"`
	NoMetaBlock int            `json:"no_meta_block"`
	Keys        map[string]int `json:"keys"`
}

type Store interface {
	PublishRelease(ctx context.Context, r Release, files []ReleaseFile) (int64, error)
	ListReleases(ctx context.Context) ([]Release, error)
	ReleaseFiles(ctx context.Context, releaseID int64) ([]ReleaseFile, error)
	GetRelease(ctx context.Context, id int64) (Release, error)

	RecordBuild(ctx context.Context, b Build) (Build, error)
	ListBuilds(ctx context.Context) ([]Build, error)
	BuildByID(ctx context.Context, id int64) (Build, error)

	CreateRule(ctx context.Context, r Rule, rev RuleRevision) (int64, error)
	GetRule(ctx context.Context, id int64) (Rule, RuleRevision, error)
	ListRules(ctx context.Context, layer string) ([]Rule, error)
	RuleIndex(ctx context.Context) ([]RuleIndexRow, error)
	AddRevision(ctx context.Context, ruleID int64, rev RuleRevision) (int, error)
	SoftDeleteRule(ctx context.Context, ruleID int64) error
	AllRuleTexts(ctx context.Context) (map[string]string, error)
	BackfillMeta(ctx context.Context) (MetaCoverage, error)

	CreateRuleSet(ctx context.Context, name, createdBy string) (int64, error)
	SetSelection(ctx context.Context, ruleSetID int64, sel Selection) error
	GetSelection(ctx context.Context, ruleSetID int64) (Selection, error)
	AddExclusion(ctx context.Context, ruleSetID, ruleID int64, reason, author string) error
	ListExclusions(ctx context.Context, ruleSetID int64) ([]Exclusion, error)
	ResolveSelection(ctx context.Context, ruleSetID int64) ([]RuleRevision, error)
	ResolvedCount(ctx context.Context, ruleSetID int64) (int, error)
	Freeze(ctx context.Context, ruleSetID int64, version int, frozenBy, yarcSHA256 string, revisionIDs []int64) error
	GetRuleSet(ctx context.Context, id int64) (RuleSet, error)
	ListRuleSets(ctx context.Context) ([]RuleSet, error)
	FrozenMembers(ctx context.Context, ruleSetID int64) ([]RuleRevision, error)
	FrozenMemberList(ctx context.Context, ruleSetID int64) ([]FrozenMember, error)

	CreateCase(ctx context.Context, name, createdBy string) (int64, error)
	ListCases(ctx context.Context) ([]Case, error)
	SaveScan(ctx context.Context, caseID int64, s ScanRecord) (scanID int64, created bool, err error)
	ListScans(ctx context.Context, caseID int64) ([]ScanRecord, error)
	GetScan(ctx context.Context, scanID int64) (ScanRecord, error)
	FindingsForScan(ctx context.Context, scanID int64) ([]FindingRecord, error)
	CoverageForScan(ctx context.Context, scanID int64) ([]CoverageRecord, error)

	RecordDecision(ctx context.Context, d Decision) (int64, error)
	DecisionsFor(ctx context.Context, contentKeys []string) (map[string][]Decision, error)

	Audit(ctx context.Context, actor, action, subject string, detail any) error
}
