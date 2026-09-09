// Package reports ingests scanner run folders into the console.
//
// It is the seam between the scanner's report format and the console's storage: report parsing
// knows nothing about the database, and the store knows nothing about report.json.
package reports

import (
	"context"
	"fmt"
	"time"

	"shellsightconsole/internal/report"
	"shellsightconsole/internal/store"
)

// ScanSaver is the slice of store.Store this service needs.
type ScanSaver interface {
	SaveScan(ctx context.Context, caseID int64, s store.ScanRecord) (int64, bool, error)
}

type Service struct{ store ScanSaver }

func NewService(s ScanSaver) *Service { return &Service{store: s} }

// Result describes what an ingest did.
type Result struct {
	ScanID    int64  `json:"scan_id"`
	RunID     string `json:"run_id"`
	Host      string `json:"host"`
	Created   bool   `json:"created"`
	Findings  int    `json:"findings"`
	Integrity string `json:"integrity"`
}

// IngestFolder reads a run folder and stores it.
//
// Re-ingesting a run folder is NOT an error: bulk import is the primary import and an analyst
// dragging the same folder twice is ordinary. Created reports which happened.
func (s *Service) IngestFolder(ctx context.Context, caseID int64, dir string) (Result, error) {
	loaded, err := report.LoadRunFolder(dir)
	if err != nil {
		return Result{}, err
	}
	return s.save(ctx, caseID, loaded)
}

// Ingest is IngestFolder for bytes that never touched this machine's disk -- an upload from the
// console UI. The scanner runs on the target host, so its run folder is on the ANALYST's laptop or
// a share, not on the console server; requiring a server-side path meant the only way in was a
// shell on the console box.
//
// source records where the bytes came from, for the audit trail: a folder path from the CLI, and
// the uploaded filename from the browser.
func (s *Service) Ingest(ctx context.Context, caseID int64, body, manifest []byte, source string) (Result, error) {
	loaded, err := report.Load(body, manifest, source)
	if err != nil {
		return Result{}, err
	}
	return s.save(ctx, caseID, loaded)
}

func (s *Service) save(ctx context.Context, caseID int64, loaded report.Loaded) (Result, error) {
	rec := toScanRecord(loaded)
	id, created, err := s.store.SaveScan(ctx, caseID, rec)
	if err != nil {
		return Result{}, fmt.Errorf("storing scan %s: %w", rec.RunID, err)
	}
	return Result{
		ScanID: id, RunID: rec.RunID, Host: rec.Host, Created: created,
		Findings: len(rec.Findings), Integrity: rec.Integrity,
	}, nil
}

func toScanRecord(l report.Loaded) store.ScanRecord {
	r := l.Report
	rec := store.ScanRecord{
		RunID: r.Scan.RunID, Host: r.Scan.Host, ToolVersion: r.Scan.ToolVersion,
		Operator: r.Scan.Operator, Invocation: r.Scan.Invocation,
		BuildID: r.Scan.BuildID, RuleSet: r.Scan.RuleSet,
		Tier: r.Verdict.Tier, Score: r.Verdict.Score, Incomplete: r.Verdict.Incomplete,
		Integrity: l.Integrity, Source: l.Source,
		Started: parseTime(r.Scan.Started), Finished: parseTime(r.Scan.Finished),
	}
	for _, c := range r.Coverage {
		cr := store.CoverageRecord{
			View: c.View, Status: c.Status, Reason: c.Reason, TargetsScanned: c.TargetsScanned,
		}
		if c.Skipped != nil {
			cr.NonRegular = c.Skipped.NonRegular
			cr.Unreadable = c.Skipped.Unreadable
			cr.OversizeSkipped = c.Skipped.OversizeSkipped
			cr.NoLanguageDetector = c.Skipped.NoLanguageDetector
		}
		rec.Coverage = append(rec.Coverage, cr)
	}
	for _, f := range r.Findings {
		fr := store.FindingRecord{
			Ref: f.ID, ContentKey: report.ContentKey(f), Host: f.Host, View: f.View,
			ArtifactKind: f.Artifact.Kind, ArtifactID: f.Artifact.Identity,
			Basis: f.Detection.Basis, KnowledgeRef: f.Detection.KnowledgeRef,
			Evidence: f.Detection.Evidence, Score: f.Score, Tier: f.Tier,
			Mitre: f.Mitre, Fingerprint: f.Fingerprint,
		}
		if f.Target.File != nil {
			fr.FilePath = f.Target.File.Path
			fr.FileSHA256 = f.Target.File.SHA256
		}
		rec.Findings = append(rec.Findings, fr)
	}
	return rec
}

// parseTime tolerates an absent or unparseable timestamp. A report that cannot state when it ran
// is still worth storing; refusing it would lose evidence over a formatting detail.
func parseTime(s string) *time.Time {
	if s == "" {
		return nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return nil
	}
	return &t
}
