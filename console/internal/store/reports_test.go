package store

import (
	"context"
	"sync"
	"testing"
)

func seedCase(t *testing.T, s *PG, name string) int64 {
	t.Helper()
	id, err := s.CreateCase(context.Background(), name, "v.quannh67")
	if err != nil {
		t.Fatalf("create case: %v", err)
	}
	return id
}

func sampleScan(runID, host string) ScanRecord {
	return ScanRecord{
		RunID: runID, Host: host, ToolVersion: "1.0.0", Operator: "svc-ir",
		Tier: "confirmed", Score: 90, Incomplete: false, Integrity: "verified",
		Coverage: []CoverageRecord{{
			View: "disk", Status: "ran", TargetsScanned: 3, Unreadable: 2,
		}},
		Findings: []FindingRecord{
			{Ref: "aaa-ObfuscatedPhp", ContentKey: "sha256:aa", Host: host, View: "disk",
				FilePath: `C:\www\shell.php`, FileSHA256: "aa", Basis: "signature",
				KnowledgeRef: "kb:yara/ObfuscatedPhp", Score: 70, Tier: "likely-malicious",
				Fingerprint: "fp1"},
			{Ref: "aaa-DodgyPhp", ContentKey: "sha256:aa", Host: host, View: "disk",
				FilePath: `C:\www\shell.php`, FileSHA256: "aa", Basis: "signature",
				KnowledgeRef: "kb:yara/DodgyPhp", Score: 70, Tier: "likely-malicious",
				Fingerprint: "fp2"},
		},
	}
}

func TestSaveScanStoresFindingsAndCoverage(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	c := seedCase(t, s, "IR-1")

	id, created, err := s.SaveScan(ctx, c, sampleScan("run-1", "web-01"))
	if err != nil {
		t.Fatalf("save: %v", err)
	}
	if !created {
		t.Fatal("first save should report created")
	}
	if id == 0 {
		t.Fatal("no scan id")
	}

	got, err := s.FindingsForScan(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d findings, want 2", len(got))
	}
	cov, err := s.CoverageForScan(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if len(cov) != 1 || cov[0].Unreadable != 2 {
		t.Fatalf("coverage not stored: %+v", cov)
	}
}

func TestSavingTheSameRunTwiceDoesNotDuplicate(t *testing.T) {
	// Re-importing a run folder must be safe. Bulk import is the primary import, and an analyst
	// dragging the same folder twice is normal.
	s := newTestStore(t)
	ctx := context.Background()
	c := seedCase(t, s, "IR-1")

	first, created1, err := s.SaveScan(ctx, c, sampleScan("run-1", "web-01"))
	if err != nil {
		t.Fatal(err)
	}
	second, created2, err := s.SaveScan(ctx, c, sampleScan("run-1", "web-01"))
	if err != nil {
		t.Fatalf("second save must not error: %v", err)
	}
	if !created1 {
		t.Fatal("first save should report created")
	}
	if created2 {
		t.Fatal("second save must report NOT created")
	}
	if first != second {
		t.Fatalf("second save returned a different scan id: %d vs %d", first, second)
	}
	got, _ := s.FindingsForScan(ctx, first)
	if len(got) != 2 {
		t.Fatalf("re-import duplicated findings: got %d, want 2", len(got))
	}
}

func TestAPartialSaveLeavesNothingBehind(t *testing.T) {
	// A finding that violates a constraint must not leave a scan row with half its findings --
	// that would read as a completed scan that found less than it did.
	s := newTestStore(t)
	ctx := context.Background()
	c := seedCase(t, s, "IR-1")

	bad := sampleScan("run-bad", "web-01")
	bad.Findings = append(bad.Findings, bad.Findings[0]) // duplicate ref+fingerprint

	if _, _, err := s.SaveScan(ctx, c, bad); err == nil {
		t.Fatal("expected a duplicate finding to fail the save")
	}
	var n int
	if err := s.pool.QueryRow(ctx,
		`SELECT count(*) FROM scans WHERE run_id='run-bad'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatal("a failed save left a scan row behind")
	}
}

func TestConcurrentImportsOfTheSameRunYieldOneScan(t *testing.T) {
	// Bulk import is the primary path, and two analysts dragging in the same run folder is
	// ordinary rather than an error. The UNIQUE constraint on scans.run_id is what makes that
	// safe. A read-then-write pre-check does not: every writer can miss the read before any of
	// them writes, and then all but one get a raw duplicate-key error instead of the existing id.
	s := newTestStore(t)
	ctx := context.Background()
	caseID := seedCase(t, s, "IR-race")

	const writers = 8
	ids := make(chan int64, writers)
	flags := make(chan bool, writers)
	errs := make(chan error, writers)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start // release them together, so they genuinely overlap
			id, created, err := s.SaveScan(ctx, caseID, sampleScan("run-raced", "web-01"))
			if err != nil {
				errs <- err
				return
			}
			ids <- id
			flags <- created
		}()
	}
	close(start)
	wg.Wait()
	close(ids)
	close(flags)
	close(errs)

	for err := range errs {
		t.Errorf("concurrent save: %v", err)
	}
	var first int64
	seen := 0
	for id := range ids {
		seen++
		if first == 0 {
			first = id
		}
		if id != first {
			t.Errorf("one run_id produced two scan ids: %d and %d", first, id)
		}
	}
	if seen != writers {
		t.Fatalf("%d of %d writers returned an id", seen, writers)
	}
	creates := 0
	for created := range flags {
		if created {
			creates++
		}
	}
	if creates != 1 {
		t.Errorf("created=true returned %d times, want exactly 1", creates)
	}

	var rows int
	if err := s.pool.QueryRow(ctx,
		`SELECT count(*) FROM scans WHERE run_id='run-raced'`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 1 {
		t.Errorf("%d scan rows for one run_id, want 1", rows)
	}
}

func TestADecisionMadeOnOneCaseSurfacesOnAnother(t *testing.T) {
	// The compounding property. Same content, different engagement, judgement carries over.
	s := newTestStore(t)
	ctx := context.Background()
	contoso := seedCase(t, s, "IR-contoso")
	acme := seedCase(t, s, "IR-acme")

	if _, err := s.RecordDecision(ctx, Decision{
		ContentKey: "sha256:aa", Verdict: "malicious",
		Note: "legacy admin backdoor", Author: "a-teammate", CaseID: &contoso,
	}); err != nil {
		t.Fatalf("record: %v", err)
	}

	// The same content turns up on a different case.
	if _, _, err := s.SaveScan(ctx, acme, sampleScan("run-acme", "acme-web")); err != nil {
		t.Fatal(err)
	}

	got, err := s.DecisionsFor(ctx, []string{"sha256:aa"})
	if err != nil {
		t.Fatal(err)
	}
	prior := got["sha256:aa"]
	if len(prior) != 1 {
		t.Fatalf("got %d prior decisions, want 1", len(prior))
	}
	if prior[0].CaseName != "IR-contoso" {
		t.Fatalf("prior decision names case %q, want IR-contoso", prior[0].CaseName)
	}
	if prior[0].Verdict != "malicious" {
		t.Fatalf("verdict = %q", prior[0].Verdict)
	}
}

func TestDecisionsAreAppendOnly(t *testing.T) {
	// A changed mind is a new row. The history of what the team believed, and when, survives.
	s := newTestStore(t)
	ctx := context.Background()
	c := seedCase(t, s, "IR-1")
	for _, v := range []string{"malicious", "false-positive"} {
		if _, err := s.RecordDecision(ctx, Decision{
			ContentKey: "sha256:bb", Verdict: v, Author: "a", CaseID: &c,
		}); err != nil {
			t.Fatal(err)
		}
	}
	got, _ := s.DecisionsFor(ctx, []string{"sha256:bb"})
	if len(got["sha256:bb"]) != 2 {
		t.Fatalf("got %d decisions, want both retained", len(got["sha256:bb"]))
	}
	if got["sha256:bb"][0].Verdict != "false-positive" {
		t.Fatal("newest decision must sort first")
	}
}

func TestAnInvalidVerdictIsRejected(t *testing.T) {
	s := newTestStore(t)
	c := seedCase(t, s, "IR-1")
	if _, err := s.RecordDecision(context.Background(), Decision{
		ContentKey: "sha256:cc", Verdict: "probably-fine", Author: "a", CaseID: &c,
	}); err == nil {
		t.Fatal("expected an unknown verdict to be rejected by the CHECK constraint")
	}
}
