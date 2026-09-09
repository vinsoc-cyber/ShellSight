package main

import (
	"os"
	"path/filepath"
	"testing"
)

// corpusDir is the labeled disk-efficacy fixture set. It was moved on 2026-07-27 into the
// gitignored corpus root beside the repo (shellsight-corpus/curated/disk/synthetic-efficacy),
// so all samples live in one place. A clone without the corpus mounted will not have these;
// TestDiskEfficacy skips in that case (see the os.Stat guard below). Override with
// SHELLSIGHT_CORPUS_PATH (which is then joined with the label directly).
func corpusDir(label string) string {
	if p := os.Getenv("SHELLSIGHT_CORPUS_PATH"); p != "" {
		return filepath.Join(p, label)
	}
	return filepath.Join(repoRoot(), "..", "shellsight-corpus", "curated", "disk", "synthetic-efficacy", label)
}

// TestDiskEfficacy measures detection rate (malicious flagged) + false-positive rate (benign
// flagged) over the labeled corpus, using the real yr scan path. Acceptance gate: every
// malicious file is flagged AND no benign file is flagged.
func TestDiskEfficacy(t *testing.T) {
	yr := yrPath()
	if yr == "" {
		t.Skip("yr binary not found — see Plan 3 Task 0")
	}
	if _, err := os.Stat(corpusDir("malicious")); err != nil {
		t.Skipf("disk-efficacy fixtures not mounted (%v); they live in the gitignored "+
			"shellsight-corpus/curated/disk/synthetic-efficacy — set SHELLSIGHT_CORPUS_PATH to override", err)
	}
	rules := rulesDir()

	mal, malOK, malFail := scanWebrootDirs(yr, rules, []string{corpusDir("malicious")}, "EVAL")
	ben, benOK, benFail := scanWebrootDirs(yr, rules, []string{corpusDir("benign")}, "EVAL")
	if malOK != 1 || len(malFail) != 0 || benOK != 1 || len(benFail) != 0 {
		t.Fatalf("both corpus roots must scan cleanly; malOK=%d malFail=%v benOK=%d benFail=%v", malOK, malFail, benOK, benFail)
	}

	// Count distinct malicious files flagged (a file may match >1 rule → one finding each).
	flaggedMal := map[string]bool{}
	for _, f := range mal {
		if f.Target.File != nil {
			flaggedMal[f.Target.File.Path] = true
		}
	}
	flaggedBen := map[string]bool{}
	for _, f := range ben {
		if f.Target.File != nil {
			flaggedBen[f.Target.File.Path] = true
		}
	}

	const wantMal = 3 // shell.php, shell.jsp, shell.aspx
	detRate := float64(len(flaggedMal)) / float64(wantMal) * 100
	fpRate := float64(len(flaggedBen)) / 3.0 * 100
	t.Logf("DISK efficacy: detection=%.0f%% (%d/%d malicious flagged), FP=%.0f%% (%d/3 benign flagged)",
		detRate, len(flaggedMal), wantMal, fpRate, len(flaggedBen))

	if len(flaggedMal) != wantMal {
		t.Fatalf("detection gate: want all %d malicious flagged, got %d (%v)", wantMal, len(flaggedMal), flaggedMal)
	}
	if len(flaggedBen) != 0 {
		t.Fatalf("FP gate: benign files must NOT be flagged, got %d (%v)", len(flaggedBen), flaggedBen)
	}
}
