package agentgen

import (
	"archive/zip"
	"bytes"
	"strings"
	"testing"
	"time"
)

func sample() []StagedFile {
	return []StagedFile{
		{Path: "shellsight", Body: []byte("orchestrator")},
		{Path: "third_party/yara-x/yr", Body: []byte("yr")},
		{Path: AgentPath, Body: []byte("{}\n")},
	}
}

// G6. Not "the same files are present" -- the same BYTES.
func TestTheSameInputsProduceTheSameArchiveBytes(t *testing.T) {
	first, err := WriteArchive(sample())
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	for i := 0; i < 5; i++ {
		again, err := WriteArchive(sample())
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(first, again) {
			t.Fatalf("archive %d differs from the first (%d vs %d bytes); G6 requires identical "+
				"inputs to produce identical bytes", i, len(first), len(again))
		}
	}
}

// Input order must not change the output: the caller resolved a sorted set, and a zip whose entry
// order depended on map iteration upstream would break G6 for a reason invisible here.
func TestArchiveEntryOrderDoesNotDependOnInputOrder(t *testing.T) {
	forward := sample()
	backward := []StagedFile{forward[2], forward[1], forward[0]}
	a, err := WriteArchive(forward)
	if err != nil {
		t.Fatal(err)
	}
	b, err := WriteArchive(backward)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Error("entry order follows input order; sort inside WriteArchive so a caller cannot break G6")
	}
}

func TestTheArchiveHoldsEveryStagedFileWithItsBytes(t *testing.T) {
	raw, err := WriteArchive(sample())
	if err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatalf("the output is not a readable zip: %v", err)
	}
	if len(zr.File) != 3 {
		t.Fatalf("archive holds %d entries, want 3", len(zr.File))
	}
	found := map[string]bool{}
	for _, f := range zr.File {
		found[f.Name] = true
		if strings.ContainsRune(f.Name, '\\') {
			t.Errorf("entry %q uses a backslash; zip names are forward-slashed by specification", f.Name)
		}
	}
	for _, want := range []string{"shellsight", "third_party/yara-x/yr", AgentPath} {
		if !found[want] {
			t.Errorf("archive is missing %q", want)
		}
	}
}

// Every entry carries the timestamp this code chose, and that assertion is the whole reason this
// test exists rather than the byte-identity one alone.
//
// Measured 2026-09-04: deleting `Modified: archiveEpoch` from the FileHeader killed no test.
// archive/zip does not default Modified to now -- CreateHeader takes the header as given, and
// writer.go:306 skips the timestamp block entirely when Modified.IsZero(), leaving ModifiedDate and
// ModifiedTime at the struct's zero value. A constant. So byte-identity survives losing the epoch,
// and every entry then claims 1979-11-30 00:00:00 -- MS-DOS date 0, which is not a date, read back
// by Go's own reader. Determinism was being provided by the zero value, not by the choice, and the
// plan's three mutations could not tell the difference.
func TestEveryEntryCarriesTheTimestampThisCodeChose(t *testing.T) {
	raw, err := WriteArchive(sample())
	if err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range zr.File {
		if got := f.Modified.UTC(); !got.Equal(archiveEpoch) {
			t.Errorf("entry %q is stamped %s, want %s: a timestamp this code did not choose is one a "+
				"future change can move", f.Name, got.Format(time.RFC3339), archiveEpoch.Format(time.RFC3339))
		}
	}
}
func TestADuplicatePathIsRefused(t *testing.T) {
	dup := append(sample(), StagedFile{Path: "shellsight", Body: []byte("other")})
	if _, err := WriteArchive(dup); err == nil {
		t.Fatal("a duplicate entry must be refused: extractors disagree about which one wins, so the " +
			"agent that lands on the host is not decided by us")
	}
}

func TestAnEmptyArchiveIsRefused(t *testing.T) {
	if _, err := WriteArchive(nil); err == nil {
		t.Fatal("an empty archive must be refused rather than handed to an analyst")
	}
}
