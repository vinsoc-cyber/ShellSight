package agentgen

import (
	"archive/zip"
	"bytes"
	"fmt"
	"sort"
	"time"
)

// archiveEpoch is every entry's modification time.
//
// A fixed instant, because G6 requires identical inputs to produce identical bytes and a zip
// entry's timestamp is part of those bytes.
//
// It is NOT what stops the clock leaking in -- measured 2026-09-04, and worth writing down because
// the obvious reading is wrong. archive/zip does not default Modified to now: CreateHeader takes the
// FileHeader as given, and writer.go:306 skips the whole timestamp block when Modified.IsZero(),
// leaving ModifiedDate and ModifiedTime at their zero value. So an archive written with no Modified
// at all is still byte-identical run to run. What the epoch buys is a timestamp that MEANS
// something: MS-DOS date 0 is not a date, and Go's own reader turns it back into 1979-11-30.
//
// 2026-01-01 UTC rather than the Unix epoch, because the zip format stores MS-DOS timestamps, which
// cannot represent anything before 1980 -- a 1970 value would be silently rewritten and the instant
// an extractor shows would not be the one set here.
var archiveEpoch = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// WriteArchive writes the agent zip.
//
// Deterministic by construction: entries are sorted by path, every timestamp is archiveEpoch, and
// the compression method is fixed. Sorting happens HERE rather than being required of the caller,
// because a caller that forgot would break G6 in a way no test of this function could see.
//
// The honest limit: identical bytes are guaranteed for identical inputs on the same Go toolchain.
// flate's output is stable within a Go release but is not a documented cross-version constant, so a
// toolchain upgrade may change the bytes while changing nothing about the agent.
func WriteArchive(staged []StagedFile) ([]byte, error) {
	if len(staged) == 0 {
		return nil, fmt.Errorf("an agent archive must contain at least one file")
	}
	ordered := make([]StagedFile, len(staged))
	copy(ordered, staged)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Path < ordered[j].Path })

	for i := 1; i < len(ordered); i++ {
		if ordered[i].Path == ordered[i-1].Path {
			return nil, fmt.Errorf(
				"%q appears twice: extractors disagree about which entry wins, so what lands on the "+
					"host would not be decided by us", ordered[i].Path)
		}
	}

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, f := range ordered {
		header := &zip.FileHeader{
			Name:     f.Path,
			Method:   zip.Deflate,
			Modified: archiveEpoch,
		}
		// 0o755 for everything. A generated agent's executables must be executable on a Linux
		// target, and the zip is the only place that bit can be carried -- Windows ignores it.
		// Marking the data files executable too is harmless and keeps the header constant.
		header.SetMode(0o755)
		w, err := zw.CreateHeader(header)
		if err != nil {
			return nil, fmt.Errorf("creating %q: %w", f.Path, err)
		}
		if _, err := w.Write(f.Body); err != nil {
			return nil, fmt.Errorf("writing %q: %w", f.Path, err)
		}
	}
	if err := zw.Close(); err != nil {
		return nil, fmt.Errorf("closing the archive: %w", err)
	}
	return buf.Bytes(), nil
}
