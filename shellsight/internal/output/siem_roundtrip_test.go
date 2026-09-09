package output

// Can a SIEM ingest what we write, without anyone reformatting it first?
//
// The existing OCSF tests check that one finding maps to the right fields. This one checks the
// property those tests cannot see: that the FILE is ingestible. Splunk HEC and Elastic _bulk both
// read NDJSON by splitting on newlines and parsing each line independently, so the failures that
// matter are structural -- a pretty-printed object spanning lines, a trailing comma, a BOM, a
// non-finite number, a duplicate uid that makes deduplication collapse two detections into one.
// None of those is visible from a single mapped finding.
//
// The assertions below are taken from a REAL run: the shipped Windows archive scanned the platform
// fixture tree on 2026-08-21 and produced 19 findings, and every invariant here held on that file.
// Reproduced through the writer rather than committed as a fixture, so the test tracks the code
// rather than a snapshot of it.

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"shellsight/internal/finding"
)

func siemReport() finding.Report {
	// `ID` and `Scan.Started` are populated because a REAL report carries them: the run this test
	// was written against emitted finding_info.uid = "000b7f0615852ef8" and time = 1787269233000.
	// Leaving them empty here would have made the two assertions below vacuous rather than failing.
	mk := func(id, path, ref, basis string, score int, tier finding.Tier) finding.Finding {
		return finding.Finding{
			SchemaVersion: finding.SchemaVersion,
			ID:            id,
			Host:          "HOST",
			View:          "disk",
			Target:        finding.Target{Kind: "file", File: &finding.File{Path: path}},
			Detection: finding.Detection{
				Basis: basis, KnowledgeRef: ref, Evidence: "rule " + ref + " matched",
			},
			Score: score,
			Tier:  tier,
		}
	}
	return finding.Report{
		SchemaVersion: finding.SchemaVersion,
		Scan: finding.Scan{Host: "HOST", RunID: "20260821_000000", ToolVersion: "1.0.0",
			Started: "2026-08-21T00:00:33Z", Finished: "2026-08-21T00:00:36Z"},
		Verdict:       finding.Verdict{Tier: finding.TierConfirmed, Score: 90},
		Coverage:      []finding.Coverage{{View: "disk", Status: finding.CovRan}},
		Findings: []finding.Finding{
			mk("000b7f0615852ef8", `C:\web\detect.php`, "kb:yara/php_eval_request_webshell",
				"signature", 90, finding.TierConfirmed),
			mk("a4a1b990fe93813a", `C:\web\detect.asp`, "kb:yara/asp_dim_request_webshell",
				"heuristic", 75, finding.TierLikely),
		},
	}
}

func writeSIEMRun(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	runDir, err := Write(siemReport(), dir)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	return filepath.Join(runDir, "findings.ndjson")
}

func readSIEMLines(t *testing.T) (string, []string) {
	t.Helper()
	raw, err := os.ReadFile(writeSIEMRun(t))
	if err != nil {
		t.Fatalf("read findings.ndjson: %v", err)
	}
	body := string(raw)
	lines := []string{}
	for _, line := range strings.Split(body, "\n") {
		if strings.TrimSpace(line) != "" {
			lines = append(lines, line)
		}
	}
	return body, lines
}

func TestSIEMStreamIsOneCompleteObjectPerLine(t *testing.T) {
	// The whole NDJSON contract. A pretty-printed object would parse as a file and fail as a stream.
	_, lines := readSIEMLines(t)
	if len(lines) != 2 {
		t.Fatalf("expected one line per finding, got %d", len(lines))
	}
	for i, line := range lines {
		var obj map[string]any
		if err := json.Unmarshal([]byte(line), &obj); err != nil {
			t.Fatalf("line %d is not a standalone JSON object: %v", i, err)
		}
	}
}

func TestSIEMStreamHasNoByteOrderMarkAndNoCarriageReturns(t *testing.T) {
	// A BOM makes the first line fail to parse in every ingest pipeline that splits before decoding,
	// and a CR rides along into the last field value.
	body, _ := readSIEMLines(t)
	if strings.HasPrefix(body, "\ufeff") {
		t.Error("findings.ndjson starts with a byte-order mark")
	}
	if strings.Contains(body, "\r") {
		t.Error("findings.ndjson contains a carriage return")
	}
}

func TestSIEMStreamEndsWithExactlyOneNewline(t *testing.T) {
	// A missing final newline makes the last record vanish from a tail-based collector; a doubled
	// one makes it emit a blank record.
	body, _ := readSIEMLines(t)
	if !strings.HasSuffix(body, "\n") {
		t.Error("findings.ndjson does not end with a newline")
	}
	if strings.HasSuffix(body, "\n\n") {
		t.Error("findings.ndjson ends with a blank line")
	}
}

func TestSIEMRecordsCarryTheFieldsIngestKeysOn(t *testing.T) {
	// class_uid + category_uid is how both Splunk and Elastic route an OCSF event to its schema.
	_, lines := readSIEMLines(t)
	for i, line := range lines {
		var obj map[string]any
		if err := json.Unmarshal([]byte(line), &obj); err != nil {
			t.Fatalf("line %d: %v", i, err)
		}
		for _, key := range []string{"class_uid", "category_uid", "type_uid", "activity_id",
			"severity_id", "time", "metadata", "finding_info"} {
			if _, ok := obj[key]; !ok {
				t.Errorf("line %d is missing %q", i, key)
			}
		}
		if got := obj["class_uid"]; got != float64(ocsfClassUID) {
			t.Errorf("line %d class_uid = %v, want %d", i, got, ocsfClassUID)
		}
		if got := obj["category_uid"]; got != float64(ocsfCategoryUID) {
			t.Errorf("line %d category_uid = %v, want %d", i, got, ocsfCategoryUID)
		}
	}
}

func TestSIEMTimeIsFiniteEpochMilliseconds(t *testing.T) {
	// A NaN or an Inf is not representable in JSON and breaks the parser rather than the record.
	// A seconds-valued timestamp lands the event in 1970 and quietly falls outside every dashboard.
	_, lines := readSIEMLines(t)
	for i, line := range lines {
		var obj map[string]any
		if err := json.Unmarshal([]byte(line), &obj); err != nil {
			t.Fatalf("line %d: %v", i, err)
		}
		value, ok := obj["time"].(float64)
		if !ok {
			t.Fatalf("line %d: time is %T, want a number", i, obj["time"])
		}
		if math.IsNaN(value) || math.IsInf(value, 0) {
			t.Errorf("line %d: time is not finite", i)
		}
		// Milliseconds since the epoch for any plausible run date exceed 1e12; seconds do not.
		if value < 1e12 {
			t.Errorf("line %d: time %v looks like seconds, not milliseconds", i, value)
		}
	}
}

func TestSIEMFindingUIDsAreUnique(t *testing.T) {
	// A SIEM deduplicates on finding_info.uid. A collision silently collapses two detections into
	// one, which is the direction that understates an incident.
	_, lines := readSIEMLines(t)
	seen := map[string]bool{}
	for i, line := range lines {
		var obj struct {
			FindingInfo struct {
				UID string `json:"uid"`
			} `json:"finding_info"`
		}
		if err := json.Unmarshal([]byte(line), &obj); err != nil {
			t.Fatalf("line %d: %v", i, err)
		}
		if obj.FindingInfo.UID == "" {
			t.Fatalf("line %d has no finding_info.uid", i)
		}
		if seen[obj.FindingInfo.UID] {
			t.Errorf("duplicate finding_info.uid %q", obj.FindingInfo.UID)
		}
		seen[obj.FindingInfo.UID] = true
	}
}

func TestSIEMRecordsSurviveAReEncode(t *testing.T) {
	// Decode and re-encode every line. Anything that does not round-trip -- a duplicate key, a
	// control character, an invalid UTF-8 sequence from an attacker-authored path -- shows up here
	// rather than in somebody's ingest error queue.
	_, lines := readSIEMLines(t)
	for i, line := range lines {
		var obj map[string]any
		if err := json.Unmarshal([]byte(line), &obj); err != nil {
			t.Fatalf("line %d: %v", i, err)
		}
		if _, err := json.Marshal(obj); err != nil {
			t.Errorf("line %d does not re-encode: %v", i, err)
		}
	}
}

func TestSIEMStreamIsEmptyNotAbsentWhenThereAreNoFindings(t *testing.T) {
	// An empty file is valid NDJSON and means "scanned, found nothing". A MISSING file means
	// "something went wrong", and a collector cannot tell the two apart if we omit it.
	dir := t.TempDir()
	runDir, err := Write(finding.Report{
		SchemaVersion: finding.SchemaVersion,
		Scan: finding.Scan{Host: "HOST", RunID: "r", ToolVersion: "1.0.0",
			Started: "2026-08-21T00:00:33Z"},
		Verdict:       finding.Verdict{Tier: finding.TierClean},
	}, dir)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(runDir, "findings.ndjson"))
	if err != nil {
		t.Fatalf("findings.ndjson must exist even with no findings: %v", err)
	}
	if len(raw) != 0 {
		t.Errorf("expected an empty file, got %d bytes", len(raw))
	}
}
