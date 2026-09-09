package javadisk

import (
	"strings"
	"testing"
)

func TestDefaultOptionsMatchProductionCeilings(t *testing.T) {
	got := DefaultOptions().Limits
	if got.MaxArtifactBytes != 32<<20 || got.MaxArchiveEntries != 100_000 ||
		got.MaxEntryBytes != 32<<20 || got.MaxCompressedEntryBytes != 32<<20 ||
		got.MaxArchiveBytes != 2<<30 ||
		got.MaxCompressionRatio != 200 || got.MaxNestedDepth != 2 ||
		got.CompressionRatioFloor != 64<<10 || got.MaxMethods != 65_535 ||
		got.MaxInstructions != 250_000 || got.MaxArtifactInstructions != 5_000_000 ||
		got.MaxStateMerges != 1_000_000 || got.MaxClasses != 50_000 ||
		got.MaxFrameSlots != 16_384 || got.MaxAnnotationDepth != 32 ||
		got.MaxSummaryRounds != 32 || got.MaxCallTargets != 64 ||
		got.MaxProvenanceSteps != 16 || got.MaxRetainedClassBytes != 256<<20 ||
		got.MaxConstantBytes != 4<<10 || got.MaxDecodedBytes != 1<<20 ||
		got.MaxFindings != 10_000 {
		t.Fatalf("unexpected limits: %+v", got)
	}
}

func TestNormalizeOptionsFillsInvalidValuesAndPreservesOverrides(t *testing.T) {
	got := normalizeOptions(Options{Limits: Limits{MaxInstructions: 17}})
	if got.Limits.MaxInstructions != 17 || got.Limits.MaxArtifactBytes != 32<<20 {
		t.Fatalf("normalizeOptions=%+v", got)
	}
	invalid := normalizeOptions(Options{Limits: Limits{MaxEntryBytes: -1}})
	if invalid.Limits.MaxEntryBytes != 32<<20 {
		t.Fatalf("negative limit was not normalized: %+v", invalid)
	}
}

func TestBoundedDiagnosticTextRemovesControlsAndCapsBytes(t *testing.T) {
	got := boundedDiagnosticText("bad\r\n" + strings.Repeat("x", 300))
	if strings.ContainsAny(got, "\r\n\t") || len(got) > 256 {
		t.Fatalf("unsafe diagnostic %q (%d bytes)", got, len(got))
	}
}

func TestParseOptionsJSONIsStrictAndFillsDefaults(t *testing.T) {
	got, err := ParseOptionsJSON([]byte(`{"limits":{"max_archive_entries":17}}`))
	if err != nil {
		t.Fatal(err)
	}
	if got.Limits.MaxArchiveEntries != 17 || got.Limits.MaxEntryBytes != 32<<20 {
		t.Fatalf("options=%+v", got)
	}
	for _, bad := range []string{
		`null`,
		`{}`,
		`{"limits":null}`,
		`{"limits":{"max_archive_entries":-1}}`,
		`{"limits":{"max_archive_entries":100001}}`,
		`{"limits":{"unknown_limit":1}}`,
		`{} trailing`,
	} {
		if _, err := ParseOptionsJSON([]byte(bad)); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}
