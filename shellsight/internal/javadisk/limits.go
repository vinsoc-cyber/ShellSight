package javadisk

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

type Limits struct {
	MaxArtifactBytes        int64 `json:"max_artifact_bytes"`
	MaxArchiveEntries       int   `json:"max_archive_entries"`
	MaxEntryBytes           int64 `json:"max_entry_bytes"`
	MaxCompressedEntryBytes int64 `json:"max_compressed_entry_bytes"`
	MaxArchiveBytes         int64 `json:"max_archive_bytes"`
	MaxCompressionRatio     int64 `json:"max_compression_ratio"`
	CompressionRatioFloor   int64 `json:"compression_ratio_floor"`
	MaxNestedDepth          int   `json:"max_nested_depth"`
	MaxMethods              int   `json:"max_methods"`
	MaxInstructions         int   `json:"max_instructions"`
	MaxArtifactInstructions int   `json:"max_artifact_instructions"`
	MaxStateMerges          int   `json:"max_state_merges"`
	MaxClasses              int   `json:"max_classes"`
	MaxFrameSlots           int   `json:"max_frame_slots"`
	MaxAnnotationDepth      int   `json:"max_annotation_depth"`
	MaxSummaryRounds        int   `json:"max_summary_rounds"`
	MaxCallTargets          int   `json:"max_call_targets"`
	MaxProvenanceSteps      int   `json:"max_provenance_steps"`
	MaxRetainedClassBytes   int64 `json:"max_retained_class_bytes"`
	MaxConstantBytes        int   `json:"max_constant_bytes"`
	MaxDecodedBytes         int64 `json:"max_decoded_bytes"`
	MaxFindings             int   `json:"max_findings"`
}

type Options struct {
	Limits   Limits
	Webroots []string
}

type Diagnostic struct {
	Artifact string
	Code     string
	Detail   string
	Count    int
}

type Result struct {
	Findings    []Finding
	Diagnostics []Diagnostic
}

const (
	diagClassMalformed      = "java-class-malformed"
	diagClassUnsupported    = "java-class-version-unsupported"
	diagClassDuplicate      = "java-class-duplicate-name"
	diagBytecodeUnsupported = "java-bytecode-unsupported"
	diagAnalysisBudget      = "java-analysis-budget-exhausted"
	diagArchiveBudget       = "java-archive-budget-exhausted"
	diagArtifactRead        = "java-artifact-read-failed"
	diagParserPanic         = "java-parser-panic-isolated"
	diagCancelled           = "java-analysis-cancelled"
)

// Exported diagnostic-code vocabulary. These are the SAME string values the unexported diag*
// constants above already carried; they are exported so an integration can build its own severity
// table from the canonical set instead of re-declaring string literals that silently drift. Purely
// additive: no analyzer behavior, diagnostic, finding or limit depends on these declarations.
const (
	DiagCodeClassMalformed      = diagClassMalformed
	DiagCodeClassUnsupported    = diagClassUnsupported
	DiagCodeClassDuplicate      = diagClassDuplicate
	DiagCodeBytecodeUnsupported = diagBytecodeUnsupported
	DiagCodeAnalysisBudget      = diagAnalysisBudget
	DiagCodeArchiveBudget       = diagArchiveBudget
	DiagCodeArtifactRead        = diagArtifactRead
	DiagCodeParserPanic         = diagParserPanic
	DiagCodeCancelled           = diagCancelled
)

// StableDiagnosticCodes returns every diagnostic code this package can emit, sorted. A consumer that
// maps codes to its own vocabulary should build its table from this slice so a code added here fails
// that consumer's coverage test rather than being silently ignored. The returned slice is a fresh
// copy on every call.
func StableDiagnosticCodes() []string {
	return []string{
		DiagCodeAnalysisBudget,      // java-analysis-budget-exhausted
		DiagCodeCancelled,           // java-analysis-cancelled
		DiagCodeArchiveBudget,       // java-archive-budget-exhausted
		DiagCodeArtifactRead,        // java-artifact-read-failed
		DiagCodeBytecodeUnsupported, // java-bytecode-unsupported
		DiagCodeClassDuplicate,      // java-class-duplicate-name
		DiagCodeClassMalformed,      // java-class-malformed
		DiagCodeClassUnsupported,    // java-class-version-unsupported
		DiagCodeParserPanic,         // java-parser-panic-isolated
	}
}

const maxDiagnosticTextBytes = 256

func boundedDiagnosticText(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			r = '?'
		}
		n := utf8.RuneLen(r)
		if n < 0 || b.Len()+n > maxDiagnosticTextBytes {
			break
		}
		b.WriteRune(r)
	}
	return b.String()
}

func newDiagnostic(artifact, code, detail string) Diagnostic {
	return Diagnostic{
		Artifact: boundedDiagnosticText(artifact),
		Code:     code,
		Detail:   boundedDiagnosticText(detail),
		Count:    1,
	}
}

func DefaultOptions() Options {
	return Options{Limits: Limits{
		MaxArtifactBytes:        32 << 20,
		MaxArchiveEntries:       100_000,
		MaxEntryBytes:           32 << 20,
		MaxCompressedEntryBytes: 32 << 20,
		MaxArchiveBytes:         2 << 30,
		MaxCompressionRatio:     200,
		CompressionRatioFloor:   64 << 10,
		MaxNestedDepth:          2,
		MaxMethods:              65_535,
		MaxInstructions:         250_000,
		MaxArtifactInstructions: 5_000_000,
		MaxStateMerges:          1_000_000,
		MaxClasses:              50_000,
		MaxFrameSlots:           16_384,
		MaxAnnotationDepth:      32,
		MaxSummaryRounds:        32,
		MaxCallTargets:          64,
		MaxProvenanceSteps:      16,
		MaxRetainedClassBytes:   256 << 20,
		MaxConstantBytes:        4 << 10,
		MaxDecodedBytes:         1 << 20,
		MaxFindings:             10_000,
	}}
}

func normalizeOptions(opts Options) Options {
	d := DefaultOptions().Limits
	fill64 := func(v *int64, x int64) {
		if *v <= 0 {
			*v = x
		}
	}
	fill := func(v *int, x int) {
		if *v <= 0 {
			*v = x
		}
	}
	fill64(&opts.Limits.MaxArtifactBytes, d.MaxArtifactBytes)
	fill(&opts.Limits.MaxArchiveEntries, d.MaxArchiveEntries)
	fill64(&opts.Limits.MaxEntryBytes, d.MaxEntryBytes)
	fill64(&opts.Limits.MaxCompressedEntryBytes, d.MaxCompressedEntryBytes)
	fill64(&opts.Limits.MaxArchiveBytes, d.MaxArchiveBytes)
	fill64(&opts.Limits.MaxCompressionRatio, d.MaxCompressionRatio)
	fill64(&opts.Limits.CompressionRatioFloor, d.CompressionRatioFloor)
	fill(&opts.Limits.MaxNestedDepth, d.MaxNestedDepth)
	fill(&opts.Limits.MaxMethods, d.MaxMethods)
	fill(&opts.Limits.MaxInstructions, d.MaxInstructions)
	fill(&opts.Limits.MaxArtifactInstructions, d.MaxArtifactInstructions)
	fill(&opts.Limits.MaxStateMerges, d.MaxStateMerges)
	fill(&opts.Limits.MaxClasses, d.MaxClasses)
	fill(&opts.Limits.MaxFrameSlots, d.MaxFrameSlots)
	fill(&opts.Limits.MaxAnnotationDepth, d.MaxAnnotationDepth)
	fill(&opts.Limits.MaxSummaryRounds, d.MaxSummaryRounds)
	fill(&opts.Limits.MaxCallTargets, d.MaxCallTargets)
	fill(&opts.Limits.MaxProvenanceSteps, d.MaxProvenanceSteps)
	fill64(&opts.Limits.MaxRetainedClassBytes, d.MaxRetainedClassBytes)
	fill(&opts.Limits.MaxConstantBytes, d.MaxConstantBytes)
	fill64(&opts.Limits.MaxDecodedBytes, d.MaxDecodedBytes)
	fill(&opts.Limits.MaxFindings, d.MaxFindings)
	return opts
}

func ParseOptionsJSON(data []byte) (Options, error) {
	var raw struct {
		Limits json.RawMessage `json:"limits"`
	}
	if data = bytes.TrimSpace(data); len(data) == 0 || data[0] != '{' {
		return Options{}, fmt.Errorf("options JSON must be an object")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&raw); err != nil {
		return Options{}, err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return Options{}, fmt.Errorf("options JSON contains multiple values")
		}
		return Options{}, err
	}

	if raw.Limits == nil {
		return Options{}, fmt.Errorf("options JSON must contain field %q", "limits")
	}
	limitsData := bytes.TrimSpace(raw.Limits)
	if len(limitsData) == 0 || limitsData[0] != '{' {
		return Options{}, fmt.Errorf("options JSON field %q must be an object", "limits")
	}
	var limits Limits
	decoder = json.NewDecoder(bytes.NewReader(limitsData))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&limits); err != nil {
		return Options{}, err
	}

	if err := validateLimits(limits); err != nil {
		return Options{}, err
	}
	return normalizeOptions(Options{Limits: limits}), nil
}

func validateLimits(l Limits) error {
	d := DefaultOptions().Limits
	for _, limit := range []struct {
		name string
		got  int64
		max  int64
	}{
		{"max_artifact_bytes", l.MaxArtifactBytes, d.MaxArtifactBytes},
		{"max_archive_entries", int64(l.MaxArchiveEntries), int64(d.MaxArchiveEntries)},
		{"max_entry_bytes", l.MaxEntryBytes, d.MaxEntryBytes},
		{"max_compressed_entry_bytes", l.MaxCompressedEntryBytes, d.MaxCompressedEntryBytes},
		{"max_archive_bytes", l.MaxArchiveBytes, d.MaxArchiveBytes},
		{"max_compression_ratio", l.MaxCompressionRatio, d.MaxCompressionRatio},
		{"compression_ratio_floor", l.CompressionRatioFloor, d.CompressionRatioFloor},
		{"max_nested_depth", int64(l.MaxNestedDepth), int64(d.MaxNestedDepth)},
		{"max_methods", int64(l.MaxMethods), int64(d.MaxMethods)},
		{"max_instructions", int64(l.MaxInstructions), int64(d.MaxInstructions)},
		{"max_artifact_instructions", int64(l.MaxArtifactInstructions), int64(d.MaxArtifactInstructions)},
		{"max_state_merges", int64(l.MaxStateMerges), int64(d.MaxStateMerges)},
		{"max_classes", int64(l.MaxClasses), int64(d.MaxClasses)},
		{"max_frame_slots", int64(l.MaxFrameSlots), int64(d.MaxFrameSlots)},
		{"max_annotation_depth", int64(l.MaxAnnotationDepth), int64(d.MaxAnnotationDepth)},
		{"max_summary_rounds", int64(l.MaxSummaryRounds), int64(d.MaxSummaryRounds)},
		{"max_call_targets", int64(l.MaxCallTargets), int64(d.MaxCallTargets)},
		{"max_provenance_steps", int64(l.MaxProvenanceSteps), int64(d.MaxProvenanceSteps)},
		{"max_retained_class_bytes", l.MaxRetainedClassBytes, d.MaxRetainedClassBytes},
		{"max_constant_bytes", int64(l.MaxConstantBytes), int64(d.MaxConstantBytes)},
		{"max_decoded_bytes", l.MaxDecodedBytes, d.MaxDecodedBytes},
		{"max_findings", int64(l.MaxFindings), int64(d.MaxFindings)},
	} {
		if limit.got < 0 || limit.got > limit.max {
			return fmt.Errorf("invalid limit %q: %d exceeds allowed range 0..%d", limit.name, limit.got, limit.max)
		}
	}
	return nil
}
