// Package finding defines the cross-probe contract: every probe emits []Finding,
// the core assembles them into a Report. JSON tags are the on-disk schema.
package finding

import (
	"encoding/json"
	"fmt"
	"strings"
	"unicode/utf8"
)

type Tier string

const (
	TierClean      Tier = "clean"
	TierSuspicious Tier = "suspicious"
	TierLikely     Tier = "likely-malicious"
	TierConfirmed  Tier = "confirmed"

	// TierUnknown is a VERDICT-only tier: the scan did not complete and found nothing, so no
	// statement about the host is warranted. Probes never emit it. It exists because "clean" on a
	// scan that failed or timed out is a false negative dressed as an all-clear, and scan cost
	// scales with obfuscation — so the timeout that produces it is likeliest exactly on the hosts
	// that matter. Never map this to clean; it means "ask again with more time".
	TierUnknown Tier = "unknown"
)

const SchemaVersion = "1.0"

// Behavioral-view knowledge references (the stable key fusion maps to ATT&CK techniques).
const (
	KBBehaviorViewState          = "kb:behavioral/viewstate-mac-failure" // ASP.NET ViewState MAC FAILURE (failed/keyless forge — NOT a successful key-signed attack)
	KBBehaviorIISConfig          = "kb:behavioral/iis-config-change"     // IIS module / web.config change
	KBBehaviorW3wpChild          = "kb:behavioral/w3wp-child-process"    // w3wp spawned a known shell/LOLBin
	KBBehaviorW3wpAnomalousChild = "kb:behavioral/w3wp-anomalous-child"  // w3wp spawned an unexpected child (non-shell, non-compiler) — migration target / dropped binary
)

type Finding struct {
	SchemaVersion  string            `json:"schema_version"`
	ID             string            `json:"id"`
	Host           string            `json:"host"`
	View           string            `json:"view"` // disk | java-mem | dotnet-mem | mock
	Target         Target            `json:"target"`
	Artifact       Artifact          `json:"artifact"`
	Detection      Detection         `json:"detection"`
	Score          int               `json:"score"`
	Tier           Tier              `json:"tier"`
	Classification Classification    `json:"classification"` // present-but-null in v1 (the hook)
	Artifacts      Artifacts         `json:"artifacts"`
	Context        map[string]string `json:"context,omitempty"`
	CorrelationID  string            `json:"correlation_id,omitempty"`
	Mitre          []string          `json:"mitre,omitempty"`       // ATT&CK technique IDs, e.g. ["T1505.003"]
	Fingerprint    string            `json:"fingerprint,omitempty"` // deterministic content hash (dedup/suppression key)
}

type Target struct {
	Kind    string   `json:"kind"` // process | file | dump
	Process *Process `json:"process,omitempty"`
	File    *File    `json:"file,omitempty"`
}
type Process struct {
	PID     int    `json:"pid"`
	Name    string `json:"name"`
	AppPool string `json:"app_pool,omitempty"`
	Bitness string `json:"bitness,omitempty"`
}
type File struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256,omitempty"`
}

type Artifact struct {
	Kind     string `json:"kind"`
	Identity string `json:"identity"`
	Location string `json:"location,omitempty"`
}

type Detection struct {
	Basis        string `json:"basis"` // structural-heuristic | signature | behavioral
	KnowledgeRef string `json:"knowledge_ref,omitempty"`
	Evidence     string `json:"evidence,omitempty"`
	Allowlisted  bool   `json:"allowlisted"`
}

// Classification is the architected-in hook: always emitted, always null in v1.
// Pointers/slice marshal to JSON null so the schema is stable for the Phase-3 classifier.
type Classification struct {
	Family     *string  `json:"family"`
	Capability []string `json:"capability"`
	Source     *string  `json:"source"`
	Confidence float64  `json:"confidence"`
}

type Artifacts struct {
	Raw        string `json:"raw,omitempty"`
	Decompiled string `json:"decompiled,omitempty"`
	Features   string `json:"features,omitempty"`
}

type Report struct {
	SchemaVersion  string     `json:"schema_version"`
	Scan           Scan       `json:"scan"`
	Verdict        Verdict    `json:"verdict"`
	Coverage       []Coverage `json:"coverage"`
	Findings       []Finding  `json:"findings"`
	ArtifactsDir   string     `json:"artifacts_dir,omitempty"`
	ManifestSHA256 string     `json:"manifest_sha256,omitempty"`
}
type Scan struct {
	Host        string `json:"host"`
	Started     string `json:"started"`
	Finished    string `json:"finished"`
	ToolVersion string `json:"tool_version"`
	KBVersion   string `json:"kb_version,omitempty"`
	RunID       string `json:"run_id"`
	Operator    string `json:"operator,omitempty"`   // OS user that ran the scan (chain-of-custody)
	Invocation  string `json:"invocation,omitempty"` // exact command line (reproducibility)
	// Webroots is the scope the disk view was actually given, after CLI > agent.json > discovery.
	//
	// Invocation alone cannot answer "what did this scan examine": a scope baked into agent.json
	// never appears on the command line, and one that came from auto-discovery appears nowhere at
	// all. A report that records a verdict without recording what it looked at leaves the reader to
	// assume, which is the same failure as a coverage figure that omits what it skipped.
	//
	// Empty means the disk view auto-discovered, which the coverage record already describes.
	Webroots []string `json:"webroots,omitempty"`
}
type Verdict struct {
	Tier       Tier `json:"tier"`
	Score      int  `json:"score"`
	Incomplete bool `json:"incomplete"`
}

// CoverageStatus values.
const (
	CovRan      = "ran"
	CovNA       = "n/a"
	CovDegraded = "degraded"
	CovFailed   = "failed"
)

type Coverage struct {
	View           string `json:"view"`
	Status         string `json:"status"`
	Reason         string `json:"reason,omitempty"`
	TargetsScanned int    `json:"targets_scanned"`
	// Skipped is carried through from the probe so the gap stays machine-readable end to end. The
	// Reason string also names the numbers, but a SIEM consumer should not have to parse prose.
	Skipped *ScanSkips `json:"skipped,omitempty"`
	// Discovery records how the scanned roots were located, when the probe found them itself.
	Discovery *DiscoveryReport `json:"discovery,omitempty"`
	// Scratch is the directory the probe used for its temporary workspace when the default temporary
	// location was not writable (spec 007 US3) -- a read-only container root with no /tmp. Set only
	// then, so an ordinary run's report is byte-identical; the directory is removed when the run ends
	// and this records where transient content briefly lived, for evidence handling.
	Scratch string `json:"scratch,omitempty"`
	// Truncated is carried through from ProbeCoverage.Truncated -- see the contract there. It is the
	// unbounded-gap flag: the probe stopped early and cannot say what it did not examine. Fusion
	// turns it into `incomplete`, so it must survive the hop from probe output into the report or
	// the verdict never learns about it.
	Truncated bool `json:"truncated,omitempty"`
}

// ProbeOutput is the richer probe stdout contract: findings + optional coverage. Probes may
// still emit a bare []Finding array (legacy); the core accepts both forms. A probe uses the
// coverage block to report honestly when it ran but could not actually cover its targets
// (e.g. the behavioral view on a host with process-auditing disabled).
//
// ArtifactCoverage is an OPT-IN observation channel (measurement builds only). It is nil in
// production, and `omitempty` keeps the emitted bytes identical to the pre-channel schema.
type ProbeOutput struct {
	Findings         []Finding          `json:"findings"`
	Coverage         *ProbeCoverage     `json:"coverage,omitempty"`
	ArtifactCoverage []ArtifactCoverage `json:"artifact_coverage,omitempty"`
}

// ArtifactCoverage statuses: how completely one physical artifact was analyzed.
const (
	ArtifactCovComplete = "complete" // analyzed end to end, no diagnostics
	ArtifactCovDegraded = "degraded" // analyzed, but a parser/unsupported/budget limit applied
	ArtifactCovFailed   = "failed"   // could not be read or hashed at all
)

// ArtifactCoverage records per-artifact analysis coverage. It is pure observation: nothing in it
// feeds rules, scores, tiers, sources, sinks or transforms. DiagnosticCodes is bounded to the
// analyzer's stable code vocabulary (sorted, deduplicated, never free-text detail) so nothing
// attacker-controlled can ride this channel.
type ArtifactCoverage struct {
	Path            string   `json:"path"`
	SHA256          string   `json:"sha256"`
	Status          string   `json:"status"`
	Bytes           int64    `json:"bytes"`
	DiagnosticCodes []string `json:"diagnostic_codes,omitempty"`
}

// ValidArtifactCovStatus reports whether s is one of the three defined artifact statuses.
func ValidArtifactCovStatus(s string) bool {
	switch s {
	case ArtifactCovComplete, ArtifactCovDegraded, ArtifactCovFailed:
		return true
	}
	return false
}

const maxArtifactStatusTextBytes = 32

// UnmarshalJSON rejects an unrecognized status. Coverage honesty runs both ways: an unknown
// vocabulary must fail loudly rather than be silently read as "this artifact was covered".
func (a *ArtifactCoverage) UnmarshalJSON(data []byte) error {
	type artifactCoverageFields ArtifactCoverage // sheds this method, so no recursion
	var raw artifactCoverageFields
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	if !ValidArtifactCovStatus(raw.Status) {
		return fmt.Errorf("unknown artifact coverage status %q", boundedStatusText(raw.Status))
	}
	*a = ArtifactCoverage(raw)
	return nil
}

// boundedStatusText keeps a rejected status quotable in an error without letting probe-supplied
// bytes (length or control characters) through unchecked.
func boundedStatusText(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			r = '?'
		}
		n := utf8.RuneLen(r)
		if n < 0 || b.Len()+n > maxArtifactStatusTextBytes {
			break
		}
		b.WriteRune(r)
	}
	return b.String()
}

// ProbeCoverage is the probe's self-reported coverage (View is stamped by the core).
type ProbeCoverage struct {
	Status         string `json:"status"` // ran | degraded | failed | n/a
	Reason         string `json:"reason,omitempty"`
	TargetsScanned int    `json:"targets_scanned"`
	// Skipped is set by probes that walk a filesystem and nil for those that do not, so its
	// absence means "not applicable" rather than "nothing was skipped".
	Skipped *ScanSkips `json:"skipped,omitempty"`
	// Discovery records how the scanned roots were located, when the probe found them itself.
	Discovery *DiscoveryReport `json:"discovery,omitempty"`
	// Scratch mirrors Coverage.Scratch: the fallback temporary workspace, when one was used.
	Scratch string `json:"scratch,omitempty"`
	// Truncated says the probe STOPPED EARLY and cannot enumerate what it did not examine.
	//
	// This is the difference between two kinds of gap that `degraded` alone cannot tell apart:
	//
	//   bounded   — "2 entries not examined: 0 non-regular, 0 unreadable, 0 oversize, 2 examined by
	//               no language-specific detector". The reader knows exactly what was missed, so a
	//               clean verdict still means something. This is the NORMAL state of a disk scan.
	//   unbounded — "in-JVM sweep truncated: time budget exhausted after 0 class(es) captured". The
	//               probe does not know what is in the part it never reached, so the evidence could
	//               be anywhere in it and a clean verdict claims coverage the run did not have.
	//
	// Only the second sets this. Fusion turns it into `incomplete`, which turns a clean tier into
	// `unknown` and exit 5 — because a truncated sweep that found nothing has not established that
	// there was nothing to find. Verified on a live Tomcat holding a resident Suo5 memshell: with
	// the agent budget forced to 1 ms the scan returned verdict=clean, incomplete=false, exit 0.
	//
	// omitempty, so a probe that ran to completion emits byte-identical output to before this field
	// existed. The tempting alternative was to always serialise it, on the reasoning that "absent"
	// and "false" are different claims. They are — but not in a way that changes any decision here:
	// an old probe binary paired with a new core omits the field either way, and the core cannot
	// require it without rejecting every probe that predates it. So always-serialising buys no
	// protection against version skew and costs a change to every probe's output, which
	// cmd/diskprobe's own production-compatibility gate exists to prevent.
	Truncated bool `json:"truncated,omitempty"`
}

// ScanSkips counts what a filesystem-walking probe declined to read (spec 002 data-model E3).
//
// Every field is serialised even when zero: a scan that skipped nothing must SAY it skipped
// nothing, because a missing counter and a zero counter are the difference between an assertion
// and an absence of evidence. Before this existed, a file the scanner could not read was dropped
// silently while the run still reported success.
type ScanSkips struct {
	// NonRegular is entries rejected by the file-kind allowlist: FIFO, socket, device, dangling or
	// circular link, or a link resolving outside the scanned roots.
	NonRegular int `json:"non_regular"`
	// Unreadable is entries that exist and are ordinary but could not be opened or read.
	Unreadable int `json:"unreadable"`
	// OversizeSkipped is ordinary files past the in-memory read bound. The engine still scans
	// these; the deobfuscation and taint passes do not.
	OversizeSkipped int `json:"oversize_skipped"`
	// NoLanguageDetector is files no LANGUAGE-SPECIFIC detector examined: the name claimed no
	// language and the content matched no language sign, or the file was past the in-memory read
	// bound so no sign could be taken.
	//
	// THE NAME IS PRECISE ON PURPOSE. These files WERE scanned -- every third-party rule is unscoped
	// and fires on any file whatever its name. Calling this `not_scanned` would over-report the gap,
	// which is the same dishonesty as hiding it, in the other direction. What it discloses is that
	// the language-declaring rules and the taint passes did not look, so "no finding here" is a
	// weaker statement for these files than for the rest.
	NoLanguageDetector int `json:"no_language_detector"`
}

// Total is the number of entries that were not fully examined. A non-zero total degrades the
// record (FR-017) without marking coverage incomplete -- a skipped device is a disclosed gap, not
// a broken scan.
func (s ScanSkips) Total() int {
	return s.NonRegular + s.Unreadable + s.OversizeSkipped + s.NoLanguageDetector
}

// DiscoveryReport is how a probe's scan targets were located, carried end to end so a responder can
// tell a directory read out of live configuration from one guessed off a distro default (FR-036).
//
// Nil when the probe was handed its targets explicitly: absence means discovery did not run, not
// that it found nothing. That is the same distinction ScanSkips draws, for the same reason -- the
// difference between an assertion and an absence of evidence.
//
// The shape is deliberately duplicated from internal/discover rather than shared: this is the wire
// contract, and it owns its own JSON tags so a refactor inside discovery cannot silently change
// what a SIEM consumer receives.
type DiscoveryReport struct {
	Roots      []DiscoveredRoot     `json:"roots"`
	Mechanisms []DiscoveryMechanism `json:"mechanisms"`
	// Rejected is a path a mechanism proposed that did not survive validation. Reported, not
	// dropped: a config naming a directory that vanished, or one pointing at the filesystem root,
	// is itself worth seeing during an incident.
	//
	// BOUNDED. Every input discovery reads is attacker-writable, so the volume is attacker-chosen: a
	// config with 50,000 root directives would otherwise put 50,000 entries here and 50,000 lines in
	// the report, burying every real finding for the price of editing a file. RejectedTotal carries
	// the true count so the bound is visible rather than silent.
	Rejected      []DiscoveryRejection `json:"rejected,omitempty"`
	RejectedTotal int                  `json:"rejected_total,omitempty"`
}

// DiscoveredRoot is one scanned directory and its provenance.
type DiscoveredRoot struct {
	Path      string `json:"path"`
	Mechanism string `json:"mechanism"`
	// Source is the config file or environment variable the path came from, empty for a
	// conventional location, which has no source to cite.
	Source string `json:"source,omitempty"`
	// InFilesystem is the path as the SCANNED filesystem names it, when that differs from where it was
	// reachable during the scan. On a mounted image the config says /var/www/html and the scanner opens
	// /mnt/image/var/www/html; a report needs both, because the first is what the compromised host was
	// serving and the second is only where the disk happened to be attached.
	InFilesystem string `json:"in_filesystem,omitempty"`
	// AlsoFoundBy names other mechanisms that independently proposed this directory. Two mechanisms
	// agreeing is better evidence than one.
	AlsoFoundBy []string `json:"also_found_by,omitempty"`
	// Subsumes lists directories inside this one that were proposed separately and are covered by
	// scanning it, kept visible so the report does not look like it lost a discovered root.
	Subsumes []string `json:"subsumes,omitempty"`
}

// DiscoveryMechanism is one mechanism's account of itself: succeeded, attempted, unavailable or
// refused. Every mechanism consulted reports, including the ones that found nothing -- "there is no
// nginx here" and "nginx is here and named no root" are different facts during an IR, and an absent
// field cannot express either.
type DiscoveryMechanism struct {
	Mechanism string `json:"mechanism"`
	Status    string `json:"status"`
	Roots     int    `json:"roots"`
	Detail    string `json:"detail,omitempty"`
}

// DiscoveryRejection is a proposed path that was refused, with the reason.
type DiscoveryRejection struct {
	Path      string `json:"path"`
	Mechanism string `json:"mechanism"`
	Source    string `json:"source,omitempty"`
	Reason    string `json:"reason"`
}

// TargetSpec is what the core hands a probe on stdin (the input half of the contract).
type TargetSpec struct {
	Host     string   `json:"host"`
	PIDs     []int    `json:"pids,omitempty"`
	Webroots []string `json:"webroots,omitempty"`
	DumpPath string   `json:"dump_path,omitempty"`
}
