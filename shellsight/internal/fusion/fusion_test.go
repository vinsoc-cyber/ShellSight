package fusion

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"shellsight/internal/finding"
)

func sig(host, view string) finding.Finding {
	return finding.Finding{Host: host, View: view, Detection: finding.Detection{Basis: "signature"}, Tier: finding.TierLikely}
}
func structural(host, view string) finding.Finding {
	return finding.Finding{Host: host, View: view, Detection: finding.Detection{Basis: "structural-heuristic"}, Tier: finding.TierSuspicious}
}

// A lone structural-heuristic must cap at suspicious (spec §8 discipline).
func TestLoneStructuralCapsAtSuspicious(t *testing.T) {
	v, out := Assess([]finding.Finding{structural("WEB01", "dotnet-mem")}, nil)
	if out[0].Tier != finding.TierSuspicious || out[0].Score != 50 {
		t.Fatalf("lone structural must be suspicious/50, got %s/%d", out[0].Tier, out[0].Score)
	}
	if v.Tier != finding.TierSuspicious {
		t.Fatalf("verdict want suspicious, got %s", v.Tier)
	}
}

// Two independent views on the same host corroborate → escalate one notch each.
func TestCrossViewCorroborationEscalates(t *testing.T) {
	v, out := Assess([]finding.Finding{sig("WEB01", "disk"), structural("WEB01", "dotnet-mem")}, nil)
	// signature + corroboration → confirmed; structural + corroboration → likely
	if out[0].Tier != finding.TierConfirmed {
		t.Fatalf("corroborated signature want confirmed, got %s", out[0].Tier)
	}
	if out[1].Tier != finding.TierLikely {
		t.Fatalf("corroborated structural want likely, got %s", out[1].Tier)
	}
	if v.Tier != finding.TierConfirmed {
		t.Fatalf("verdict want confirmed, got %s", v.Tier)
	}
}

// Findings on different hosts do NOT corroborate each other.
func TestDifferentHostsDoNotCorroborate(t *testing.T) {
	_, out := Assess([]finding.Finding{structural("WEB01", "dotnet-mem"), sig("WEB02", "disk")}, nil)
	if out[0].Tier != finding.TierSuspicious {
		t.Fatalf("structural on a different host must stay suspicious, got %s", out[0].Tier)
	}
}

// A named family fingerprint is high-confidence on its own (likely), confirmed when corroborated.
func TestFamilyFingerprint(t *testing.T) {
	fam := "Behinder"
	f := finding.Finding{Host: "WEB01", View: "dotnet-mem", Detection: finding.Detection{Basis: "structural-heuristic"},
		Classification: finding.Classification{Family: &fam}}
	_, out := Assess([]finding.Finding{f}, nil)
	if out[0].Tier != finding.TierLikely || out[0].Score != 80 {
		t.Fatalf("lone family-fp want likely/80, got %s/%d", out[0].Tier, out[0].Score)
	}
}

// Coverage honesty: a failed view with nothing found is UNKNOWN, never "clean". The scan did not
// finish, so the tool does not know. Reporting "clean" here is the most dangerous output the
// product can produce, and it is not hypothetical: the disk probe needs 4m16s on 989 obfuscated
// shells (0.26 s/file) versus 0.011 s/file on clean code, so scan cost rises with obfuscation and
// the default per-probe timeout is MORE likely to fire on a host that is actually compromised.
func TestFailedCoverageWithNoFindingsIsUnknownNotClean(t *testing.T) {
	v, _ := Assess(nil, []finding.Coverage{{View: "dotnet-mem", Status: finding.CovFailed, Reason: "access denied"}})
	if v.Tier == finding.TierClean {
		t.Fatal("a scan with a failed view must never report clean")
	}
	if v.Tier != finding.TierUnknown || !v.Incomplete {
		t.Fatalf("want unknown+incomplete, got %s incomplete=%v", v.Tier, v.Incomplete)
	}
}

// A failed view alongside real findings keeps the worst finding tier — "confirmed but incomplete"
// is already honest, so unknown must not mask it.
func TestFailedCoverageWithFindingsKeepsWorstTier(t *testing.T) {
	f := diskFinding(`C:\web\shell.php`, "php_antsword_payload", 90, finding.TierConfirmed)
	v, _ := Assess([]finding.Finding{f}, []finding.Coverage{{View: "java-mem", Status: finding.CovFailed, Reason: "no JRE"}})
	if v.Tier != finding.TierConfirmed || !v.Incomplete {
		t.Fatalf("want confirmed+incomplete, got %s incomplete=%v", v.Tier, v.Incomplete)
	}
}

// A scan that ran every view and found nothing is genuinely clean.
func TestCompleteScanWithNoFindingsIsClean(t *testing.T) {
	v, _ := Assess(nil, []finding.Coverage{{View: "disk", Status: finding.CovRan}})
	if v.Tier != finding.TierClean || v.Incomplete {
		t.Fatalf("want clean+complete, got %s incomplete=%v", v.Tier, v.Incomplete)
	}
}

// A capability that CANNOT exist on this host is not a gap in the scan. There is no .NET runtime on
// a Linux web server to have missed anything in, so a Linux host with a clean webroot must report
// clean and exit 0 — the alternative is every clean Linux sweep coming back inconclusive, which
// trains the reader to ignore `incomplete` on the sweeps where it means something.
func TestNotApplicableCoverageDoesNotMakeAScanIncomplete(t *testing.T) {
	v, _ := Assess(nil, []finding.Coverage{
		{View: "disk", Status: finding.CovRan},
		{View: "dotnet-mem", Status: finding.CovNA, Reason: "dotnet-mem is supported on windows only; this host is linux"},
		{View: "behavioral", Status: finding.CovNA, Reason: "behavioral is supported on windows only; this host is linux"},
	})
	if v.Tier != finding.TierClean || v.Incomplete {
		t.Fatalf("want clean+complete, got %s incomplete=%v", v.Tier, v.Incomplete)
	}
}

// ...and the distinction has to hold in the same report. A defective package must stay loud even
// when most of the coverage list is legitimately n/a: "cannot exist here" and "should have run and
// did not" are the two statements this field exists to keep apart.
func TestAFailedViewIsStillIncompleteBesideNotApplicableOnes(t *testing.T) {
	v, _ := Assess(nil, []finding.Coverage{
		{View: "disk", Status: finding.CovFailed, Reason: "fork/exec: permission denied"},
		{View: "dotnet-mem", Status: finding.CovNA, Reason: "dotnet-mem is supported on windows only; this host is linux"},
	})
	if !v.Incomplete || v.Tier != finding.TierUnknown {
		t.Fatalf("want unknown+incomplete, got %s incomplete=%v", v.Tier, v.Incomplete)
	}
}

// One incident per host: all findings on a host share a correlation_id.
func TestCorrelationIDPerHost(t *testing.T) {
	_, out := Assess([]finding.Finding{sig("WEB01", "disk"), structural("WEB01", "dotnet-mem")}, nil)
	if out[0].CorrelationID == "" || out[0].CorrelationID != out[1].CorrelationID {
		t.Fatalf("same-host findings must share a correlation_id, got %q vs %q", out[0].CorrelationID, out[1].CorrelationID)
	}
}

// An allowlisted (benign) peer must NOT corroborate a real finding (no FP-cannon escalation).
func TestAllowlistedPeerDoesNotCorroborate(t *testing.T) {
	benign := finding.Finding{Host: "WEB01", View: "disk", Detection: finding.Detection{Basis: "signature", Allowlisted: true}}
	real := structural("WEB01", "dotnet-mem")
	_, out := Assess([]finding.Finding{benign, real}, nil)
	if out[1].Tier != finding.TierSuspicious {
		t.Fatalf("an allowlisted peer must not corroborate; want suspicious, got %s", out[1].Tier)
	}
}

// Two weak/unknown-basis findings on different views must not mutually self-promote.
func TestWeakPeersDoNotMutuallyEscalate(t *testing.T) {
	a := finding.Finding{Host: "H", View: "disk", Detection: finding.Detection{Basis: "info"}}
	b := finding.Finding{Host: "H", View: "dotnet-mem", Detection: finding.Detection{Basis: "info"}}
	_, out := Assess([]finding.Finding{a, b}, nil)
	if out[0].Tier != finding.TierSuspicious || out[1].Tier != finding.TierSuspicious {
		t.Fatalf("weak default-basis findings must not escalate each other, got %s/%s", out[0].Tier, out[1].Tier)
	}
}

// Two findings from the SAME view (same probe/artifact) are not independent → no escalation.
func TestSameViewDifferentBasisDoesNotCorroborate(t *testing.T) {
	s := finding.Finding{Host: "H", View: "dotnet-mem", Detection: finding.Detection{Basis: "signature"}}
	h := finding.Finding{Host: "H", View: "dotnet-mem", Detection: finding.Detection{Basis: "structural-heuristic"}}
	_, out := Assess([]finding.Finding{s, h}, nil)
	if out[0].Tier != finding.TierLikely {
		t.Fatalf("same-view signature must stay likely (not confirmed), got %s", out[0].Tier)
	}
	if out[1].Tier != finding.TierSuspicious {
		t.Fatalf("same-view structural must stay suspicious, got %s", out[1].Tier)
	}
}

// A family-fingerprint match on the bytes corroborates a structural hit even within one view
// (spec §5/§8: a distinct KIND of evidence on the same artifact).
func TestIntraViewFamilyFingerprintCorroboratesStructural(t *testing.T) {
	fam := "Godzilla"
	struc := finding.Finding{Host: "H", View: "dotnet-mem", Detection: finding.Detection{Basis: "structural-heuristic"}}
	famHit := finding.Finding{Host: "H", View: "dotnet-mem", Detection: finding.Detection{Basis: "structural-heuristic"}, Classification: finding.Classification{Family: &fam}}
	_, out := Assess([]finding.Finding{struc, famHit}, nil)
	if out[0].Tier != finding.TierLikely {
		t.Fatalf("structural corroborated by an intra-view family-fp must be likely, got %s", out[0].Tier)
	}
	if out[1].Tier != finding.TierLikely || out[1].Score != 80 {
		t.Fatalf("the family-fp finding (no independent peer) stays likely/80, got %s/%d", out[1].Tier, out[1].Score)
	}
}

func TestBehavioralMitreMapping(t *testing.T) {
	cases := []struct {
		ref  string
		want []string
	}{
		{finding.KBBehaviorViewState, []string{"T1505.003"}}, // failed forge attempt, not a reflective load
		{finding.KBBehaviorIISConfig, []string{"T1505.003", "T1505.004"}},
		{finding.KBBehaviorW3wpChild, []string{"T1505.003"}},
	}
	for _, c := range cases {
		f := finding.Finding{Host: "H", View: "behavioral", Detection: finding.Detection{Basis: "behavioral", KnowledgeRef: c.ref}}
		_, out := Assess([]finding.Finding{f}, nil)
		if len(out[0].Mitre) != len(c.want) {
			t.Fatalf("%s: want %v, got %v", c.ref, c.want, out[0].Mitre)
		}
		for i := range c.want {
			if out[0].Mitre[i] != c.want[i] {
				t.Fatalf("%s: want %v, got %v", c.ref, c.want, out[0].Mitre)
			}
		}
	}
}

func TestBehavioralLoneCapsAtSuspicious(t *testing.T) {
	f := finding.Finding{Host: "H", View: "behavioral", Detection: finding.Detection{Basis: "behavioral", KnowledgeRef: finding.KBBehaviorW3wpChild}}
	_, out := Assess([]finding.Finding{f}, nil)
	if out[0].Tier != finding.TierSuspicious || out[0].Score != 50 {
		t.Fatalf("lone behavioral must be suspicious/50, got %s/%d", out[0].Tier, out[0].Score)
	}
}

func TestBehavioralCorroboratesMemAcrossViews(t *testing.T) {
	// The real behavioral signal (w3wp→shell child, basis "behavioral") corroborates a mem finding.
	beh := finding.Finding{Host: "H", View: "behavioral", Detection: finding.Detection{Basis: "behavioral", KnowledgeRef: finding.KBBehaviorW3wpChild}}
	mem := structural("H", "dotnet-mem")
	_, out := Assess([]finding.Finding{beh, mem}, nil)
	if out[0].Tier != finding.TierLikely {
		t.Fatalf("behavioral corroborated by a mem finding must be likely, got %s", out[0].Tier)
	}
	if out[1].Tier != finding.TierLikely {
		t.Fatalf("mem corroborated by behavioral must be likely, got %s", out[1].Tier)
	}
}

// ViewState/IIS-config are informational context: clean tier, and they must NOT escalate a peer
// (closes the FP-cannon where two benign-prone weak signals mutually promoted to likely).
func TestBehavioralContextIsInformationalAndNonCorroborating(t *testing.T) {
	ctx := finding.Finding{Host: "H", View: "behavioral", Detection: finding.Detection{Basis: "behavioral-context", KnowledgeRef: finding.KBBehaviorViewState}}
	mem := structural("H", "dotnet-mem")
	_, out := Assess([]finding.Finding{ctx, mem}, nil)
	if out[0].Tier != finding.TierClean {
		t.Fatalf("behavioral-context must be clean/informational, got %s", out[0].Tier)
	}
	if out[1].Tier != finding.TierSuspicious {
		t.Fatalf("a lone mem structural must stay suspicious (context must not corroborate it), got %s", out[1].Tier)
	}
}

func TestFamilyFromEvidenceGodzilla(t *testing.T) {
	f := finding.Finding{Host: "H", View: "dotnet-mem",
		Detection: finding.Detection{Basis: "structural-heuristic", Evidence: "recovered module contains key literal 3c6e0b8a9c15224a"}}
	_, out := Assess([]finding.Finding{f}, nil)
	if out[0].Classification.Family == nil || *out[0].Classification.Family != "Godzilla" {
		t.Fatalf("Godzilla key must set family=Godzilla, got %v", out[0].Classification.Family)
	}
	if out[0].Tier != finding.TierLikely || out[0].Score != 80 {
		t.Fatalf("a lone family-fingerprint must be likely/80, got %s/%d", out[0].Tier, out[0].Score)
	}
}

func TestFamilyFromEvidenceBehinderCaseInsensitive(t *testing.T) {
	f := finding.Finding{Host: "H", View: "java-mem",
		Detection: finding.Detection{Basis: "structural-heuristic", Evidence: "string needle E45E329FEB5D925B present"}}
	_, out := Assess([]finding.Finding{f}, nil)
	if out[0].Classification.Family == nil || *out[0].Classification.Family != "Behinder" {
		t.Fatalf("Behinder key (any case) must set family=Behinder, got %v", out[0].Classification.Family)
	}
}

func TestMitreTagging(t *testing.T) {
	disk := finding.Finding{Host: "H", View: "disk", Target: finding.Target{Kind: "file", File: &finding.File{Path: `C:\web\x.php`}}}
	module := finding.Finding{Host: "H", View: "dotnet-mem", Detection: finding.Detection{Evidence: "implements System.Web.IHttpModule"}}
	_, out := Assess([]finding.Finding{disk, module}, nil)
	if len(out[0].Mitre) != 1 || out[0].Mitre[0] != "T1505.003" {
		t.Fatalf("disk webshell must tag T1505.003, got %v", out[0].Mitre)
	}
	// An IHttpModule implant is a web shell + an IIS component + reflectively loaded.
	if len(out[1].Mitre) != 3 || out[1].Mitre[0] != "T1505.003" || out[1].Mitre[1] != "T1505.004" || out[1].Mitre[2] != "T1620" {
		t.Fatalf("IHttpModule implant must tag T1505.003+T1505.004+T1620, got %v", out[1].Mitre)
	}
}

func TestMitreTagsJavaMemAsReflectiveLoad(t *testing.T) {
	f := finding.Finding{Host: "H", View: "java-mem", Detection: finding.Detection{Basis: "structural-heuristic", Evidence: "disk-absent class implements javax.servlet.Filter"}}
	_, out := Assess([]finding.Finding{f}, nil)
	if len(out[0].Mitre) != 2 || out[0].Mitre[0] != "T1505.003" || out[0].Mitre[1] != "T1620" {
		t.Fatalf("java-mem implant must tag T1505.003+T1620, got %v", out[0].Mitre)
	}
}

// IHttpHandler and pipeline-contract findings must also get T1505.004.
func TestMitreTagsIHttpHandlerAsT1505004(t *testing.T) {
	f := finding.Finding{
		View: "dotnet-mem",
		Detection: finding.Detection{
			Basis:    "structural-heuristic",
			Evidence: "path-less CLR module implements request-pipeline contract(s) [System.Web.IHttpHandler]",
		},
	}
	_, out := Assess([]finding.Finding{f}, nil)
	found := false
	for _, tag := range out[0].Mitre {
		if tag == "T1505.004" {
			found = true
		}
	}
	if !found {
		t.Errorf("IHttpHandler finding must get T1505.004; got %v", out[0].Mitre)
	}
}

func TestMitreTagsVirtualPathProviderAsT1505004(t *testing.T) {
	f := finding.Finding{
		View: "dotnet-mem",
		Detection: finding.Detection{
			Basis:    "structural-heuristic",
			Evidence: "path-less CLR module implements request-pipeline contract(s) [System.Web.Hosting.VirtualPathProvider]",
		},
	}
	_, out := Assess([]finding.Finding{f}, nil)
	found := false
	for _, tag := range out[0].Mitre {
		if tag == "T1505.004" {
			found = true
		}
	}
	if !found {
		t.Errorf("VirtualPathProvider finding must get T1505.004; got %v", out[0].Mitre)
	}
}

// VirtualPathProvider evidence that does NOT contain the word "pipeline" must still get T1505.004
// (F11: the tag was previously coupled to the "pipeline" substring and passed only by accident).
func TestMitreVPPWithoutPipelineWordStillTagged(t *testing.T) {
	f := finding.Finding{View: "dotnet-mem", Detection: finding.Detection{Basis: "structural-heuristic",
		Evidence: "fileless module type implements System.Web.Hosting.VirtualPathProvider"}}
	_, out := Assess([]finding.Finding{f}, nil)
	found := false
	for _, tag := range out[0].Mitre {
		if tag == "T1505.004" {
			found = true
		}
	}
	if !found {
		t.Fatalf("VPP evidence (no 'pipeline' word) must still tag T1505.004; got %v", out[0].Mitre)
	}
}

func TestFingerprintDeterministicAndDistinct(t *testing.T) {
	a := finding.Finding{Host: "H", View: "disk", Target: finding.Target{File: &finding.File{Path: `C:\a.php`}}, Detection: finding.Detection{KnowledgeRef: "kb:yara/r1"}}
	b := finding.Finding{Host: "H", View: "disk", Target: finding.Target{File: &finding.File{Path: `C:\b.php`}}, Detection: finding.Detection{KnowledgeRef: "kb:yara/r1"}}
	_, o1 := Assess([]finding.Finding{a}, nil)
	_, o1b := Assess([]finding.Finding{a}, nil)
	_, o2 := Assess([]finding.Finding{b}, nil)
	if o1[0].Fingerprint == "" || o1[0].Fingerprint != o1b[0].Fingerprint {
		t.Fatalf("fingerprint must be deterministic, got %q vs %q", o1[0].Fingerprint, o1b[0].Fingerprint)
	}
	if o1[0].Fingerprint == o2[0].Fingerprint {
		t.Fatal("distinct targets must get distinct fingerprints")
	}
}

func TestProvenanceAnomalyScoring(t *testing.T) {
	host := "H1"
	// Lone provenance-anomaly → suspicious, score 50.
	lone := []finding.Finding{{
		SchemaVersion: finding.SchemaVersion, Host: host, View: "dotnet-mem",
		Detection: finding.Detection{Basis: "provenance-anomaly", Evidence: "spoofed-strong-name: framework PKT b77a5c561934e089 with invalid signature"},
	}}
	_, out := Assess(lone, nil)
	if out[0].Tier != finding.TierSuspicious || out[0].Score != 50 {
		t.Fatalf("lone provenance-anomaly: got %v/%d, want suspicious/50", out[0].Tier, out[0].Score)
	}
	// Corroborated by an independent credible signal (different view) → likely, 75.
	corr := []finding.Finding{
		{SchemaVersion: finding.SchemaVersion, Host: host, View: "dotnet-mem",
			Detection: finding.Detection{Basis: "provenance-anomaly", Evidence: "spoofed-strong-name"}},
		{SchemaVersion: finding.SchemaVersion, Host: host, View: "behavioral",
			Detection: finding.Detection{Basis: "behavioral", Evidence: "w3wp.exe spawned cmd.exe"}},
	}
	_, out = Assess(corr, nil)
	if out[0].Tier != finding.TierLikely || out[0].Score != 75 {
		t.Fatalf("corroborated provenance-anomaly: got %v/%d, want likely/75", out[0].Tier, out[0].Score)
	}
}

// Duplicate fingerprints (same host+view+target+rule+evidence) must collapse to one finding.
func TestDedupCollapsesDuplicateFingerprints(t *testing.T) {
	f := finding.Finding{
		Host: "host1", View: "disk",
		Detection: finding.Detection{Basis: "signature", KnowledgeRef: "kb:yara/test_rule", Evidence: "YARA rule test_rule matched"},
		Target:    finding.Target{Kind: "file", File: &finding.File{Path: "/var/www/shell.php"}},
		Artifact:  finding.Artifact{Identity: "shell.php"},
		Score:     70,
	}
	_, findings := Assess([]finding.Finding{f, f}, nil)
	if len(findings) != 1 {
		t.Errorf("expected 1 finding after dedup, got %d", len(findings))
	}
}

// When duplicates collide, the one with the higher score survives.
func TestDedupKeepsHighestScore(t *testing.T) {
	low := finding.Finding{Host: "H", View: "disk",
		Detection: finding.Detection{Basis: "signature", KnowledgeRef: "kb:yara/r", Evidence: "ev"},
		Target:    finding.Target{Kind: "file", File: &finding.File{Path: "/x.php"}}, Score: 70,
	}
	high := low
	high.Score = 90
	_, findings := Assess([]finding.Finding{low, high}, nil)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding after dedup, got %d", len(findings))
	}
}

// --- C1/C2: every basis a probe emits must be recognized by fusion ---
// An unrecognized basis silently falls to the default (suspicious/45) bucket, which discards the
// probe verdict AND disables corroboration. native-mem ("memory-region-anomaly") and the .NET ETW
// channel ("etw-dynamic-load") hit this before the fix.

// nativeImplant models a high-confidence native finding (RWX/PE/thread-corroborated): the probe
// marks it likely. nativeUnbacked models the ambiguous case (unbacked-RX alone): suspicious.
func nativeImplant(host, view string) finding.Finding {
	return finding.Finding{Host: host, View: view, Detection: finding.Detection{Basis: "memory-region-anomaly"}, Tier: finding.TierLikely, Score: 85}
}
func nativeUnbacked(host, view string) finding.Finding {
	return finding.Finding{Host: host, View: view, Detection: finding.Detection{Basis: "memory-region-anomaly"}, Tier: finding.TierSuspicious, Score: 50}
}

// C1: a recognized basis must NOT fall to the default (45) bucket — an ambiguous native finding is
// suspicious/50 (recognized), not 45.
func TestNativeMemBasisRecognized(t *testing.T) {
	_, out := Assess([]finding.Finding{nativeUnbacked("WEB01", "native-mem")}, nil)
	if out[0].Tier != finding.TierSuspicious || out[0].Score != 50 {
		t.Fatalf("ambiguous native must be recognized as suspicious/50 (not default/45), got %s/%d", out[0].Tier, out[0].Score)
	}
}

// C2: the .NET ETW dynamic-load basis must be recognized (suspicious/50), not the default bucket.
func TestEtwDynamicLoadBasisRecognized(t *testing.T) {
	f := finding.Finding{Host: "H", View: "dotnet-mem", Detection: finding.Detection{Basis: "etw-dynamic-load"}}
	_, out := Assess([]finding.Finding{f}, nil)
	if out[0].Tier != finding.TierSuspicious || out[0].Score != 50 {
		t.Fatalf("lone etw-dynamic-load must be recognized as suspicious/50, got %s/%d", out[0].Tier, out[0].Score)
	}
}

// Regression guard: NO basis emitted by any probe may fall to fusion's default bucket
// (suspicious/45).
//
// THE LIST IS DERIVED, NEVER WRITTEN DOWN. The previous version of this test hand-wrote it and its
// own comment predicted the consequence -- "it missed it for the same reason it will miss the next
// one -- a hard-coded list". It then did exactly that twice: it named "structural-heuristic" where
// cmd/diskprobe emits "heuristic" (the basis carrying most of PHP's confirmed band), and it never
// learned "taint", which internal/asptaint, internal/ssitaint and internal/perlpytaint reach fusion
// through -- so asp, aspx, perl, python, cgi and shtml lost their confirmed band in the CLI while
// every gate figure, measured on cmd/diskprobe, still showed it. Measured 2026-09-08: asp confirmed
// went 73 -> 4 on 163 real shells.
//
// So the set is read out of the source at test time. The Go side is parsed with go/ast rather than
// grepped, because a grep for `Basis: "` also matches internal/corpus's CandidatePair.Basis
// ("exact-shingle-jaccard"), which is a corpus-dedup field and not a probe verdict -- a false
// positive that would make this test fail for a reason that is not a bug. The C# probes are matched
// by pattern; they have no Go AST to walk.
func TestNoProbeBasisFallsToDefault(t *testing.T) {
	bases := emittedBases(t)
	if len(bases) < 8 {
		t.Fatalf("derived only %d bases (%v) -- the scan is broken, not the code; a passing "+
			"result here would be vacuous", len(bases), bases)
	}
	for _, b := range bases {
		_, out := Assess([]finding.Finding{{Host: "H", View: "v", Detection: finding.Detection{Basis: b}}}, nil)
		if out[0].Score == 45 && out[0].Tier == finding.TierSuspicious {
			t.Errorf("basis %q is emitted by a probe but falls to fusion's default bucket "+
				"(suspicious/45) -- it must be handled explicitly in scoreFinding", b)
		}
	}
}

// emittedBases returns every value assigned to finding.Detection.Basis anywhere in the scanner
// (Go, via the AST) or the .NET/Java probes (C#, by pattern), sorted and deduplicated.
func emittedBases(t *testing.T) []string {
	t.Helper()
	root := fusionRepoRoot()
	seen := map[string]bool{}

	// Go: composite literals of finding.Detection, production files only.
	for _, dir := range []string{"cmd", "internal"} {
		err := filepath.Walk(filepath.Join(root, dir), func(p string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
				return err
			}
			file, perr := parser.ParseFile(token.NewFileSet(), p, nil, 0)
			if perr != nil {
				return nil // a file this package cannot parse is not this test's business
			}
			ast.Inspect(file, func(n ast.Node) bool {
				lit, ok := n.(*ast.CompositeLit)
				if !ok || !isDetectionType(lit.Type) {
					return true
				}
				for _, el := range lit.Elts {
					kv, ok := el.(*ast.KeyValueExpr)
					if !ok {
						continue
					}
					if id, ok := kv.Key.(*ast.Ident); !ok || id.Name != "Basis" {
						continue
					}
					if s, ok := kv.Value.(*ast.BasicLit); ok && s.Kind == token.STRING {
						if v, err := strconv.Unquote(s.Value); err == nil && v != "" {
							seen[v] = true
						}
					}
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatalf("walking %s: %v", dir, err)
		}
	}

	// C#: `Basis = "..."` in the managed probes.
	csBasis := regexp.MustCompile(`Basis\s*=\s*"([a-z-]+)"`)
	_ = filepath.Walk(filepath.Join(root, "probes"), func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(p, ".cs") {
			return nil
		}
		body, rerr := os.ReadFile(p)
		if rerr != nil {
			return nil
		}
		for _, m := range csBasis.FindAllSubmatch(body, -1) {
			seen[string(m[1])] = true
		}
		return nil
	})

	out := make([]string, 0, len(seen))
	for b := range seen {
		out = append(out, b)
	}
	sort.Strings(out)
	return out
}

// isDetectionType reports whether a composite-literal type is finding.Detection (or bare Detection,
// for a literal written inside package finding itself).
func isDetectionType(e ast.Expr) bool {
	switch t := e.(type) {
	case *ast.SelectorExpr:
		pkg, ok := t.X.(*ast.Ident)
		return ok && pkg.Name == "finding" && t.Sel.Name == "Detection"
	case *ast.Ident:
		return t.Name == "Detection"
	}
	return false
}

// fusionRepoRoot walks up from cwd to the module root, the same way cmd/diskprobe's tests do.
func fusionRepoRoot() string {
	if r := os.Getenv("SHELLSIGHT_REPO_ROOT"); r != "" {
		return r
	}
	dir, _ := os.Getwd()
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "."
		}
		dir = parent
	}
}

// --- C3: honor the probe's confidence — a high-confidence memshell verdict alerts without a 2nd view ---

// A lone high-confidence native implant (probe said likely) reaches likely on its own — the common
// real case is a memshell with no corroborating disk/behavioral artifact.
func TestHighConfidenceNativeAlertsAlone(t *testing.T) {
	_, out := Assess([]finding.Finding{nativeImplant("WEB01", "native-mem")}, nil)
	if out[0].Tier != finding.TierLikely || out[0].Score < 80 {
		t.Fatalf("lone high-confidence native implant must be likely (>=80), got %s/%d", out[0].Tier, out[0].Score)
	}
}

// A high-confidence .NET/Java pipeline-contract hit (structural-heuristic + probe likely) also alerts
// alone — proving C3 is runtime-agnostic and needs no probe rebuild (fusion honors the existing Tier).
func TestHighConfidencePipelineAlertsAlone(t *testing.T) {
	f := finding.Finding{Host: "H", View: "dotnet-mem",
		Detection: finding.Detection{Basis: "structural-heuristic", Evidence: "path-less CLR module implements request-pipeline contract(s) [System.Web.IHttpModule]"},
		Tier:      finding.TierLikely, Score: 85}
	_, out := Assess([]finding.Finding{f}, nil)
	if out[0].Tier != finding.TierLikely || out[0].Score < 80 {
		t.Fatalf("lone high-confidence pipeline memshell must be likely (>=80), got %s/%d", out[0].Tier, out[0].Score)
	}
}

// A high-confidence finding corroborated by an independent credible view reaches confirmed; the
// ambiguous peer it corroborates rises to likely.
func TestHighConfidenceCorroboratedIsConfirmed(t *testing.T) {
	_, out := Assess([]finding.Finding{nativeImplant("H", "native-mem"), structural("H", "dotnet-mem")}, nil)
	if out[0].Tier != finding.TierConfirmed {
		t.Fatalf("high-confidence native + independent view must be confirmed, got %s", out[0].Tier)
	}
	if out[1].Tier != finding.TierLikely {
		t.Fatalf("the ambiguous peer corroborated by the native implant must be likely, got %s", out[1].Tier)
	}
}

// The FP-discipline still holds for AMBIGUOUS findings: a lone unbacked-RX (probe said suspicious)
// stays capped at suspicious, reaching likely only with an independent corroborating view.
func TestAmbiguousNativeStaysCapped(t *testing.T) {
	_, out := Assess([]finding.Finding{nativeUnbacked("H", "native-mem")}, nil)
	if out[0].Tier != finding.TierSuspicious || out[0].Score != 50 {
		t.Fatalf("lone ambiguous native must stay suspicious/50, got %s/%d", out[0].Tier, out[0].Score)
	}
	_, out2 := Assess([]finding.Finding{nativeUnbacked("H", "native-mem"), sig("H", "disk")}, nil)
	if out2[0].Tier != finding.TierLikely || out2[0].Score != 75 {
		t.Fatalf("ambiguous native corroborated by an independent view must be likely/75, got %s/%d", out2[0].Tier, out2[0].Score)
	}
}

// --- Reachability-dispatch: a component proven wired into the live request pipeline ---

// --- Verdict-path fidelity: fusion must not overwrite the probe's calibrated score, and
// --- corroboration must be local and attributed.
//
// Measured 2026-08-10: a stock WordPress webroot (5,213 files, benign) scored 0 files in the
// confirmed band under cmd/diskprobe but came out of `shellsight scan` as 35/35 findings
// "confirmed" (90-95) with a host verdict of confirmed — including bundled lodash.js and
// react-dom.js. Two independent causes, one test group each below.

// diskFinding models what cmd/diskprobe actually emits: a per-rule calibrated score and the
// tier scoreToTier() derives from it (>=85 confirmed, >=60 likely, >=40 suspicious, else clean).
func diskFinding(path, rule string, score int, tier finding.Tier) finding.Finding {
	return finding.Finding{
		Host: "WEB01", View: "disk",
		Detection: finding.Detection{Basis: "signature", KnowledgeRef: "kb:yara/" + rule, Evidence: "rule " + rule + " matched"},
		Target:    finding.Target{Kind: "file", File: &finding.File{Path: path}},
		Tier:      tier, Score: score,
	}
}

func withFamily(f finding.Finding, family string) finding.Finding {
	f.Classification = finding.Classification{Family: &family}
	return f
}

// Cause 1: fusion discarded the probe's score for basis "signature" and substituted a flat
// band. A finding the probe scored 30 — BELOW the 40 suspicious floor, i.e. tier clean — must
// never be reported as likely or confirmed. This is the lodash.js/react-dom.js case.
func TestProbeCleanSignatureIsNotPromoted(t *testing.T) {
	_, out := Assess([]finding.Finding{diskFinding(`C:\web\lodash.js`, "DodgyStrings", 30, finding.TierClean)}, nil)
	if out[0].Tier == finding.TierConfirmed || out[0].Tier == finding.TierLikely {
		t.Fatalf("a probe-clean (score 30) signature must not be promoted, got %s/%d", out[0].Tier, out[0].Score)
	}
	if out[0].Score > 30 {
		t.Fatalf("fusion must not inflate the probe's score 30, got %d", out[0].Score)
	}
}

// ...and it must stay unpromoted even when the host carries a genuine attributed detection.
// Corroboration is evidence the HOST is compromised, not evidence that this file is a shell.
func TestProbeCleanSignatureNeverReachesConfirmed(t *testing.T) {
	weak := diskFinding(`C:\web\react-dom.js`, "DodgyStrings", 30, finding.TierClean)
	real := withFamily(diskFinding(`C:\web\shell.aspx`, "china_chopper_aspx", 90, finding.TierConfirmed), "ChinaChopper")
	_, out := Assess([]finding.Finding{weak, real}, nil)
	if out[0].Tier == finding.TierConfirmed {
		t.Fatalf("a probe-clean signature must never reach confirmed, got %s/%d", out[0].Tier, out[0].Score)
	}
}

// The same defect ran the other way: a genuine confirmed-band shell (probe score 90) was
// DEMOTED to likely/70 whenever it had no corroborating peer. That is a recall loss at exactly
// the threshold a SOC triages on.
func TestConfirmedBandSignatureIsNotDemoted(t *testing.T) {
	_, out := Assess([]finding.Finding{diskFinding(`C:\web\shell.php`, "php_antsword_payload", 90, finding.TierConfirmed)}, nil)
	if out[0].Tier != finding.TierConfirmed {
		t.Fatalf("a lone probe-confirmed shell must stay confirmed, got %s", out[0].Tier)
	}
	if out[0].Score < 90 {
		t.Fatalf("a probe score of 90 must not be reduced, got %d", out[0].Score)
	}
}

// Cause 2: corroborated() had no locality check, so ONE family label anywhere on the host
// promoted every other finding on it. This is the phpMyAdmin case reduced to two files:
// examples/openid.php alone was likely(70); beside an unrelated family-labelled file it became
// confirmed(90).
func TestFamilyLabelOnAnotherFileDoesNotCorroborate(t *testing.T) {
	fp := diskFinding(`C:\web\examples\openid.php`, "DodgyPhp", 70, finding.TierLikely)
	other := withFamily(diskFinding(`C:\web\src\GisVisualizationController.php`, "php_varfunc_request_webshell", 80, finding.TierLikely), "DynamicDispatch")
	_, out := Assess([]finding.Finding{fp, other}, nil)
	if out[0].Tier == finding.TierConfirmed {
		t.Fatalf("a family label on a DIFFERENT file must not confirm this one, got %s/%d", out[0].Tier, out[0].Score)
	}
}

// Locality alone is not enough: WordPress wp-admin/admin.php carries TWO family-labelled
// findings on the SAME file (GenericEval + DynamicDispatch). Those labels are the CATEGORY of
// whichever rule fired, so two of them are one detection restated, not a second opinion.
func TestTwoCategoryFamiliesOnOneFileDoNotCorroborate(t *testing.T) {
	a := withFamily(diskFinding(`C:\web\wp-admin\admin.php`, "php_eval_request_webshell", 80, finding.TierLikely), "GenericEval")
	b := withFamily(diskFinding(`C:\web\wp-admin\admin.php`, "php_varfunc_request_webshell", 80, finding.TierLikely), "DynamicDispatch")
	_, out := Assess([]finding.Finding{a, b}, nil)
	for i, f := range out {
		if f.Tier == finding.TierConfirmed {
			t.Fatalf("out[%d]: two Generic*/technique family buckets on one file must not confirm each other, got %s/%d", i, f.Tier, f.Score)
		}
	}
}

// A probe verdict of confirmed must survive on the structural path too, not just on "signature".
func TestProbeConfirmedStructuralStaysConfirmed(t *testing.T) {
	f := finding.Finding{Host: "WEB01", View: "disk",
		Detection: finding.Detection{Basis: "structural-heuristic", KnowledgeRef: "dotnet:pipeline"},
		Target:    finding.Target{Kind: "file", File: &finding.File{Path: `C:\web\shell.php`}},
		Tier:      finding.TierConfirmed, Score: 90}
	_, out := Assess([]finding.Finding{f}, nil)
	if out[0].Tier != finding.TierConfirmed {
		t.Fatalf("a lone probe-confirmed structural finding must stay confirmed, got %s/%d", out[0].Tier, out[0].Score)
	}
	if out[0].Score < 90 {
		t.Fatalf("probe score 90 must not be reduced, got %d", out[0].Score)
	}
}

// The real shape of a PHP confirmed-band detection: cmd/diskprobe emits internal/phptaint and
// internal/javadisk findings with basis "heuristic" and Tier: scoreToTier(f.Score). That basis was
// absent from fusion's switch entirely, so every one of them hit `default` (suspicious/45) and
// only reached the analyst at all because ANY family label used to bypass the switch. Measured on
// 989 hannousse webshells: all 314 findings scoring >=85 carry basis "heuristic", so leaving it
// unhandled put confirmed-band recall at 0/989 against a diskprobe reference of 268/989.
func TestHeuristicBasisHonorsProbeVerdict(t *testing.T) {
	mk := func(score int, tier finding.Tier) finding.Finding {
		return finding.Finding{Host: "WEB01", View: "disk",
			Detection: finding.Detection{Basis: "heuristic", KnowledgeRef: "phptaint:sink-on-request"},
			Target:    finding.Target{Kind: "file", File: &finding.File{Path: `C:\web\shell.php`}},
			Tier:      tier, Score: score}
	}
	for _, c := range []struct {
		score int
		tier  finding.Tier
	}{{90, finding.TierConfirmed}, {85, finding.TierConfirmed}, {75, finding.TierLikely}, {30, finding.TierClean}} {
		_, out := Assess([]finding.Finding{mk(c.score, c.tier)}, nil)
		if out[0].Tier != c.tier || out[0].Score != c.score {
			t.Errorf("basis heuristic score %d/%s must pass through, got %s/%d", c.score, c.tier, out[0].Tier, out[0].Score)
		}
	}
}

// Preserved intent: an ATTRIBUTED family fingerprint on the SAME artifact is a genuinely
// distinct kind of evidence and still corroborates within one view (spec §5/§8).
func TestAttributedFamilySameArtifactStillCorroborates(t *testing.T) {
	const p = `C:\web\upload.aspx`
	plain := diskFinding(p, "aspx_command_exec_webshell", 80, finding.TierLikely)
	famHit := withFamily(diskFinding(p, "china_chopper_aspx", 90, finding.TierConfirmed), "ChinaChopper")
	_, out := Assess([]finding.Finding{plain, famHit}, nil)
	if out[0].Tier != finding.TierConfirmed {
		t.Fatalf("an attributed family fingerprint on the same artifact must corroborate, got %s/%d", out[0].Tier, out[0].Score)
	}
}

// ...but even a real family label does not reach across files.
func TestAttributedFamilyOnAnotherFileDoesNotCorroborate(t *testing.T) {
	plain := diskFinding(`C:\web\a.aspx`, "aspx_command_exec_webshell", 80, finding.TierLikely)
	famHit := withFamily(diskFinding(`C:\web\b.aspx`, "china_chopper_aspx", 90, finding.TierConfirmed), "ChinaChopper")
	_, out := Assess([]finding.Finding{plain, famHit}, nil)
	if out[0].Tier == finding.TierConfirmed {
		t.Fatalf("an attributed family on a different file must not confirm this one, got %s/%d", out[0].Tier, out[0].Score)
	}
}

// A lone high-confidence reachability finding must surface (it's the strongest .NET signal — a
// component proven wired into the live request pipeline), mirroring the C3 etw/native handling.
func TestLoneReachabilityLikelySurfaces(t *testing.T) {
	f := finding.Finding{Host: "H", View: "dotnet-mem", Tier: finding.TierLikely, Score: 85,
		Detection: finding.Detection{Basis: "reachability-dispatch"}}
	_, out := Assess([]finding.Finding{f}, nil)
	if out[0].Tier != finding.TierLikely || out[0].Score < 80 {
		t.Fatalf("lone reachability-dispatch likely must stay likely(>=80), got %s/%d", out[0].Tier, out[0].Score)
	}
}

// An ambiguous (suspicious) lone reachability finding stays capped at suspicious until corroborated.
func TestLoneReachabilitySuspiciousCapped(t *testing.T) {
	f := finding.Finding{Host: "H", View: "dotnet-mem", Tier: finding.TierSuspicious, Score: 55,
		Detection: finding.Detection{Basis: "reachability-dispatch"}}
	_, out := Assess([]finding.Finding{f}, nil)
	if out[0].Tier != finding.TierSuspicious {
		t.Fatalf("lone ambiguous reachability-dispatch must cap at suspicious, got %s", out[0].Tier)
	}
}

// ---------------------------------------------------------------- truncated coverage

// The degraded-coverage triage hole. Reproduced on a live Tomcat 9 holding a resident Suo5 memshell
// (confirmed by jcmd, independently of ShellSight) with the agent's budget forced to 1 ms: the scan
// captured 0 classes, found nothing, and reported verdict=clean, incomplete=false, exit 0. A
// responder triages on the tier and the exit code, so a 0-class-deep partial sweep read as a clean
// host, with the truncation visible only to someone who opened the coverage record.
//
// A truncated sweep that found nothing has not established that there was nothing to find.
func TestATruncatedProbeMakesTheScanIncomplete(t *testing.T) {
	v, _ := Assess(nil, []finding.Coverage{
		{View: "disk", Status: finding.CovRan},
		{View: "java-mem", Status: finding.CovDegraded, Truncated: true,
			Reason: "in-JVM sweep truncated — pid 1: time budget exhausted after 0 class(es) captured"},
	})
	if !v.Incomplete {
		t.Error("a truncated probe must make the scan incomplete")
	}
	if v.Tier != finding.TierUnknown {
		t.Errorf("a truncated sweep that found nothing must not report clean, got %s", v.Tier)
	}
}

// The load-bearing regression, and the reason this is a separate field rather than `degraded`
// setting Incomplete. Degraded is the NORMAL state of a disk scan: a three-file webroot containing
// a .txt and a .bin already reports "2 entr(ies) not examined ... 2 examined by no
// language-specific detector". Downgrading for that would make nearly every real scan exit 5 and
// teach the reader to ignore `incomplete` on the runs where it means something.
func TestBoundedDegradedCoverageStillReportsClean(t *testing.T) {
	v, _ := Assess(nil, []finding.Coverage{
		{View: "disk", Status: finding.CovDegraded,
			Reason:  "2 entr(ies) not examined: 0 non-regular, 0 unreadable, 0 oversize, 2 examined by no language-specific detector",
			Skipped: &finding.ScanSkips{NoLanguageDetector: 2}},
	})
	if v.Incomplete {
		t.Error("degraded with an enumerated skip list must NOT make the scan incomplete")
	}
	if v.Tier != finding.TierClean {
		t.Errorf("want clean, got %s", v.Tier)
	}
}

// Truncation is orthogonal to Status: a probe can stop early having already found something. The
// findings keep their tier -- "likely-malicious but incomplete" is honest and actionable -- while
// `incomplete` still tells the reader the sweep did not finish.
func TestATruncatedProbeWithFindingsKeepsItsTier(t *testing.T) {
	f := []finding.Finding{{
		SchemaVersion: finding.SchemaVersion, View: "java-mem",
		Artifact:  finding.Artifact{Kind: "java-memory-class", Identity: "x.EvilFilter"},
		Detection: finding.Detection{Basis: "structural-heuristic", KnowledgeRef: "kb:java-mem/fileless-pipeline-class"},
		Tier:      finding.TierLikely, Score: 95,
	}}
	v, _ := Assess(f, []finding.Coverage{
		{View: "java-mem", Status: finding.CovDegraded, Truncated: true, Reason: "truncated"},
	})
	if v.Tier == finding.TierUnknown || v.Tier == finding.TierClean {
		t.Errorf("real findings must survive a truncated sweep, got %s", v.Tier)
	}
	if !v.Incomplete {
		t.Error("the run must still be marked incomplete")
	}
}

// Truncation must count even when the probe calls itself `ran` -- the two answer different
// questions, and a probe that forgets to downgrade its status must not thereby hide the gap.
func TestTruncatedCountsRegardlessOfStatus(t *testing.T) {
	v, _ := Assess(nil, []finding.Coverage{{View: "java-mem", Status: finding.CovRan, Truncated: true}})
	if !v.Incomplete || v.Tier != finding.TierUnknown {
		t.Errorf("truncated must count independently of status, got %s incomplete=%v", v.Tier, v.Incomplete)
	}
}
