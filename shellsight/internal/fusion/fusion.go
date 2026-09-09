// Package fusion turns the raw []Finding from the probes into a scored, correlated
// verdict: it assigns one incident (correlation_id) per host, applies corroboration-
// aware scoring (a high-confidence probe verdict can alert on its own; an ambiguous lone
// heuristic caps at suspicious until an independent signal corroborates it), and rolls
// the findings into a host verdict.
// Pure: no I/O, deterministic, fully unit-testable.
package fusion

import "shellsight/internal/finding"

// Assess enriches the findings (correlation_id + tier + score) and returns the host verdict.
// Returns a copy; the input slice is not mutated.
func Assess(findings []finding.Finding, coverage []finding.Coverage) (finding.Verdict, []finding.Finding) {
	out := make([]finding.Finding, len(findings))
	copy(out, findings)

	// 1) Correlation: one incident per host (v1 scans a single host; this collapses
	//    cross-view findings about that host into one incident for the SOC).
	for i := range out {
		host := out[i].Host
		if host == "" {
			host = "unknown"
		}
		out[i].CorrelationID = "incident-" + host
	}

	// 1b) Normalize: free family label from a fingerprint constant in the evidence, then
	//     ATT&CK tags, then the stable content fingerprint (which folds in the family).
	for i := range out {
		if !familySet(out[i]) {
			if fam := familyFromEvidence(out[i]); fam != "" {
				out[i].Classification.Family = &fam
			}
		}
		out[i].Mitre = mitreFor(out[i])
		out[i].Fingerprint = fingerprint(out[i])
	}

	// 1c) Dedup: one finding per content fingerprint; keep highest score if duplicates collide.
	{
		seen := make(map[string]int, len(out)) // fingerprint → index in deduped
		deduped := make([]finding.Finding, 0, len(out))
		for _, f := range out {
			if idx, exists := seen[f.Fingerprint]; exists {
				if f.Score > deduped[idx].Score {
					deduped[idx] = f
				}
			} else {
				seen[f.Fingerprint] = len(deduped)
				deduped = append(deduped, f)
			}
		}
		out = deduped
	}

	// 2) Corroboration-aware scoring.
	for i := range out {
		out[i].Tier, out[i].Score = scoreFinding(i, out)
	}

	// 3) Verdict rollup: worst tier + max score; incomplete if any view failed.
	v := finding.Verdict{Tier: finding.TierClean}
	for _, f := range out {
		if f.Tier.Rank() > v.Tier.Rank() {
			v.Tier = f.Tier
		}
		if f.Score > v.Score {
			v.Score = f.Score
		}
	}
	// ONLY `failed` counts. The four statuses answer two different questions and this loop asks only
	// one of them — was anything that should have been examined left unexamined?
	//
	//   failed   — should have run and did not. A gap. The scan cannot vouch for that view.
	//   n/a      — cannot exist on this host. Not a gap: there is no .NET runtime on a Linux web
	//              server for a memory view to have missed anything in. Treating it as one would
	//              make every clean Linux sweep come back inconclusive, which teaches the reader to
	//              ignore `incomplete` on the sweeps where it means something.
	//   degraded — ran, covered less than all of its targets, and SAID SO with counts. The
	//              disclosure is in the coverage record; the verdict is not downgraded for it.
	//              This is the NORMAL state of a disk scan, not an exceptional one: any webroot
	//              holding a file with no language-specific detector is degraded, so downgrading
	//              for it would make nearly every scan inconclusive and teach the reader to ignore
	//              `incomplete` on the runs where it means something.
	//   ran      — covered its targets.
	//
	// So this needed no change when the platform-unsupported capabilities started reporting `n/a`
	// instead of vanishing (US4): the code was already right, and that is now asserted by
	// TestNotApplicableCoverageDoesNotMakeAScanIncomplete and
	// TestAFailedViewIsStillIncompleteBesideNotApplicableOnes rather than left to inspection.
	// `Truncated` is the second thing that counts, and it is a different question from Status.
	// A probe that stopped early cannot enumerate what it did not examine, so its clean result is
	// not evidence of absence -- where a `degraded` probe that lists exactly what it skipped still
	// is. Measured on a live Tomcat with a resident Suo5 memshell and the agent budget forced to
	// 1 ms: before this, the scan reported verdict=clean, incomplete=false, exit 0, with the
	// truncation visible only to someone who read the coverage record.
	for _, c := range coverage {
		if c.Status == finding.CovFailed || c.Truncated {
			v.Incomplete = true
		}
	}
	// An incomplete scan that found nothing has not established anything. Say so rather than
	// reporting "clean" — the tier an analyst reads must not claim coverage the run did not have.
	// A verdict carrying real findings keeps them; "confirmed but incomplete" is already honest.
	if v.Incomplete && v.Tier == finding.TierClean {
		v.Tier = finding.TierUnknown
	}
	return v, out
}

// scoreFinding maps one finding to (tier, score) given its peers (for corroboration).
// Scoring model (spec §8, refined by C3):
//
//	attributed family-fingerprint      → probe score, floor likely (80), → confirmed (95) if corroborated
//	signature                          → THE PROBE'S OWN calibrated score/tier, → confirmed (90)
//	                                     if corroborated AND the probe already said likely
//	memory/structural, probe=likely    → likely (probe score), → confirmed (95) if corroborated  [C3]
//	memory/structural, probe=ambiguous → suspicious (50, CAP), → likely (75) if corroborated
//	other                              → suspicious (45)
func scoreFinding(i int, all []finding.Finding) (finding.Tier, int) {
	f := all[i]
	corr := corroborated(i, all)
	if attributedFamily(f) {
		if corr {
			return finding.TierConfirmed, atLeast(f.Score, 95)
		}
		if f.Tier == finding.TierConfirmed {
			return finding.TierConfirmed, f.Score
		}
		return finding.TierLikely, atLeast(f.Score, 80)
	}
	switch f.Detection.Basis {
	case "signature", "heuristic", "taint":
		// All three disk bases carry a fully calibrated verdict from cmd/diskprobe: a per-rule score
		// derived from measured precision, and Tier: scoreToTier(score) (>=85 confirmed, >=60
		// likely, >=40 suspicious, else clean). "signature" is the YARA path; "heuristic" is
		// internal/phptaint and internal/javadisk (deobfscan.go:629,670); "taint" is
		// internal/asptaint, internal/ssitaint and internal/perlpytaint (deobfscan.go:1024,1076,1222).
		//
		// "taint" was the same omission as "heuristic", found 2026-09-08 by running a generated
		// agent rather than a test. These passes exist to make the confirmed band MEAN something
		// for the languages whose YARA rules cannot rank -- they assert a source-to-sink dataflow,
		// which is the strongest disk evidence there is -- so dropping them to suspicious/45
		// inverted their whole purpose. Measured on 3,420 real corpus files, same rules and the
		// same diskprobe bytes: asp confirmed 73 -> 4, aspx 46 -> 31, perl 9 -> 1, python 5 -> 2,
		// cgi 2 -> 0. php and jsp were unaffected because they arrive as "heuristic". The >=40
		// band never moved -- 45 still clears 40 -- which is why every @40 gate figure stayed
		// green while six of eight languages had no confirmed band in the product at all.
		//
		// Honor it. Overwriting it with a flat band broke it in BOTH directions: a DodgyStrings
		// hit the probe scored 30 (tier clean) was reported as confirmed 90, while a genuine
		// 90-scoring shell with no peer was demoted to likely 70 — a recall loss at exactly the
		// threshold a SOC triages on. "heuristic" was worse than either: it was absent from this
		// switch, so it fell to default (suspicious/45) and reached an analyst only because any
		// family label used to bypass the switch entirely. It carries most of PHP's confirmed
		// band (all 314 findings >=85 on hannousse), so that was the whole band.
		//
		// Corroboration may still escalate, but only a finding the probe already placed in the
		// likely band. An independent signal elsewhere on the host is evidence that the HOST is
		// compromised; it is not evidence that THIS artifact is a shell. Conflating those is
		// what turned a stock WordPress tree into 35 "confirmed" findings, bundled
		// lodash.js/react-dom.js included.
		if f.Tier == finding.TierConfirmed {
			return finding.TierConfirmed, f.Score
		}
		if corr && f.Tier == finding.TierLikely {
			return finding.TierConfirmed, atLeast(f.Score, 90)
		}
		if f.Score > 0 {
			if f.Tier == "" {
				// Score but no tier: derive one rather than emit "", which sevConf would
				// silently map to Informational and hide a real finding.
				return tierForScore(f.Score), f.Score
			}
			return f.Tier, f.Score
		}
		if f.Tier != "" {
			return f.Tier, f.Score
		}
		return finding.TierLikely, 70 // probe supplied neither score nor tier
	case "structural-heuristic", "provenance-anomaly", "memory-region-anomaly", "etw-dynamic-load",
		"reachability-dispatch", "stomp-diff":
		// Memory/structural heuristics (fileless class/module, native unbacked-executable region,
		// path-less dynamic CLR load, spoofed strong-name). C3: honor the probe's own confidence.
		// A probe that marked this likely-malicious is high-confidence by construction — a fileless
		// request-pipeline class, an RWX/PE/thread-corroborated native implant, a multi-capability
		// path-less module — and the FPR-hardened probes do NOT mark benign code likely. Such a
		// finding may alert on its own (a lone memshell is the common case; requiring a second view
		// is what made the differentiator under-alert), and reaches confirmed when an independent
		// view agrees. Findings the probe left at suspicious (lone path-less module, unbacked-RX
		// alone, fileless-unexplained, in-place stomp w/o capability) stay corroboration-gated —
		// the spec §8 anti-FP discipline, now applied only where confidence is genuinely ambiguous.
		// A probe that already said CONFIRMED keeps that verdict — the same "honor the probe"
		// rule the signature branch follows. This branch used to collapse confirmed down to
		// likely, which was invisible while any family label promoted findings to confirmed
		// anyway; once only attributed families do that, the cap zeroed the PHP confirmed band
		// outright (internal/phptaint arrives here as "structural-heuristic", and phptaint is
		// most of what scores >=85 on PHP — measured 0/989 confirmed on hannousse).
		if f.Tier == finding.TierConfirmed {
			return finding.TierConfirmed, atLeast(f.Score, 85)
		}
		if f.Tier == finding.TierLikely {
			if corr {
				return finding.TierConfirmed, atLeast(f.Score, 95)
			}
			score := f.Score
			if score < 80 {
				score = 80 // floor: a likely-tier verdict should not read below the likely band
			}
			return finding.TierLikely, score
		}
		if corr {
			return finding.TierLikely, 75
		}
		return finding.TierSuspicious, 50 // lone ambiguous anomaly never auto-escalates
	case "behavioral":
		// Log signals are suggestive, not proof (web→shell calls have benign causes). Cap a
		// lone signal at suspicious; escalate on corroboration.
		if corr {
			return finding.TierLikely, 75
		}
		return finding.TierSuspicious, 50
	case "behavioral-context":
		// Informational only (ViewState MAC failures, IIS-config changes): too noisy to be
		// malicious, and NOT the signature of a successful key-signed ViewState attack. Surfaced
		// for the analyst, never drives the verdict, never corroborates (see isCredibleSignal).
		return finding.TierClean, 10
	default:
		return finding.TierSuspicious, 45
	}
}

// corroborated reports whether finding i has an INDEPENDENT, CREDIBLE corroborating signal
// on the same host. Independence means either a DIFFERENT view (cross-view agreement between
// two probes) or an ATTRIBUTED family fingerprint ON THE SAME ARTIFACT (a distinct KIND of
// evidence about the same thing). The peer must itself be a credible malicious signal — see
// isCredibleSignal — so a benign/allowlisted or weak finding can NEVER escalate a real one
// (spec §8: a lone structural-heuristic only escalates on an independent signal;
// over-escalation is the #1 false-positive risk).
func corroborated(i int, all []finding.Finding) bool {
	f := all[i]
	for j, g := range all {
		if j == i || g.Host != f.Host {
			continue
		}
		if !isCredibleSignal(g) {
			continue
		}
		// Cross-view agreement: two different probes, two different classes of artifact.
		// Host-scoped by design — that is the multi-view thesis.
		if g.View != f.View {
			return true
		}
		// Within a single view, only an attributed family fingerprint on the SAME artifact
		// counts. Both halves of that are load-bearing, and each was measured:
		//   - Without the locality check, one family label anywhere on the host promoted every
		//     other finding on it. phpMyAdmin's examples/openid.php was likely(70) alone and
		//     confirmed(90) merely for sharing a host with an unrelated labelled file.
		//   - Without attributedFamily, two Generic*/technique buckets on ONE file promoted
		//     each other — wp-admin/admin.php carries GenericEval and DynamicDispatch, which
		//     is one detection restated by two rules, not a second opinion.
		if attributedFamily(g) && targetKey(g) == targetKey(f) {
			return true
		}
	}
	return false
}

// isCredibleSignal reports whether g may corroborate another finding: it must NOT be
// allowlisted, and must carry a recognized malicious detection basis (or an attributed family).
// The weak/unknown ("default") basis bucket cannot corroborate anything.
func isCredibleSignal(g finding.Finding) bool {
	if g.Detection.Allowlisted {
		return false
	}
	if attributedFamily(g) {
		return true
	}
	switch g.Detection.Basis {
	case "signature", "structural-heuristic", "behavioral", "provenance-anomaly",
		"memory-region-anomaly", "etw-dynamic-load", "reachability-dispatch":
		return true
	default:
		return false
	}
}

func familySet(f finding.Finding) bool {
	return f.Classification.Family != nil && *f.Classification.Family != ""
}

// attributedFamilies are the family labels that actually IDENTIFY a webshell family, from a
// distinctive artifact: a keyed generator's default key (see familyFingerprints) or a
// generator's payload wrapper. Only these are independent evidence about an artifact.
//
// Every other value that reaches classification.family is the CATEGORY of whichever YARA rule
// fired — diskprobe reads it straight off r.Meta["family"], so `GenericEval`, `GenericCmdExec`,
// `GenericASPX`, `GenericJSP`, `GenericSQL`, `GenericCallback`, `ClassicASP`,
// `DynamicDispatch`, `ReflectionSink` and `CallbackSink` are rule taxonomy, not attribution.
// RUNBOOK.md already tells analysts not to rely on those labels; fusion must not either.
//
// This set is deliberately small and fails CLOSED: an unrecognized label simply does not
// corroborate, which costs at most one tier on a real detection (the probe's own score still
// governs) and cannot manufacture a confirmed false positive. `Behinder/Godzilla-ASPX` is
// excluded on purpose — it names two families at once, so it does not attribute one. Extend
// this set only when a rule genuinely pins a single family.
var attributedFamilies = map[string]bool{
	"Behinder":     true, // AES key MD5("rebeyond")[:16] — familyFingerprints
	"Godzilla":     true, // AES key MD5("key")[:16]      — familyFingerprints
	"AntSword":     true, // asoutput/asenc payload wrapper
	"ChinaChopper": true,
	"IceScorpion":  true,
}

func attributedFamily(f finding.Finding) bool {
	return familySet(f) && attributedFamilies[*f.Classification.Family]
}

// atLeast keeps an escalated score from reading below the band it lands in, without ever
// lowering a probe score that is already higher.
func atLeast(score, floor int) int {
	if score > floor {
		return score
	}
	return floor
}

// tierForScore mirrors cmd/diskprobe's scoreToTier. It is only a fallback for a probe that
// reported a score without a tier; keep the bands in step with that function.
func tierForScore(score int) finding.Tier {
	switch {
	case score >= 85:
		return finding.TierConfirmed
	case score >= 60:
		return finding.TierLikely
	case score >= 40:
		return finding.TierSuspicious
	default:
		return finding.TierClean
	}
}
