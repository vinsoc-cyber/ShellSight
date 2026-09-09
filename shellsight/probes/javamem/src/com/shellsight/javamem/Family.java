package com.shellsight.javamem;

import java.util.*;

/**
 * Family attribution for a memory-resident artifact.
 *
 * <p>This is the project's stated differentiator, and on 2026-09-01 the way it had been stated was
 * measured false and narrowed. What the evidence supports: <b>no surveyed Java tool attributes the
 * family of an in-memory artifact, and no tool of any kind does it from outside the target
 * process.</b> It is not unclaimed everywhere --
 * {@code yzddmr6/ASP.NET-Memshell-Scanner} reflects Godzilla's live password and key straight out of
 * a resident .NET {@code VirtualPathProvider}, which for that one mechanism recovers the operator's
 * REAL key where the markers below match only a DEFAULT one. Our durable advantage is that a
 * constant-pool literal cannot be renamed by an attacker, where its {@code GetField("password")}
 * can. Record:
 * {@code docs/measurements/2026-08-30-memshell-detection-landscape/05-dotnet-oss-incumbent-and-sample-supply.md}
 *
 * <p>Before 2026-08-31 attribution was also entirely unimplemented in this view --
 * {@code Classification} was emitted with every field null, and a 92-cell corpus measured
 * attribution at 0/92.
 *
 * <p><b>A marker must survive compilation.</b> Source-level expressions never appear in a constant
 * pool, so a marker built on one can never fire. Every marker here is a literal that is present in
 * the class file itself, and each was verified by parsing the constant pool of a real generated
 * shell:
 *
 * <ul>
 *   <li>Behinder {@code e45e329feb5d925b} = MD5("rebeyond")[:16]
 *   <li>Godzilla {@code 3c6e0b8a9c15224a} = MD5("key")[:16]
 * </ul>
 *
 * <p><b>These are DEFAULT keys.</b> An operator who changes the password changes the derived key,
 * and attribution then correctly reports nothing rather than guessing. That is the intended
 * behaviour: attribution is additive evidence, never a gate. A class with no family marker is
 * exactly as malicious as the rest of the evidence says it is.
 */
final class Family {

    /** One attribution rule: a literal that identifies a family, and why it does. */
    private static final class Marker {
        final String family, needle, evidence;
        final double confidence;
        Marker(String family, String needle, String evidence, double confidence) {
            this.family = family; this.needle = needle; this.evidence = evidence; this.confidence = confidence;
        }
    }

    // Deliberately small. An attribution that fires on a generic string is worse than none: it is a
    // confident wrong answer in an incident report.
    private static final List<Marker> MARKERS = List.of(
        new Marker("behinder", "e45e329feb5d925b",
            "default Behinder AES key literal (MD5(\"rebeyond\")[:16])", 0.9),
        new Marker("godzilla", "3c6e0b8a9c15224a",
            "default Godzilla key literal (MD5(\"key\")[:16])", 0.9),
        // Confidence 0.85, not 0.9, and the difference is meant: this is a HEADER NAME, so it
        // survives an operator changing a password (unlike the two derived keys above) but it
        // identifies the tool by transport behaviour, which is a step weaker than a build-unique
        // literal. Evidence: docs/measurements/2026-08-30-memshell-detection-landscape/02-tunnel-capability.md
        //
        // Added 2026-09-01, and only because a measurement caught its absence. The tunnel work put
        // this marker in internal/jvmprov/family.go and the needle in Facts/mem-contracts, but not
        // in THIS table -- so the jar path scored the Suo5 cells at the right tier while attributing
        // 28/92 against the native path's 44/92. "Both delivery paths" has to mean every table.
        new Marker("suo5", "X-Accel-Buffering",
            "Suo5 anti-buffering header literal (X-Accel-Buffering)", 0.85)
    );

    /** The needles Facts must look for so attribution has something to work from. */
    static List<String> markerNeedles() {
        List<String> out = new ArrayList<>(MARKERS.size());
        for (Marker m : MARKERS) out.add(m.needle);
        return out;
    }

    /** Result of attributing one class. {@code family} is null when nothing matched. */
    static final class Attribution {
        final String family, evidence;
        final double confidence;
        Attribution(String family, String evidence, double confidence) {
            this.family = family; this.evidence = evidence; this.confidence = confidence;
        }
    }

    /**
     * Attribute a family from the capability/string hits already collected for the class.
     *
     * <p>Works off the hit list rather than re-scanning: {@link Facts#scanBytecode} has already
     * looked, and doing it once keeps the two from disagreeing about what the class contains.
     */
    static Attribution of(List<String> hits) {
        if (hits == null || hits.isEmpty()) return null;
        for (Marker m : MARKERS) {
            if (hits.contains(m.needle)) return new Attribution(m.family, m.evidence, m.confidence);
        }
        return null;
    }

    private Family() {}
}
