package com.shellsight.javamem;

import java.util.*;
import java.util.stream.Collectors;

// Out-of-process fileless-candidate gate (the agent pre-filtered; this re-asserts before the
// discriminator, mirroring .NET ModuleScan.Suspicious).
final class ClassScan {

    /**
     * Which recovered classes are worth assessing.
     *
     * <p>THIS IS A SECOND GATE, and it has already cost one detection. The agent's
     * {@code Suspicion.isCandidate} decides what to capture; this decides what to assess. Both were
     * written around the same two invariants -- no file on disk, or a bytecode/CodeSource anomaly --
     * so an entirely new invariant has to be added in BOTH places or the second one silently drops
     * what the first worked to collect.
     *
     * <p>Measured: with `outOfContract` handled in the agent, in Extract, in ClassFacts and in
     * Discriminator -- and its Discriminator arm covered by passing unit tests -- the CISA AR25-261A
     * corpus cell still reported `clean` on the jar path, because the class is neither fileless nor
     * anomalous and was discarded here before Discriminator ever ran. A green unit test on an
     * unreachable branch proves nothing about the pipeline; that is why this is measured end to end.
     */
    static List<RecoveredClass> suspicious(List<RecoveredClass> all) {
        return all.stream()
            .filter(rc -> Extract.looksLikeClass(rc.bytes))
            .filter(rc -> rc.facts.fileless()
                       || rc.facts.outOfContract
                       || (rc.facts.provenanceAnomaly != null && !rc.facts.provenanceAnomaly.isEmpty()))
            .collect(Collectors.toList());
    }
}
