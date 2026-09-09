package com.shellsight.javamem;

import java.util.*;

/**
 * Stage 3: score a loaded class WITHOUT reading its bytecode.
 *
 * <p>Everything used here comes from {@code java.lang.Class} — loader identity, ProtectionDomain,
 * interfaces, superclass chain, declared member names. None of it requires a retransform, so
 * scoring every class in a large application costs nothing measurable and causes no safepoint.
 * That is what makes the overhead constraint achievable rather than aspirational: bytecode capture
 * becomes the exception applied to a handful of classes instead of the rule applied to thousands.
 *
 * <p>The previous pipeline captured every disk-absent class up to a cap of 2000 — and its own
 * comment noted a production Spring Boot Tomcat has "~500-2000 fileless" classes, so the common
 * case really did retransform thousands.
 *
 * <p>Scoring is a PURE FUNCTION so two scans of an unchanged JVM capture the same set. A scanner
 * whose evidence depends on iteration order is not reproducible.
 */
final class Suspicion {

    /**
     * Ranking floor. NOT a capture gate -- see {@link #isCandidate}. It exists so callers can
     * describe a candidate as "high" or "low" interest without re-deriving the weights.
     */
    static final int CAPTURE_THRESHOLD = 60;

    /**
     * Is this class worth spending a retransform on at all?
     *
     * <p>Deliberately BROAD, and separate from {@link #score}. Capture produces the bytecode, and
     * the bytecode is where the decisive evidence lives -- constant-pool capability strings, the
     * family key literals, the in-memory-vs-jar diff. Gating capture on reflection-only signals
     * therefore throws away the evidence needed to judge the class.
     *
     * <p>Measured cost of getting this wrong: an earlier cut gated capture on score alone and lost
     * 20 of 92 corpus cells -- every ProxyValve, AgentContextValve, AgentFilterChain and Upgrade
     * shell, across all eight tools. Those classes are disk-absent, carry no pipeline contract, and
     * hold their capabilities in method bodies, which reflection cannot see. They scored 30-40
     * against a threshold of 60 and vanished.
     *
     * <p>Three ways in, any one sufficient:
     * <ul>
     *   <li><b>disk-absent and not verifiably generated</b> -- the primary memshell invariant. The
     *       generated-class exclusion is what keeps this from meaning "every proxy in a Spring
     *       app": on a real Tomcat it takes ~4800 loaded classes down to single digits.
     *   <li><b>implements a pipeline contract</b> -- catches a class that CLAIMS a real jar
     *       (CodeSource spoofing), which is disk-present and would otherwise be skipped.
     *   <li><b>on the retransform watchlist</b> -- a known Agent-type hook target, jar-backed and
     *       contract-less, whose only signal is the bytecode diff.
     * </ul>
     */
    static boolean isCandidate(Input in) {
        if (in.platformLoaded) return false;
        if (in.watched) return true;
        if (in.diskAbsent && !in.verifiedGenerated) return true;
        // FOURTH way in: backed by a real file, in a place the container never declared. Without
        // this the CISA AR25-261A shape is not merely mis-scored, it is never CAPTURED -- disk is
        // present so the fileless branch above misses it, and it is wired to nothing so the
        // contract branch below misses it too. Measured: corpus cell t9-unregistered-tmpjar
        // returned NO finding at any tier before this existed.
        if (in.outOfContract && !in.verifiedGenerated) return true;
        for (String c : in.contracts) {
            if (Contracts.isPipeline(c)) return true;
        }
        return false;
    }

    /** The reflection-derived facts Stage 3 works from. */
    static final class Input {
        final String className;
        final boolean diskAbsent;        // ProtectionDomain has no CodeSource location
        final boolean bootstrapLoaded;   // defined by the bootstrap loader (null)
        final boolean platformLoaded;    // defined by the platform loader
        final boolean verifiedGenerated; // structurally proven runtime-generated
        final List<String> contracts;    // interfaces + superclass chain
        final List<String> capabilities; // reflection-visible capability hints
        final List<String> methods;      // declared method names
        /** A known Agent-type retransform hook target, from mem-contracts retransform_watchlist. */
        final boolean watched;
        /**
         * The class IS backed by a real file, but that file is outside every repository the
         * container declares -- see {@link Repos}. Distinct from diskAbsent, and the two are
         * mutually exclusive: a class with no CodeSource cannot have one in the wrong place.
         */
        final boolean outOfContract;

        Input(String className, boolean diskAbsent, boolean bootstrapLoaded, boolean platformLoaded,
              boolean verifiedGenerated, List<String> contracts, List<String> capabilities,
              List<String> methods, boolean watched) {
            this(className, diskAbsent, bootstrapLoaded, platformLoaded, verifiedGenerated,
                 contracts, capabilities, methods, watched, false);
        }

        Input(String className, boolean diskAbsent, boolean bootstrapLoaded, boolean platformLoaded,
              boolean verifiedGenerated, List<String> contracts, List<String> capabilities,
              List<String> methods, boolean watched, boolean outOfContract) {
            this.outOfContract = outOfContract;
            this.className = className;
            this.diskAbsent = diskAbsent;
            this.bootstrapLoaded = bootstrapLoaded;
            this.platformLoaded = platformLoaded;
            this.verifiedGenerated = verifiedGenerated;
            this.contracts    = contracts    == null ? Collections.<String>emptyList() : contracts;
            this.capabilities = capabilities == null ? Collections.<String>emptyList() : capabilities;
            this.methods      = methods      == null ? Collections.<String>emptyList() : methods;
            this.watched = watched;
        }
    }

    /**
     * RANK one candidate against the others. Higher means it gets the budget first.
     *
     * <p>This does not decide whether a class is examined -- {@link #isCandidate} does. It decides
     * the ORDER, which only matters when a JVM has more candidates than the class cap allows. On
     * such a host the highest-ranked are captured and the agent records `incomplete:` naming the
     * limit that stopped it.
     *
     * <p>The weights encode one judgement: a memshell must be <em>wired into the request path</em>
     * and must have <em>arrived without a file</em>. Either alone is ordinary — frameworks are full
     * of jar-backed filters, and JVMs are full of fileless generated classes. Together they are the
     * shape of a memory-resident webshell.
     */
    static int score(Input in) {
        // Authentic platform code is excluded by an unforgeable property — the DEFINING LOADER —
        // never by name. A class merely CALLED java.* but defined by an application loader is not
        // excluded; that naming trick is precisely what this guards against.
        if (in.platformLoaded) return 0;

        // A watchlisted Agent-type hook target ranks top: it is jar-backed and contract-less, so
        // on structure alone it would rank last, yet the bytecode diff is the ONLY signal an
        // Agent-type shell produces.
        if (in.watched) return CAPTURE_THRESHOLD + 40;

        int s = 0;

        boolean pipeline = false;
        for (String c : in.contracts) {
            if (Contracts.isPipeline(c)) { pipeline = true; break; }
        }
        if (pipeline)      s += 40;
        if (in.diskAbsent) s += 30;
        // Weighted like diskAbsent, and for the same reason: both say the class's origin cannot be
        // accounted for. Ranking matters as much as candidacy here -- capture is budget-limited, so
        // a candidate that ranks below the ordinary jar-backed crowd is admitted and then never
        // reached.
        if (in.outOfContract) s += 30;
        // Both together is the memshell shape, and is worth more than the sum of its halves.
        if (pipeline && in.diskAbsent) s += 15;

        if (!in.capabilities.isEmpty()) s += 15;

        // A pipeline entry-point method name corroborates that the class is really on the request
        // path rather than merely implementing an interface it never services.
        for (String m : in.methods) {
            if (m.equals("doFilter") || m.equals("service") || m.equals("invoke")
                || m.equals("preHandle") || m.equals("onMessage") || m.equals("transform")) {
                s += 10;
                break;
            }
        }

        // Structurally VERIFIED generated code (JDK proxy, lambda, CGLIB with its fingerprint,
        // Jasper JSP with _jspService, groovyc with $getStaticMetaClass, reflection accessors) is
        // fileless BY DESIGN. A Spring application has thousands. Without this discount the capture
        // budget is spent on proxies before it reaches anything real. The check is structural, so a
        // shell cannot claim the discount just by naming itself $Proxy0.
        if (in.verifiedGenerated) s -= 55;

        // A bootstrap-loaded class is NOT skipped. Bootstrap-ClassLoader injection is a published
        // bypass, so such a class is scored and reported; Stage 4 declines to RETRANSFORM it
        // because the JVM will not permit it, and says so rather than going quiet.
        if (in.bootstrapLoaded) s += 10;

        return Math.max(0, s);
    }

    private Suspicion() {}
}
