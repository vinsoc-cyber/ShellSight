package com.shellsight.javamem;

import java.util.*;
import java.util.stream.Collectors;

enum AssessTier { CLEAN, SUSPICIOUS, LIKELY_MALICIOUS }
final class Assessment {
    final AssessTier tier; final int score; final boolean allowlisted; final List<String> signals; final String evidence;
    Assessment(AssessTier tier, int score, boolean allowlisted, List<String> signals, String evidence) {
        this.tier=tier; this.score=score; this.allowlisted=allowlisted; this.signals=signals; this.evidence=evidence;
    }
}
final class Discriminator {
    // Non-final: configure() replaces this at startup when mem-contracts.json is present.
    private static Set<String> PIPELINE_CONTRACTS = new HashSet<>(Arrays.asList(
        // javax Servlet API (Tomcat 9 and earlier)
        "javax.servlet.Filter","javax.servlet.Servlet","javax.servlet.http.HttpServlet",
        "javax.servlet.ServletRequestListener","javax.servlet.http.HttpSessionListener",
        "javax.servlet.ServletContextListener",
        // jakarta Servlet API (Tomcat 10+, Spring Boot 3+) — full parity with javax
        "jakarta.servlet.Filter","jakarta.servlet.Servlet","jakarta.servlet.http.HttpServlet",
        "jakarta.servlet.ServletRequestListener","jakarta.servlet.http.HttpSessionListener",
        "jakarta.servlet.ServletContextListener",
        // Tomcat internals
        "org.apache.catalina.Valve","org.apache.catalina.valves.ValveBase","org.apache.catalina.Container",
        "org.apache.catalina.LifecycleListener",                         // lifecycle hook (stealthier than Valve)
        // Coyote / protocol level
        "org.apache.coyote.Adapter",
        // Spring MVC
        "org.springframework.web.servlet.HandlerInterceptor",
        "org.springframework.web.servlet.handler.HandlerInterceptorAdapter",
        "org.springframework.web.servlet.mvc.Controller",
        "org.springframework.web.filter.OncePerRequestFilter",           // Spring filter base — many real shells extend this
        // Struts2 (massive enterprise footprint, especially APAC)
        "com.opensymphony.xwork2.interceptor.Interceptor",
        "org.apache.struts2.interceptor.AbstractInterceptor",
        // Jetty (embedded services, Jenkins, Nexus)
        "org.eclipse.jetty.server.Handler",
        "org.eclipse.jetty.server.handler.AbstractHandler",
        // Undertow / WildFly / JBoss EAP (common in financial sector)
        "io.undertow.server.HttpHandler",
        // WebSocket endpoints
        "javax.websocket.Endpoint","jakarta.websocket.Endpoint",
        "javax.websocket.server.ServerEndpointConfig",
        // Java agent / instrumentation memshell
        "java.lang.instrument.ClassFileTransformer"
    ));

    // Called once at startup by Probe.run() after loading mem-contracts.json.
    /** True if the named type is a request-pipeline contract. Exposed so the agent-side
     *  scorer and ContractParityTests compare against the SAME set the verdict layer uses. */
    static boolean isPipelineContract(String typeName) { return PIPELINE_CONTRACTS.contains(typeName); }

    static void configure(Set<String> contracts) {
        if (contracts != null && !contracts.isEmpty())
            PIPELINE_CONTRACTS = Collections.unmodifiableSet(new HashSet<>(contracts));
    }


    /** Action-grade capability: the payload can run a command, or tunnel traffic.
     *
     *  Loader/reflection/crypto references are NOT action-grade -- ordinary framework code is full
     *  of them, and treating them as corroboration is what put Tomcat's own DefaultServlet at
     *  likely-malicious.
     *
     *  X-Accel-Buffering makes a tunnel action-grade. Suo5 relays TCP over HTTP and never executes
     *  anything, so an exec-only test scored it a tier below every command shell on the identical
     *  mechanism. The header is absent from all 4,016 classes of a stock Tomcat 9; the socket APIs
     *  Suo5 also uses are NOT accepted here, because 45 of those 4,016 reference java/net/Socket.
     *  See docs/measurements/2026-08-30-memshell-detection-landscape/02-tunnel-capability.md */
    static boolean hasExecCapability(java.util.List<String> capabilityHits) {
        for (String h : capabilityHits) {
            if (h.equals("cmd.exe") || h.equals("/bin/sh") || h.equals("/bin/bash")
                || h.equals("java/lang/Runtime") || h.equals("java/lang/ProcessBuilder")
                || h.equals("X-Accel-Buffering")) return true;
        }
        return false;
    }

    static Assessment assess(ClassFacts f) {
        boolean trusted = f.trustedProvenance;
        // Structural verification replaces the old name-substring heuristic: a class merely NAMED
        // like a generated one no longer gets a pass. The value is computed by
        // ExtractAgent.isVerifiedGenerated INSIDE the target JVM and arrives here as the
        // `verified_generated` fact via Extract.java -- NOT by calling Provenance, whose copy of that
        // method is unreachable from production (see the header on Provenance.java). The previous
        // wording credited Provenance and sent a reader to the wrong implementation.
        boolean generated = f.verifiedGenerated;
        List<String> pipelineHits = f.contracts.stream().filter(PIPELINE_CONTRACTS::contains).collect(Collectors.toList());
        boolean hasPipeline = !pipelineHits.isEmpty();
        boolean hasProvenanceAnomaly = f.capabilityHits.contains("provenance-anomaly");
        // Separate provenance-anomaly from capability signals for clean output; both inform scoring.
        List<String> capSignals = f.capabilityHits.stream()
            .filter(s -> !s.equals("provenance-anomaly"))
            .map(s -> "cap:" + s).collect(Collectors.toList());
        int capCount = capSignals.size();

        // OUT-OF-CONTRACT CODE SOURCE, checked BEFORE the trusted-provenance early return. A jar in
        // /tmp is a perfectly readable jar, so without this it is waved through as trusted -- which
        // is precisely how the CISA AR25-261A shape produced no finding at all.
        //
        // Tiering matches cmd/jvmprobe/fuse.go arm for arm so the Windows jar and the Linux native
        // probe cannot disagree about the same class. Capped at SUSPICIOUS without an action-grade
        // capability: the predicted false positive is a framework extracting a WAR into
        // java.io.tmpdir, which is benign and carries no such capability.
        if (f.outOfContract) {
            List<String> sig = new ArrayList<>(List.of("codesource-out-of-contract"));
            if (hasPipeline) sig.add(0, "pipeline:" + String.join("+", pipelineHits));
            sig.addAll(capSignals);
            String where = "code loaded from outside every repository the container declares"
                + (f.declaredRepos.isEmpty() ? "" : " (measured against " + f.declaredRepos + ")");
            // A RUNTIME GENERATOR'S OUTPUT LOCATION IS NOT A DECLARED REPOSITORY, BY CONSTRUCTION.
            // `generated` above was computed and then consulted only by the CLEAN early-return
            // below, which a pipeline-wired class never reaches -- so a Jasper-compiled JSP page on
            // a container that declares no catalina.* was escalated to 90 on the strength of where
            // its generator happens to write. Measured on a benign Jetty petclinic: 5 such findings
            // (docs/measurements/2026-09-03-jetty-jasper-fp/).
            //
            // The capability arm stays UNGATED: a generated JSP that can execute commands is a JSP
            // webshell. Only the LOCATION argument is excused, never a capability.
            if (hasPipeline && !generated)
                return new Assessment(AssessTier.LIKELY_MALICIOUS, 90, false, sig,
                    where + "; wired into the request pipeline [" + String.join(", ", pipelineHits) + "]");
            if (hasExecCapability(f.capabilityHits))
                return new Assessment(AssessTier.LIKELY_MALICIOUS, 80, false, sig,
                    where + "; carries an action-grade capability [" + String.join(", ", capSignals) + "]");
            if (!generated)
                return new Assessment(AssessTier.SUSPICIOUS, 55, false, sig,
                    where + "; neither on the request path nor action-capable; warrants analyst review");
            // Generated, out of contract, no capability: fall through. NOTE what that means on THIS
            // path, because it is not the same as on the Go path, where the equivalent case reaches
            // `default: continue` and produces no finding. Here the class is pipeline-wired (a JSP
            // page implements jakarta.servlet.Servlet, and contracts come from the interface and
            // superclass chain -- ExtractAgent.java:261-264), so the `generated && !hasPipeline`
            // CLEAN arm below does NOT catch it and it lands on the bare `if (hasPipeline)` arm at
            // LIKELY_MALICIOUS 85.
            //
            // That is a PRE-EXISTING behaviour of this path, not something this change introduces:
            // it applies on Tomcat too, where such a class is in contract and skips this block
            // entirely. It is deliberately NOT fixed by gating the bare pipeline arm on
            // generated-ness, because that arm is the primary memshell detector and gating it would
            // exempt, for instance, a Filter compiled with groovyc from the pipeline alert -- a far
            // worse hole than the false positive being fixed here. Recorded as an open item in
            // docs/measurements/2026-09-03-jetty-jasper-fp/ instead of traded away.
        }

        if (trusted && !hasPipeline && !hasProvenanceAnomaly)
            return new Assessment(AssessTier.CLEAN, 0, true, List.of("trusted-provenance"),
                "trusted-provenance class (bootstrap/platform loader or signed file: jar); no request-pipeline implant");
        if (generated && !hasPipeline && capCount == 0 && !hasProvenanceAnomaly)
            return new Assessment(AssessTier.CLEAN, 0, true, List.of("verified-generated"),
                "structurally verified runtime-generated class ('" + f.className + "'); no pipeline implant or capability indicators");

        // Provenance anomaly. Two kinds, with very different reliability:
        //  - NO-SOURCE: the class claims a CodeSource it is NOT in (spoof / injected) → reliable;
        //    a pipeline contract alone escalates it.
        //  - BYTECODE-MISMATCH: the class DOES resolve to a real on-disk source but the in-memory
        //    bytes differ → UNRELIABLE. The JVM re-serializes classes loaded before the agent
        //    attached (member/pool/attribute reordering), and legitimate runtime instrumentation
        //    (APM, profilers, load-time weaving) also rewrites bytecode. So a lone mismatch — even
        //    on a pipeline class — is NOT a likely-malicious alert; only a corroborating capability
        //    indicator (exec/crypto/loader, as a real module-stomp payload would carry) escalates it.
        if (hasProvenanceAnomaly) {
            List<String> sig = new ArrayList<>(List.of("provenance-anomaly"));
            if (hasPipeline) sig.add(0, "pipeline:" + String.join("+", pipelineHits));
            sig.addAll(capSignals);
            String anomalyDetail = f.provenanceAnomaly != null && !f.provenanceAnomaly.isEmpty()
                ? f.provenanceAnomaly : "bytecode-mismatch: in-memory bytecode differs from on-disk jar";
            boolean isMismatch = f.provenanceAnomaly != null && f.provenanceAnomaly.startsWith("bytecode-mismatch");
            // A NO-SOURCE anomaly is reliable: the class names a jar it is demonstrably not in, which
            // is forgery. Any capability corroborates it.
            if (capCount > 0 && !isMismatch)
                return new Assessment(AssessTier.LIKELY_MALICIOUS, hasPipeline ? 92 : 80, false, sig,
                    anomalyDetail + "; corroborated by capability indicators");
            // A BYTECODE-MISMATCH is NOT reliable -- the JVM re-serialises classes loaded before the
            // agent attached, and APM agents rewrite bytecode legitimately. Measured 2026-08-31 on a
            // STOCK Tomcat 9 with nothing injected: 5 catalina classes mismatch, and one of them --
            // org.apache.catalina.servlets.DefaultServlet -- reached LIKELY_MALICIOUS/92 purely
            // because it implements HttpServlet and references java/lang/ClassLoader. Tomcat's own
            // DefaultServlet is not a webshell.
            //
            // So a mismatch may only be escalated by an EXECUTION-grade capability, which is what a
            // real module-stomp payload carries. Loader/reflection/crypto references are far too
            // common in framework code to carry that weight.
            if (capCount > 0 && hasExecCapability(f.capabilityHits))
                return new Assessment(AssessTier.LIKELY_MALICIOUS, hasPipeline ? 92 : 80, false, sig,
                    anomalyDetail + "; corroborated by execution capability");
            if (capCount > 0)
                return new Assessment(AssessTier.SUSPICIOUS, 65, false, sig,
                    anomalyDetail + "; capability indicators present but none is execution-grade, and a "
                    + "bytecode-mismatch alone is unreliable (JVM re-serialization / legitimate instrumentation)");
            if (hasPipeline && !isMismatch)
                return new Assessment(AssessTier.LIKELY_MALICIOUS, 92, false, sig,
                    anomalyDetail + "; corroborated by pipeline implant");
            if (hasPipeline)  // mismatch + pipeline, no capability → unreliable signal, do NOT lone-alert
                return new Assessment(AssessTier.SUSPICIOUS, 60, false, sig,
                    anomalyDetail + "; class resolves to a real on-disk source — a bytecode-mismatch alone "
                    + "(JVM re-serialization or legitimate instrumentation) is not a lone alert; analyst review");
            return new Assessment(AssessTier.SUSPICIOUS, 65, false, sig, anomalyDetail + "; warrants analyst review");
        }

        if (hasPipeline) {
            List<String> sig = new ArrayList<>(); sig.add("pipeline:" + String.join("+", pipelineHits));
            int score = 85;
            if (capCount > 0) { sig.addAll(capSignals); score = 95; }
            return new Assessment(AssessTier.LIKELY_MALICIOUS, score, false, sig,
                "fileless class implements request-pipeline contract(s) [" + String.join(", ", pipelineHits) + "]"
                + (capCount > 0 ? " and carries capability indicators [" + String.join(", ", capSignals) + "]" : "") + "; not framework-provenanced");
        }
        if (capCount >= 2)
            return new Assessment(AssessTier.LIKELY_MALICIOUS, 80, false, capSignals,
                "fileless class with multiple webshell capability indicators [" + String.join(", ", capSignals) + "] and no benign provenance");
        if (capCount == 1)
            return new Assessment(AssessTier.SUSPICIOUS, 55, false, capSignals,
                "fileless class with a capability indicator [" + String.join(", ", capSignals) + "]; warrants analyst review");
        return new Assessment(AssessTier.SUSPICIOUS, 50, false, List.of("fileless-unexplained"),
            "fileless class '" + f.className + "' with no benign provenance and no strong malicious signal; warrants analyst review");
    }
}
