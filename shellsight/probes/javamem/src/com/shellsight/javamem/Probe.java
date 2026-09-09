package com.shellsight.javamem;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;

public final class Probe {
    static final int EXIT_OK = 0, EXIT_INTERNAL = 1, EXIT_COVERAGE = 2;
    public static void main(String[] args) {
        try { System.exit(run(args)); }
        catch (Throwable t) { System.err.println("javamem: fatal: " + t); System.exit(EXIT_INTERNAL); }
    }
    static int run(String[] args) throws Exception {
        // Safety gate: live JVM attach requires explicit opt-in to prevent accidental use in prod.
        boolean forceLiveAttach = Arrays.asList(args).contains("--force-live-attach");
        if (!forceLiveAttach) {
            System.err.println("javamem: java-mem view requires --force-live-attach.");
            System.err.println("javamem: Review prod-safety notes before enabling live JVM attach.");
            System.err.println("javamem: The shellsight scan command adds this flag automatically when --views java-mem is selected.");
            System.out.print("[]");
            return EXIT_COVERAGE;
        }

        // PID allowlist: if set, restrict attach to only listed PIDs.
        String pidAllowlistEnv = System.getenv("SHELLSIGHT_JAVA_PID_ALLOWLIST");
        String pidAllowlistArg = argValue(args, "--pid-allowlist", pidAllowlistEnv != null ? pidAllowlistEnv : "");
        Set<Long> pidAllowlist = parsePidAllowlist(pidAllowlistArg);

        Path artifactsDir = Paths.get(argValue(args, "--artifacts-dir",
            System.getProperty("java.io.tmpdir") + File.separator + "shellsight-javamem-artifacts"));
        Path agentJar = resolveAgentJar();

        // Load mem-contracts.json and override compiled-in defaults.
        Path memContractsPath = resolveMemContracts(args, agentJar);
        MemContracts mc = MemContracts.tryLoad(memContractsPath);
        if (!mc.java.pipelineContracts.isEmpty())
            Discriminator.configure(new HashSet<>(mc.java.pipelineContracts));
        if (!mc.java.typeNeedles.isEmpty() || !mc.java.stringNeedles.isEmpty())
            Facts.configure(mc.java.typeNeedles.toArray(new String[0]),
                            mc.java.stringNeedles.toArray(new String[0]));
        TargetSpec spec;
        try { spec = Contract.parseSpec(new String(System.in.readAllBytes(), StandardCharsets.UTF_8)); }
        catch (Exception e) { System.err.println("javamem: bad TargetSpec on stdin: " + e.getMessage()); return EXIT_COVERAGE; }

        boolean[] explicit = new boolean[1];
        List<AcquireTarget> targets = Acquire.resolve(spec, explicit);
        if (targets.isEmpty()) {
            if (explicit[0]) { System.err.println("javamem: requested target(s) not present"); return EXIT_COVERAGE; }
            System.err.println("javamem: no Tomcat/Java web JVM found to analyze"); System.out.print("[]"); return EXIT_OK;
        }
        Files.createDirectories(artifactsDir);
        List<Finding> findings = new ArrayList<>(); int analyzedOK = 0, allowlisted = 0; List<String> failures = new ArrayList<>(); int idx = 0;
        // Per-target coverage statements from the agent: non-empty when its sweep stopped early.
        List<String> incompletes = new ArrayList<>();
        for (AcquireTarget t : targets) {
            if (!pidAllowlist.isEmpty() && !pidAllowlist.contains(t.pid)) {
                System.err.println("javamem: skipping pid " + t.pid + " (" + t.label() + ") — not in --pid-allowlist");
                continue;
            }
            Collected col;
            try { col = Acquire.attachAndCollect(t.pid, agentJar, mc.java.pipelineContracts, mc.java.retransformWatchlist); }
            catch (AcquireException e) { failures.add(t.label() + ": " + e.getMessage()); continue; }
            if (!col.incomplete.isEmpty()) incompletes.add("pid " + t.pid + ": " + col.incomplete);
            List<RecoveredClass> recovered = col.classes;
            analyzedOK++;
            for (RecoveredClass rc : ClassScan.suspicious(recovered)) {
                try {
                    ClassFacts facts = Facts.build(rc);
                    Assessment a = Discriminator.assess(facts);
                    if (a.tier == AssessTier.CLEAN) { allowlisted++; continue; }
                    findings.add(mapFinding(spec.host, t, rc, a, artifactsDir, idx++));
                } catch (Exception e) { System.err.println("javamem: " + t.label() + ": class " + rc.name + " skipped: " + e.getMessage()); }
            }
            mergeReachability(findings, col.reachability, spec.host, (int) t.pid, t.name);
        }
        if (analyzedOK == 0) {
            for (String f : failures) System.err.println("javamem: " + f);
            System.err.println("javamem: no targets could be analyzed"); return EXIT_COVERAGE;
        }
        for (String f : failures) System.err.println("javamem: warning: " + f);
        System.err.println("javamem: analyzed=" + analyzedOK + " findings=" + findings.size() + " allowlisted(suppressed)=" + allowlisted);
        System.out.print(Contract.serializeOutput(findings, coverage(analyzedOK, failures, incompletes)));
        return EXIT_OK;
    }
    /**
     * Build the coverage statement for this run.
     *
     * <p>Two different kinds of gap, and only one of them invalidates a clean result:
     *
     * <ul>
     *   <li><b>bounded</b> -- some targets could not be attached. Counted and disclosed, and the
     *       targets that WERE analyzed are fully swept, so a clean result on them still means
     *       something. Degraded, not truncated.
     *   <li><b>unbounded</b> -- a target's in-JVM sweep stopped early. The agent cannot say what was
     *       in the classes it never reached, so a clean result claims coverage the run did not have.
     *       This sets `truncated`, which the core turns into `incomplete` -> tier `unknown` -> exit 5.
     * </ul>
     *
     * <p>Mirrors cmd/jvmprobe on the Linux path deliberately: the two delivery paths must not
     * disagree about what a truncated sweep means, and this path was blind to it entirely until now.
     */
    static Contract.ProbeCoverage coverage(int analyzedOK, List<String> failures, List<String> incompletes) {
        Contract.ProbeCoverage c = new Contract.ProbeCoverage();
        c.status = "ran";
        c.reason = ""; // never null: GSON here serializes nulls, and a null on the wire reads as a bug
        c.targets_scanned = analyzedOK;
        StringBuilder reason = new StringBuilder();
        if (!failures.isEmpty()) {
            c.status = "degraded";
            reason.append(failures.size()).append(" of ").append(analyzedOK + failures.size())
                  .append(" JVM(s) could not be inspected in-process");
        }
        if (!incompletes.isEmpty()) {
            c.status = "degraded";
            c.truncated = true;
            if (reason.length() > 0) reason.append("; ");
            reason.append("in-JVM sweep truncated — ").append(String.join("; ", incompletes));
        }
        if (reason.length() > 0) c.reason = reason.toString();
        return c;
    }

    static Finding mapFinding(String host, AcquireTarget t, RecoveredClass rc, Assessment a, Path artifactsDir, int idx) throws Exception {
        String sha = sha256(rc.bytes);
        Path raw = artifactsDir.resolve("class_" + idx + ".class"); Files.write(raw, rc.bytes);
        String decompiled = "";
        try { Path j = artifactsDir.resolve("class_" + idx + ".java"); Files.writeString(j, Decompile.toJava(rc.bytes, rc.name)); decompiled = j.toString(); }
        catch (Exception e) { System.err.println("javamem: decompile class_" + idx + " failed: " + e.getMessage()); }
        Finding f = new Finding();
        f.id = sha.substring(0,12) + "-" + sanitize(rc.name); f.host = host; f.view = "java-mem";
        f.target.process = new ProcessRef(); f.target.process.pid = (int) t.pid; f.target.process.name = t.name;
        f.artifact.kind = "java-memory-class"; f.artifact.identity = rc.name; f.artifact.location = "in-memory (pid " + t.pid + ")";
        boolean provenanceAnomalyBasis = a.signals.contains("provenance-anomaly");
        f.detection.basis = provenanceAnomalyBasis ? "provenance-anomaly" : "structural-heuristic";
        f.detection.knowledgeRef = a.tier == AssessTier.LIKELY_MALICIOUS ? "heuristic:java/pipeline-implant" : "heuristic:java/fileless-class";
        f.detection.evidence = a.evidence; f.detection.allowlisted = false; f.score = a.score;
        f.tier = a.tier == AssessTier.LIKELY_MALICIOUS ? "likely-malicious" : "suspicious";
        f.artifacts.raw = raw.toString(); f.artifacts.decompiled = decompiled;

        // Family + capability attribution. The differentiator, stated as measurement supports it:
        // no surveyed JAVA tool attributes the family of an in-memory artifact, and no tool of any
        // kind does it from OUTSIDE the target process. It is not unclaimed everywhere -- an OSS
        // .NET scanner reflects Godzilla's live key out of a resident object (see the landscape
        // record 05-dotnet-oss-incumbent-and-sample-supply.md). Additive only -- it never gates or
        // changes the tier, so an unattributed class is exactly as malicious as the rest of the
        // evidence says.
        // Assessment.signals carries the hits already, prefixed "cap:" -- reuse them rather than
        // re-parsing the class, so attribution cannot disagree with what scoring saw.
        java.util.List<String> caps = new java.util.ArrayList<>();
        for (String sig : a.signals) if (sig.startsWith("cap:")) caps.add(sig.substring(4));
        Family.Attribution attr = Family.of(caps);
        if (attr != null) {
            f.classification.family = attr.family;
            f.classification.confidence = attr.confidence;
            f.classification.source = "memory-constant-pool";
        }
        if (!caps.isEmpty()) f.classification.capability = caps.toArray(new String[0]);

        Map<String,String> ctx = new LinkedHashMap<>();
        ctx.put("class_loader", rc.facts.loader); ctx.put("code_source", rc.facts.codesource);
        ctx.put("signals", String.join(",", a.signals)); ctx.put("source", "live-attach");
        if (attr != null) ctx.put("family_evidence", attr.evidence);
        f.context = ctx; return f;
    }
    // Build a standalone finding for a fileless class wired into the live dispatch path. No recovered
    // bytes are required (the walk finds the live instance even for classes the enumeration missed),
    // so there are no raw/decompiled artifacts.
    static Finding mapReachabilityFinding(String host, int pid, String name, WiredElement w) {
        Finding f = new Finding();
        f.id = "reach-" + sanitize(w.className);
        f.host = host; f.view = "java-mem";
        f.target.process = new ProcessRef(); f.target.process.pid = pid; f.target.process.name = name;
        f.artifact.kind = "java-memory-class"; f.artifact.identity = w.className;
        f.artifact.location = "in-memory (pid " + pid + ")";
        f.detection.basis = "structural-heuristic";
        f.detection.knowledgeRef = "heuristic:java/reachable-fileless-" + w.hook;
        f.detection.evidence = "class " + w.className + " is wired into the live " + w.hook
            + " chain with no on-disk origin (reachable-from-dispatch); not a verified-generated or disk-backed class";
        f.detection.allowlisted = false;
        f.score = 90;
        f.tier = "likely-malicious";
        Map<String,String> ctx = new LinkedHashMap<>();
        ctx.put("class_loader", w.loader); ctx.put("code_source", w.codeSource);
        ctx.put("signals", "reachable-fileless-" + w.hook); ctx.put("source", "live-attach");
        f.context = ctx;
        return f;
    }
    static void addSignal(Finding f, String signal) {
        if (f.context == null) f.context = new LinkedHashMap<>();
        String cur = f.context.getOrDefault("signals", "");
        f.context.put("signals", cur == null || cur.isEmpty() ? signal : cur + "," + signal);
    }
    // For each fileless wired element: enrich a matching enumeration finding (upgrade to likely + add
    // the reachable signal), else add a standalone finding. Type-agnostic — catches memshells at hook
    // points the contract list / enumeration miss.
    static void mergeReachability(List<Finding> findings, List<WiredElement> reach, String host, int pid, String name) {
        Map<String,Finding> byIdentity = new HashMap<>();
        for (Finding f : findings) if (f.artifact != null && f.artifact.identity != null) byIdentity.put(f.artifact.identity, f);
        for (WiredElement w : reach) {
            if (!Reachability.isReachableMemshell(w)) continue;
            Finding existing = byIdentity.get(w.className);
            if (existing != null) {
                existing.tier = "likely-malicious";
                if (existing.score < 90) existing.score = 90;
                addSignal(existing, "reachable-from-dispatch:" + w.hook);
            } else {
                Finding nf = mapReachabilityFinding(host, pid, name, w);
                findings.add(nf);
                byIdentity.put(w.className, nf);
            }
        }
    }
    static Path resolveAgentJar() {
        try { Path self = Paths.get(Probe.class.getProtectionDomain().getCodeSource().getLocation().toURI());
              Path c = self.getParent().resolve("javamem-agent.jar"); if (Files.exists(c)) return c; } catch (Exception ignore) {}
        return Paths.get("javamem-agent.jar");
    }
    static Path resolveMemContracts(String[] args, Path agentJar) {
        String explicit = argValue(args, "--mem-contracts", null);
        if (explicit != null) return Paths.get(explicit);
        // Binary-relative default: kb/rules/mem-contracts.json beside the probe jar.
        try { Path c = agentJar.getParent().resolve("kb").resolve("rules").resolve("mem-contracts.json");
              if (Files.exists(c)) return c; } catch (Exception ignore) {}
        return null;
    }
    static String sha256(byte[] b) throws Exception {
        StringBuilder sb = new StringBuilder(); for (byte x : MessageDigest.getInstance("SHA-256").digest(b)) sb.append(String.format("%02x", x)); return sb.toString();
    }
    static String sanitize(String s) { StringBuilder sb = new StringBuilder(); for (char c : s.toCharArray()) sb.append(Character.isLetterOrDigit(c)?c:'_'); return sb.toString(); }
    static String argValue(String[] a, String name, String def) { for (int i=0;i<a.length-1;i++) if (a[i].equals(name)) return a[i+1]; return def; }
    static Set<Long> parsePidAllowlist(String csv) {
        Set<Long> out = new LinkedHashSet<>();
        if (csv == null || csv.isBlank()) return out;
        for (String s : csv.split(",")) {
            s = s.trim();
            try { if (!s.isEmpty()) out.add(Long.parseLong(s)); } catch (NumberFormatException ignore) {}
        }
        return out;
    }
}
