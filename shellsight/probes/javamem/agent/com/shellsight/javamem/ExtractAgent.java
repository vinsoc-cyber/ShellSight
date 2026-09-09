package com.shellsight.javamem;

import java.lang.instrument.*;
import java.lang.reflect.Proxy;
import java.nio.file.*;
import java.security.ProtectionDomain;
import java.util.*;
import java.util.concurrent.*;

// Loaded into the SUSPECT JVM via the Attach API. Enumerates loaded classes, keeps fileless app
// candidates AND watchlisted/pipeline-contract classes, captures each one's CURRENT bytecode via
// retransform, writes <handoff>/<i>.class + <i>.facts, then <handoff>/DONE. Coverage-honest:
// per-class failures go to errors.log, never dropped.
public final class ExtractAgent {
    // Stage 4 caps. These are the mechanical form of "low overhead" and "does not disturb the
    // live server"; a promise enforced by a comment is not enforced.
    //
    // 128 classes. The previous 64 was justified as "a memshell is one class plus a handful of
    // helpers", and that reasoning was wrong in kind: the cap does not budget MEMSHELL classes, it
    // budgets CANDIDATE classes, and a benign framework can produce hundreds. Measured 2026-09-02
    // (docs/measurements/2026-09-02-java-mem-fpr/): at 64 the sweep truncated on 3 of 10 benign
    // apps, which makes those apps unmeasurable -- a truncated sweep caps the finding count while
    // the denominator stays the full loaded-class plateau, so it silently UNDERSTATES any rate
    // computed from it. At 128 both remaining apps completed and the finding set was identical at
    // 256, i.e. 128 is a plateau and not merely a looser truncation.
    //
    // Note the shortlist is sorted by suspicion DESCENDING before the budget is spent (see below),
    // so a flood of low-scoring framework candidates crowds out only equal-or-lower-scoring ones.
    // It does not displace a high-scoring memshell. The cost of a small cap is measurement
    // coverage and sub-alert completeness, not top-tier recall.
    //
    // 15000 ms, and BOTH limits move together because both were measured binding. At the old
    // 5000 ms/64 the TIME budget bound on two apps -- bootembedded stopped after 30 classes and its
    // control run after 52, petclinic after 48, all under the 64 cap -- while jenkins stopped on the
    // CAP once a flood of framework candidates filled it. Re-running with the budget raised to 60 s
    // moved both apps onto the cap. So neither limit dominates: raising the cap alone would just
    // move the binding limit back onto the clock, which is why the old comment's "the wall-clock
    // budget binds long before the class cap" was half right and misleading as guidance.
    //
    // The time budget starving a sweep is not a neutral loss either: on bootembedded it truncated
    // before reaching the PLANTED POSITIVE CONTROL, so that app's zero was unfalsifiable and it was
    // excluded. A budget that cannot reach a known implant cannot certify an absence.
    //
    // The budget remains the limit that protects the served application; 15 s keeps it a backstop
    // rather than the routine stopping condition. Per-class retransform cost is NOT measured here
    // -- whole-scan wall clock (6-9 s) is dominated by attach, decompile and fusion, so it cannot
    // be divided out into a per-class number.
    static final int  MAX_CAPTURE = Integer.getInteger("shellsight.maxCapture", 128);
    static final long BUDGET_MS   = Long.getLong("shellsight.budgetMs", 15000);
    // Per-class retransform timeout in ms. A pathological class can hang retransform indefinitely.
    static final long CLASS_TIMEOUT_MS = Long.getLong("shellsight.classTimeoutMs", 200);

    // Populated from args at agent init (same mechanism as pipeline-contracts reaching the Discriminator).
    private static volatile Set<String> PIPELINE_CONTRACTS = new HashSet<>();
    private static volatile Set<String> WATCHLIST          = new HashSet<>();

    public static void agentmain(String args, Instrumentation inst) {
        // Args format: "<handoff_path>|<config_file_path>". Config comes from a file because the
        // JVM's own tooling has historically capped the attach args string.
        String[] parts = args.split("\\|", 2);
        Path handoff = Paths.get(parts[0]);
        if (parts.length >= 2 && !parts[1].isEmpty()) {
            try { loadConfig(Paths.get(parts[1])); } catch (Exception ignored) { }
        }

        List<String> errors = new ArrayList<>();
        List<String> declined = new ArrayList<>();
        CaptureBudget budget = new CaptureBudget(MAX_CAPTURE, BUDGET_MS);

        // ONE executor for the whole run. The previous implementation constructed one INSIDE the
        // per-class loop and never shut any of them down, leaving an idle thread in the target for
        // every class it examined -- up to 2000 of them. A single executor, shut down and awaited
        // in the finally block, is what makes "we leave nothing behind" true rather than intended.
        ExecutorService exec = Executors.newSingleThreadExecutor(r -> {
            Thread t = new Thread(r, "shellsight-capture");
            t.setDaemon(true);
            return t;
        });

        // ONE transformer registration for the whole run, not one per class. The transformer never
        // modifies anything: it records the bytes it is shown and returns null, which tells the JVM
        // to keep the class exactly as it was. This is a READ, implemented with the only API the
        // JVM offers for reading.
        final Map<String, byte[]> captured = new HashMap<>();
        final Class<?>[] wanted = new Class<?>[1];
        ClassFileTransformer capture = new ClassFileTransformer() {
            @Override public byte[] transform(ClassLoader loader, String name, Class<?> beingRedefined,
                    ProtectionDomain pd, byte[] buf) {
                if (beingRedefined != null && beingRedefined == wanted[0]) {
                    captured.put(beingRedefined.getName(), buf);
                }
                return null; // never modify the target
            }
        };

        int idx = 0, scored = 0, candidates = 0;
        boolean transformerAdded = false;
        try {
            // ---- Stage 3: score EVERY loaded class. Reflection only: no bytecode, no safepoint.
            //
            // The declared repository set is computed ONCE for the sweep, not per class: the test it
            // supports runs against every loaded class (~4,800 on a stock Tomcat) and has to stay a
            // path prefix comparison. Live webapp real paths are folded in so an externally-deployed
            // application (<Context docBase="/opt/myapp">) is not called out of contract wholesale.
            Class<?>[] loaded = inst.getAllLoadedClasses();
            REPOS = Repos.discover();
            // Two sources, and the ORDER is not cosmetic. The loaders' own getURLs() is
            // authoritative -- a WebappClassLoaderBase lists WEB-INF/classes and every WEB-INF/lib
            // jar -- and it is what fixes the measured false positive on an externally-deployed
            // webapp. docBases stays as a fallback for a container whose loader is not a
            // URLClassLoader. Each is wrapped separately so one failing does not cost the other.
            try {
                for (String u : DispatchWalk.declaredUrls(loaded)) REPOS.addDocBase(u);
            } catch (Throwable t) {
                errors.add("declared-URL discovery failed: " + t);
            }
            try {
                for (String d : DispatchWalk.docBases(loaded)) REPOS.addDocBase(d);
            } catch (Throwable t) {
                errors.add("docBase discovery failed: " + t);
            }
            List<Scored> shortlist = new ArrayList<>();
            for (Class<?> c : loaded) {
                scored++;
                try {
                    Suspicion.Input in = describe(c);
                    if (in == null) continue;             // authentic platform class
                    // CANDIDACY is broad and separate from ranking: capture produces the bytecode,
                    // and the bytecode holds the decisive evidence. Gating capture on
                    // reflection-only signals discards what is needed to judge the class -- it cost
                    // 20 of 92 corpus cells when this was score-gated.
                    if (!Suspicion.isCandidate(in)) continue;
                    shortlist.add(new Scored(c, Suspicion.score(in), in));
                } catch (Throwable t) {
                    errors.add(safeName(c) + ": scoring failed: " + t);
                }
            }
            candidates = shortlist.size();

            // Highest suspicion first, then by name, so the captured set is reproducible across
            // runs of an unchanged JVM instead of depending on enumeration order.
            shortlist.sort(new Comparator<Scored>() {
                @Override public int compare(Scored a, Scored b) {
                    if (a.score != b.score) return Integer.compare(b.score, a.score);
                    return a.in.className.compareTo(b.in.className);
                }
            });

            // ---- Stage 4: capture only the top of that list, under the budget.
            inst.addTransformer(capture, true);
            transformerAdded = true;
            for (Scored cand : shortlist) {
                // A bootstrap-loaded or otherwise unmodifiable class is REPORTED with its score,
                // because Bootstrap-ClassLoader injection is a published bypass and must not become
                // invisible. The JVM will not let us retransform it, so it goes to declined.tsv
                // rather than being dropped.
                if (cand.in.bootstrapLoaded || !inst.isModifiableClass(cand.c)) {
                    declined.add(cand.in.className + "\t" + cand.score + "\t"
                        + (cand.in.bootstrapLoaded ? "bootstrap-loaded" : "not-modifiable")
                        + "\t" + String.join("+", cand.in.contracts));
                    continue;
                }
                if (!budget.tryConsume()) break;

                byte[] bytes = captureOne(cand.c, inst, exec, wanted, captured, errors);
                if (bytes == null) continue;
                Files.write(handoff.resolve(idx + ".class"), bytes);
                Files.writeString(handoff.resolve(idx + ".facts"), facts(cand.c, bytes, cand.score));
                idx++;
            }
        } catch (Throwable t) {
            errors.add("pipeline: " + t);
        } finally {
            if (transformerAdded) {
                try { inst.removeTransformer(capture); } catch (Throwable ignored) { }
            }
            // Shut the executor down and WAIT. Returning while a capture thread is still running
            // would leave exactly the residue the non-disturbance constraint forbids.
            exec.shutdownNow();
            try { exec.awaitTermination(2, TimeUnit.SECONDS); }
            catch (InterruptedException ignored) { Thread.currentThread().interrupt(); }

            errors.add("summary: scored=" + scored + " candidates=" + candidates
                     + " captured=" + idx + " declined=" + declined.size()
                     + " budget_spent=" + budget.spent());
            // The stop reason is COVERAGE, not decoration: a truncated sweep must never be
            // reported as a complete one.
            if (budget.exhausted()) errors.add("incomplete: " + budget.reason());
            try { if (!declined.isEmpty()) Files.write(handoff.resolve("declined.tsv"), declined); }
            catch (Exception ignore) { }
            try { Files.write(handoff.resolve("errors.log"), errors); } catch (Exception ignore) { }
            try {
                List<String> reach = DispatchWalk.inventory(inst.getAllLoadedClasses());
                if (!reach.isEmpty()) Files.write(handoff.resolve("reachability.tsv"), reach);
            } catch (Throwable ignore) { }
            // DONE must remain the last file written -- the probe reads it as the completion marker.
            try { Files.writeString(handoff.resolve("DONE"), String.valueOf(idx)); } catch (Exception ignore) { }
        }
    }

    /** One scored candidate, carrying the facts Stage 3 computed so Stage 4 need not redo them. */
    private static final class Scored {
        final Class<?> c; final int score; final Suspicion.Input in;
        Scored(Class<?> c, int score, Suspicion.Input in) { this.c = c; this.score = score; this.in = in; }
    }

    /**
     * Gather Stage 3 facts about a class using reflection ONLY.
     *
     * <p>Returns null for authentic platform code, identified by its DEFINING LOADER -- an
     * unforgeable property. A class merely named java.* but defined by an application loader is NOT
     * excluded here; that naming trick is the evasion this guards against.
     */
    /**
     * The declared repository set for the sweep in progress.
     *
     * <p>Static because {@code describe} is static and on the hot path; set once in agentmain before
     * the sweep. Null until then, and {@code describe} treats null as "cannot tell" -- falling open,
     * which is the required direction for this signal.
     */
    private static Repos REPOS;

    private static Suspicion.Input describe(Class<?> c) {
        ClassLoader cl;
        try { cl = c.getClassLoader(); } catch (Throwable t) { return null; }

        boolean bootstrap = (cl == null);
        if (cl != null && cl == ClassLoader.getPlatformClassLoader()) return null;

        String n = safeName(c);
        // The agent's own classes and its bundled ASM, keyed on the DEFINING loader so an
        // application class merely named com.shellsight.* is still scanned.
        if (cl == ExtractAgent.class.getClassLoader()
            && (n.startsWith("com.shellsight.javamem.") || n.startsWith("org.objectweb.asm."))) return null;

        boolean diskAbsent;
        try {
            ProtectionDomain pd = c.getProtectionDomain();
            diskAbsent = pd == null || pd.getCodeSource() == null || pd.getCodeSource().getLocation() == null;
        } catch (Throwable t) { diskAbsent = false; }

        // DIRECT interfaces plus the superclass chain, DELIBERATELY NOT the transitive closure.
        //
        // This list feeds CANDIDACY and RANKING (Suspicion.isCandidate / score), and candidacy admits
        // any class carrying a pipeline contract. Running the closure here was measured on 2026-09-01
        // and it wrecks the sweep: ordinary framework classes reach a pipeline contract through some
        // super-interface in enormous numbers, candidates explode, and the 5000 ms capture budget is
        // exhausted before the shell is reached -- 28 of 44 cells truncated against 0 of 92 on the
        // same host, with 6 corpus cells losing their finding entirely. That is the starvation this
        // project already had on record: capture is budget-limited, so widening candidacy without a
        // ranking change starves the thing you were looking for.
        //
        // The closure belongs where the VERDICT is decided, not where capture is chosen: it is applied
        // to the `iface` facts in describe(), which is what internal/jvmprov/claim.go turns into
        // Claim.Contracts. A fileless shell is admitted here by diskAbsent regardless of its
        // interfaces, so nothing is lost -- the Spring cells were always captured, they were only
        // scored wrong.
        List<String> contracts = new ArrayList<>();
        List<String> methods   = new ArrayList<>();
        try {
            for (Class<?> i : c.getInterfaces()) contracts.add(i.getName());
            for (Class<?> sup = c.getSuperclass(); sup != null && sup != Object.class; sup = sup.getSuperclass()) {
                contracts.add(sup.getName());
                for (Class<?> i : sup.getInterfaces()) contracts.add(i.getName());
            }
            for (java.lang.reflect.Method m : c.getDeclaredMethods()) methods.add(m.getName());
        } catch (Throwable ignored) { }

        // Capability hints available WITHOUT bytecode: the types this class declares in its fields.
        // Weaker than a constant-pool scan, which is why it only contributes to RANKING; the real
        // capability check runs on captured bytecode.
        List<String> caps = new ArrayList<>();
        try {
            for (java.lang.reflect.Field f : c.getDeclaredFields()) {
                String tn = f.getType().getName();
                if (tn.equals("java.lang.Runtime") || tn.equals("java.lang.ProcessBuilder")
                    || tn.startsWith("javax.crypto.")) caps.add(tn);
            }
        } catch (Throwable ignored) { }

        // Out of contract only makes sense for a class that HAS a source; a class with none is
        // diskAbsent and already covered. Falls open when the repository set is unknown.
        boolean outOfContract = false;
        if (!diskAbsent && REPOS != null) {
            try {
                outOfContract = REPOS.outOfContract(Repos.normalise(codeSource(c)));
            } catch (Throwable ignored) { }
        }

        return new Suspicion.Input(n, diskAbsent, bootstrap, false,
            isVerifiedGenerated(c), contracts, caps, methods, WATCHLIST.contains(n), outOfContract);
    }

    /**
     * Retransform one class on the SHARED executor and return the bytes the transformer saw.
     *
     * <p>The per-class timeout survives from the previous implementation because it earns its keep:
     * a pathological class can hang retransform indefinitely, and hanging inside a customer's
     * request-serving JVM is the worst outcome this tool has.
     */
    private static byte[] captureOne(Class<?> c, Instrumentation inst, ExecutorService exec,
                                     Class<?>[] wanted, Map<String, byte[]> captured,
                                     List<String> errors) {
        wanted[0] = c;
        captured.remove(c.getName());
        Future<?> f = exec.submit(() -> {
            try { inst.retransformClasses(c); } catch (Throwable ignored) { }
        });
        try {
            f.get(CLASS_TIMEOUT_MS, TimeUnit.MILLISECONDS);
        } catch (TimeoutException e) {
            f.cancel(true);
            errors.add(safeName(c) + ": retransform timeout (" + CLASS_TIMEOUT_MS + "ms); skipped");
            return null;
        } catch (Exception ignored) {
        } finally {
            wanted[0] = null;
        }
        byte[] b = captured.remove(c.getName());
        if (b == null) errors.add(safeName(c) + ": no bytecode after retransform");
        return b;
    }

    /**
     * Parse the line-oriented config file written by Acquire.writeAgentConfig().
     * Format: sentinel line ("WATCHLIST" or "CONTRACTS") followed by one entry per line.
     */
    private static void loadConfig(Path configFile) throws Exception {
        java.util.List<String> lines = java.nio.file.Files.readAllLines(configFile);
        Set<String> target = null;
        for (String line : lines) {
            String t = line.trim();
            if (t.isEmpty()) continue;
            if ("WATCHLIST".equals(t)) { target = WATCHLIST; continue; }
            if ("CONTRACTS".equals(t)) { target = PIPELINE_CONTRACTS; continue; }
            if (target != null) target.add(t);
        }
    }

    // ---- Provenance checks (inlined from Provenance.java — agent jar has no probe jar on cp) ----

    /**
     * Every supertype of {@code c} -- the TRANSITIVE closure over interfaces and superclasses.
     *
     * <p>WHY THIS IS NOT `getInterfaces()` PLUS THE SUPERCLASS CHAIN. It used to be, and that missed
     * a contract we already shipped. Measured 2026-09-01 on the Spring corpus: the generator's
     * Interceptor shells implement {@code org.springframework.web.servlet.AsyncHandlerInterceptor},
     * which EXTENDS {@code HandlerInterceptor} -- a pipeline contract present in mem-contracts.json
     * since before that corpus existed. One hop away and the matcher could not see it, so all 13
     * Interceptor cells fell through `pipelineWired` and scored 80 instead of 95, and a single-
     * capability cell fell to `suspicious` 50 outright.
     *
     * <p>Adding the one missing name would have fixed those cells and left the mechanism broken:
     * `HandlerInterceptor` has several sub-interfaces and every framework in the contract set has the
     * same shape, so a finite name list is the weakness rather than the fix. The closure resolves any
     * sub-interface of any contract, for every framework, without naming any of them.
     *
     * <p>Bounded: an identity visited-set (so a diamond or a cycle terminates) and a depth cap.
     *
     * <p><b>USED FOR THE VERDICT ONLY -- NOT FOR CANDIDACY.</b> It is applied to the {@code iface}
     * facts emitted by {@code describe()}, which internal/jvmprov/claim.go turns into
     * Claim.Contracts and fuse.go tests with isPipelineContract. It is deliberately NOT used by
     * {@code describe(Class)} where Suspicion.Input is built, because candidacy admits anything
     * carrying a pipeline contract: with the closure there, ordinary framework classes match through
     * some super-interface in bulk, candidates explode, and the capture budget is spent before the
     * shell is reached. Measured -- 28 of 44 corpus cells truncated against 0 of 92 on the same host,
     * 6 cells losing their finding outright. See the comment at the candidacy call site.
     *
     * <p>Only ever ADDS names, so a captured class can move from not-pipeline-wired to
     * pipeline-wired and never the reverse -- no captured cell can lose a tier. See
     * docs/measurements/2026-08-30-memshell-detection-landscape/06-spring-reachability.md.
     */
    /** Depth and breadth caps. See MAX_TYPE_DEPTH's comment for why these are tight, not generous. */
    private static final int MAX_TYPE_DEPTH = 4;
    private static final int MAX_TYPE_NAMES = 48;

    private static void collectTypes(Class<?> c, List<String> out, Set<Class<?>> seen, int depth) {
        if (c == null || depth > MAX_TYPE_DEPTH || c == Object.class || !seen.add(c)) return;
        if (out.size() >= MAX_TYPE_NAMES) return;
        for (Class<?> i : c.getInterfaces()) {
            if (!out.contains(i.getName())) out.add(i.getName());
            // STOP at a contract. Walking past one cannot add a name this exists to find, and every
            // extra hop is a getInterfaces() call that can force the JVM to LOAD an interface it has
            // not loaded yet -- inside a 5000 ms budget, in the served application. Bounding the walk
            // is what keeps the closure from costing the sweep the very class it is looking for.
            if (Contracts.isPipeline(i.getName())) continue;
            collectTypes(i, out, seen, depth + 1);
        }
        Class<?> sup = c.getSuperclass();
        if (sup != null && sup != Object.class) {
            if (!out.contains(sup.getName())) out.add(sup.getName());
            if (!Contracts.isPipeline(sup.getName())) collectTypes(sup, out, seen, depth + 1);
        }
    }

    // NOTE: keep this method identical to the copy in Provenance.java
    /**
     * True only for genuinely runtime-generated classes. DECLARED identity (name substring,
     * implemented interface, extended superclass) is attacker-forgeable, so each mechanism is
     * verified by a JVM-authentic property (Proxy.isProxyClass / Class.isHidden) or by the
     * generator's structural fingerprint (CGLIB$ members / Jasper _jspService / groovyc
     * $getStaticMetaClass) — never by name or declared type alone.
     */
    static boolean isVerifiedGenerated(Class<?> c) {
        if (c == null) return false;
        if (Proxy.isProxyClass(c)) return true;                       // JVM-authentic
        if (c.isSynthetic() && isHiddenClass(c)) return true;         // lambda / hidden class (JVM-authentic, JDK15+)
        if (isReflectionAccessor(c)) return true;                     // JVM-authentic (see below)
        if (isJdkTrampoline(c)) return true;                          // JVM-authentic (see below)
        String n = c.getName();
        // CGLIB/Spring proxy: name marker is forgeable -> also require the generated fingerprint
        // (CGLIB$-prefixed members) and a real (non-Object) enhanced superclass.
        boolean cglibName = n.contains("$$EnhancerBySpringCGLIB$$") || n.contains("$$FastClassBySpringCGLIB$$");
        if (cglibName && c.getSuperclass() != null && c.getSuperclass() != Object.class
            && hasMemberPrefixed(c, "CGLIB$")) return true;
        // GUICE proxy: same shape of rule, DIFFERENT fingerprint, and the difference is the point.
        //
        // Guice generates one of these per injectable class, so a Guice application produces one
        // false positive per binding: measured 2026-09-02 on a benign jenkins/jenkins:lts, 230 of
        // 231 findings were `X$$FastClassByGuice$$<hash>` reported as kb:java-mem/fileless-class.
        // The count grew with the capture cap -- 38 at 64, 102 at 128, 230 at 256 -- so no capture
        // budget completes such a sweep. That is why this is a classification fix and not a budget
        // one: raising the cap converts truncation into more false positives.
        //
        // COPYING THE CGLIB ARM ABOVE WOULD MATCH NOTHING. Guice 5.0.1 dropped cglib and generates
        // these with ASM directly, so the live classes are (measured, not assumed):
        //     super  : java.lang.Object          -- so the non-Object superclass test fails
        //     methods: GUICE$TRAMPOLINE apply
        //     fields : GUICE$INVOKERS index
        //     CGLIB$ member: absent              -- so the CGLIB$ test fails too
        // They keep the legacy $$FastClassByGuice$$ name only for compatibility. The structural
        // marker is Guice's own GUICE$ prefix, which is what this requires in addition to the
        // forgeable name -- the same bar the CGLIB, JSP and Groovy arms set.
        //
        // Prior art and the measurement: docs/measurements/2026-09-02-guice-generated-proxies/
        boolean guiceName = n.contains("$$FastClassByGuice$$") || n.contains("$$EnhancerByGuice$$");
        if (guiceName && hasMemberPrefixed(c, "GUICE$")) return true;
        // JSP: extending HttpJspBase is forgeable -> also require Jasper's generated _jspService method.
        for (Class<?> s = c.getSuperclass(); s != null && s != Object.class; s = s.getSuperclass())
            if ("org.apache.jasper.runtime.HttpJspBase".equals(s.getName()))
                return hasDeclaredMethod(c, "_jspService");
        // JASPER, THE OTHER TWO ARTEFACTS. The arm above covers a JSP *page* only, and covers it by
        // its SUPERCLASS -- which Jasper writes as `pageInfo.getExtends()`, i.e. whatever the
        // `<%@ page extends="..." %>` directive says. That is the configurable half. From Tomcat 9's
        // Generator.java the page and tag-file preambles unconditionally emit
        //     implements org.apache.jasper.runtime.JspSourceDependent, ...JspSourceImports
        // plus getDependants() returning the generated _jspx_dependants field, so THAT triple is the
        // invariant. Added beside the arm above rather than replacing it, so a page compiled by an
        // older Jasper keeps matching.
        //
        // Measured 2026-09-03 on a benign Jetty petclinic (docs/measurements/2026-09-03-jetty-jasper-fp/):
        // tag files are `X_tag extends jakarta.servlet.jsp.tagext.SimpleTagSupport implements
        // JspSourceDependent, JspSourceImports, SimpleTag` with getDependants + doTag + _jspx_dependants;
        // fragment helpers are `X_jsp$Helper extends org.apache.jasper.runtime.JspFragmentHelper` with
        // invoke/invoke0 and _jspx_parent. Neither was covered, which is why 14 sub-alert findings
        // survived the page-class fix.
        if (isJasperSourceDependent(c)) return true;
        // Fragment helper: the $Helper NAME is forgeable and the class implements no interface at
        // all, so require Jasper's own helper superclass, its generated invoke method, AND that the
        // enclosing class carries the page/tag invariant -- the last is what stops a bare `$Helper`
        // from being an exemption on its own.
        //
        // Deliberately NOT a recursive isVerifiedGenerated(enclosing) call: getEnclosingClass reads
        // an attacker-supplied class-file attribute, so a crafted pair naming each other would
        // recurse until StackOverflowError. isJasperSourceDependent does not recurse.
        if (c.getSuperclass() != null
            && "org.apache.jasper.runtime.JspFragmentHelper".equals(c.getSuperclass().getName())
            && hasDeclaredMethod(c, "invoke")) {
            Class<?> enclosing = null;
            try { enclosing = c.getEnclosingClass(); } catch (Throwable ignored) { }
            if (enclosing != null && enclosing != c && isJasperSourceDependent(enclosing)) return true;
        }
        // Groovy: implementing GroovyObject is forgeable -> also require groovyc's $getStaticMetaClass.
        for (Class<?> s = c; s != null && s != Object.class; s = s.getSuperclass())
            for (Class<?> iface : s.getInterfaces())
                if ("groovy.lang.GroovyObject".equals(iface.getName()))
                    return hasDeclaredMethod(c, "$getStaticMetaClass");
        return false;
    }
    // isHidden() is JDK 15+; call reflectively so the agent still targets --release 11.

    /**
     * True for the reflection accessor stubs the JVM generates for itself
     * (jdk.internal.reflect.GeneratedConstructorAccessorN / GeneratedMethodAccessorN, and the
     * sun.reflect.* spelling on JDK 8).
     *
     * WHY THIS EXISTS: measured 2026-08-30 against a stock Tomcat 9 / JDK 11 container with
     * nothing injected, these produced 31 of 31 findings -- the ENTIRE false-positive baseline.
     * They are genuinely fileless (null CodeSource) because the JVM synthesises them at runtime
     * to speed up reflection, so a disk-absence test flags every one.
     *
     * WHY IT IS NOT FORGEABLE: the test is not the class's own name -- that is attacker-chosen.
     * It is the identity of its DEFINING loader, plus the origin of that loader's own class.
     * DelegatingClassLoader is instantiated by the JVM and is itself defined by the bootstrap or
     * platform loader, which application code cannot achieve without JVM launch flags. A memshell
     * that merely NAMES itself jdk.internal.reflect.Whatever, or that supplies its own loader
     * class of that name, fails the second half of the check and is still scanned.
     *
     * Contrast: xyy-ws/NoAgent-memshell-scanner excludes these by class-NAME substring, which a
     * shell defeats by choosing the name. This check cannot be defeated that way.
     */
    static boolean isReflectionAccessor(Class<?> c) {
        return definedByJdkInternalLoader(c, "jdk.internal.reflect.DelegatingClassLoader",
                                            "sun.reflect.DelegatingClassLoader");
    }

    /**
     * True for {@code sun.reflect.misc.Trampoline}, which the JDK defines with a deliberately null
     * CodeSource.
     *
     * <p>WHY THIS EXISTS: measured 2026-09-03 on a benign Jenkins, this was 1 alert-tier false
     * positive at score 80 -- {@code kb:java-mem/fileless-capable-class}, "a fileless class with
     * multiple capability indicators and no benign provenance". Every clause of that was TRUE, which
     * is what made it worth a lit review: OpenJDK's {@code MethodUtil} is itself a
     * {@code SecureClassLoader} and defines Trampoline via
     * {@code defineClass(name, b, 0, b.length, new CodeSource(null, null))}. The separate loader is
     * deliberate -- it exists so permission checks apply rather than being bypassed by the bootstrap
     * loader -- and the two capabilities counted against it, {@code loader} and {@code reflect}, are
     * its entire job: it declares {@code invoke(Method, Object, Object[])} as a security boundary.
     * It is reached through java.beans, JMX and EL, so it is not Jenkins-specific.
     *
     * <p>WHY IT IS NOT A NAME TEST: the same sweep also found {@code groovy.lang.TrampolineClosure},
     * an ordinary application class from {@code groovy-all-2.4.21.jar} under the webapp loader. A
     * name or package-prefix exemption would be both forgeable and, measurably, ambiguous.
     *
     * <p>See docs/measurements/2026-09-03-jdk-trampoline-fp/lit-review.md.
     */
    static boolean isJdkTrampoline(Class<?> c) {
        return definedByJdkInternalLoader(c, "sun.reflect.misc.MethodUtil");
    }

    /**
     * The forgery-resistant half, in ONE place: is {@code c}'s DEFINING loader one of the named
     * JDK-internal loader types, AND did that loader's own class come from the JVM rather than from
     * the application?
     *
     * <p>The second test is what cannot be forged, and it is the reason this is a shared helper
     * rather than copied per arm. A memshell that merely NAMES itself after a JDK class, or that
     * supplies its own loader class of a matching name, fails it: the loader's class must itself be
     * defined by the bootstrap or platform loader, which application code cannot arrange without JVM
     * launch flags. Contrast xyy-ws/NoAgent-memshell-scanner, which excludes these by class-NAME
     * substring and is defeated by choosing the name.
     */
    private static boolean definedByJdkInternalLoader(Class<?> c, String... loaderClassNames) {
        try {
            ClassLoader cl = c.getClassLoader();
            if (cl == null) return false;
            String loaderClass = cl.getClass().getName();
            boolean named = false;
            for (String n : loaderClassNames) {
                if (n.equals(loaderClass)) { named = true; break; }
            }
            if (!named) return false;
            // The loader's OWN class must come from the JVM itself, not from the application.
            ClassLoader meta = cl.getClass().getClassLoader();
            return meta == null || meta == ClassLoader.getPlatformClassLoader();
        } catch (Throwable ignored) {
            return false;
        }
    }

    private static boolean isHiddenClass(Class<?> c) {
        try { return Boolean.TRUE.equals(Class.class.getMethod("isHidden").invoke(c)); }
        catch (Throwable t) { return false; }
    }
    private static boolean hasMemberPrefixed(Class<?> c, String prefix) {
        try {
            for (java.lang.reflect.Field f : c.getDeclaredFields())   if (f.getName().startsWith(prefix)) return true;
            for (java.lang.reflect.Method m : c.getDeclaredMethods()) if (m.getName().startsWith(prefix)) return true;
        } catch (Throwable ignored) {}
        return false;
    }
    private static boolean hasDeclaredMethod(Class<?> c, String name) {
        try { for (java.lang.reflect.Method m : c.getDeclaredMethods()) if (m.getName().equals(name)) return true; }
        catch (Throwable ignored) {}
        return false;
    }
    private static boolean hasDeclaredField(Class<?> c, String name) {
        try { for (java.lang.reflect.Field f : c.getDeclaredFields()) if (f.getName().equals(name)) return true; }
        catch (Throwable ignored) {}
        return false;
    }

    /**
     * Jasper's unconditional page/tag-file fingerprint: the generator writes
     * {@code implements org.apache.jasper.runtime.JspSourceDependent, ...JspSourceImports} into
     * every page AND tag-file preamble, together with {@code getDependants()} returning the
     * generated {@code _jspx_dependants} field. The interface name alone is forgeable, so all three
     * are required -- the same bar (forgeable marker plus the generator's own structural output)
     * that the CGLIB, Guice, JSP-superclass and Groovy arms set.
     *
     * <p>Does not recurse: the fragment-helper arm calls this on an enclosing class whose identity
     * comes from an attacker-supplied class-file attribute.
     */
    private static boolean isJasperSourceDependent(Class<?> c) {
        if (c == null) return false;
        try {
            for (Class<?> s = c; s != null && s != Object.class; s = s.getSuperclass())
                for (Class<?> iface : s.getInterfaces())
                    if ("org.apache.jasper.runtime.JspSourceDependent".equals(iface.getName()))
                        return hasDeclaredMethod(c, "getDependants") && hasDeclaredField(c, "_jspx_dependants");
        } catch (Throwable ignored) {}
        return false;
    }

    /** Read the class's authoritative on-classpath bytes for the in-memory-vs-source diff.
     *  Order: (1) the exact file: jar named by the CodeSource (precise); then (2) the class's own
     *  classloader resources — which resolve Spring Boot nested fat-jars
     *  (jar:nested:.../app.jar!/BOOT-INF/lib/x.jar!/), exploded directories, modules, and custom
     *  loaders that (1) cannot open. Returns null only when nothing backs the class anywhere
     *  (genuine fileless / injected / CodeSource-spoofed code) -> NO_SOURCE -> still flagged.
     *  NOTE: keep this method identical to the copy in Provenance.java */
    static byte[] readFromCodeSource(Class<?> c) {
        String entry = c.getName().replace('.', '/') + ".class";
        // (1) exact file: jar named by the CodeSource
        try {
            java.security.CodeSource cs = c.getProtectionDomain().getCodeSource();
            if (cs != null && cs.getLocation() != null) {
                java.net.URL loc = cs.getLocation();
                if (loc.getProtocol().equals("file") && loc.getPath().endsWith(".jar")) {
                    try (java.util.jar.JarFile jf = new java.util.jar.JarFile(new java.io.File(loc.toURI()))) {
                        java.util.zip.ZipEntry e = jf.getEntry(entry);
                        if (e != null) { try (java.io.InputStream in = jf.getInputStream(e)) { return in.readAllBytes(); } }
                    }
                }
            }
        } catch (Exception ignore) {}
        // (2) fallback: the class's own classloader resolves its bytes regardless of packaging
        try {
            ClassLoader cl = c.getClassLoader();
            java.io.InputStream in = (cl != null) ? cl.getResourceAsStream(entry)
                                                  : ClassLoader.getSystemResourceAsStream(entry);
            if (in != null) { try (in) { return in.readAllBytes(); } }
        } catch (Exception ignore) {}
        return null;
    }

    /**
     * Canonicalize class bytecode so two byte-different-but-equivalent encodings of the SAME class
     * normalize identically. The JVM re-serializes a class on retransform (member + constant-pool
     * order differ from the on-disk jar, especially for classes loaded before the agent attached),
     * so a raw-byte compare false-MISMATCHes every legitimate framework class loaded from a jar.
     * We parse to a tree, SORT methods/fields/interfaces, strip debug+frames, and re-emit with a
     * fresh constant pool — order-independent. A genuine code change (a stomp) still differs.
     * Returns null if ASM cannot parse the input.
     * NOTE: keep this method identical to the copy in Provenance.java.
     */
    static byte[] normalize(byte[] b) {
        try {
            org.objectweb.asm.tree.ClassNode cn = new org.objectweb.asm.tree.ClassNode();
            new org.objectweb.asm.ClassReader(b).accept(cn,
                org.objectweb.asm.ClassReader.SKIP_DEBUG | org.objectweb.asm.ClassReader.SKIP_FRAMES);
            cn.methods.sort(java.util.Comparator.comparing((org.objectweb.asm.tree.MethodNode m) -> m.name + m.desc));
            if (cn.fields != null) cn.fields.sort(java.util.Comparator.comparing((org.objectweb.asm.tree.FieldNode f) -> f.name + f.desc));
            if (cn.interfaces != null) java.util.Collections.sort(cn.interfaces);
            org.objectweb.asm.ClassWriter cw = new org.objectweb.asm.ClassWriter(0);
            cn.accept(cw);
            return cw.toByteArray();
        } catch (Throwable t) { return null; }
    }

    /** Compare in-memory bytes to jar bytes. Returns "MATCH", "MISMATCH", or "NO_SOURCE".
     *  Normalizes both byte arrays with ASM before comparing so cosmetic JVM differences
     *  (constant-pool reordering, debug info) do not produce false MISMATCH results. */
    private static String diffAgainstSource(byte[] fromJar, byte[] inMemory) {
        if (fromJar == null) return "NO_SOURCE";
        byte[] normJar = normalize(fromJar);
        byte[] normMem = normalize(inMemory);
        // If ASM can't parse either array, treat as NO_SOURCE rather than a false MISMATCH.
        if (normJar == null || normMem == null) return "NO_SOURCE";
        return java.util.Arrays.equals(normJar, normMem) ? "MATCH" : "MISMATCH";
    }

    // ---- Facts serialization ----

    static String codeSource(Class<?> c) {
        try {
            ProtectionDomain pd = c.getProtectionDomain();
            if (pd == null || pd.getCodeSource() == null || pd.getCodeSource().getLocation() == null) return null;
            return pd.getCodeSource().getLocation().toString();
        } catch (Throwable t) { return null; }
    }

    private static String facts(Class<?> c, byte[] capturedBytes, int suspicion) {
        StringBuilder sb = new StringBuilder();
        sb.append("name\t").append(c.getName()).append('\n');
        sb.append("loader\t").append(c.getClassLoader()).append('\n');
        String cs = codeSource(c);
        sb.append("codesource\t").append(cs).append('\n');
        // Whether that CodeSource is somewhere the container ever declared. A SEPARATE fact rather
        // than something folded into `codesource`, because the Go side has to tell "a real file in a
        // legitimate place" from "a real file in a place nothing declared" -- the whole point being
        // that both are corroborated claims and only one of them is benign.
        if (REPOS != null) {
            try {
                if (REPOS.outOfContract(Repos.normalise(cs))) {
                    sb.append("out_of_contract\ttrue\n");
                    sb.append("declared_repos\t").append(REPOS.describe()).append('\n');
                }
            } catch (Throwable ignored) { }
        }
        Class<?> sup = c.getSuperclass();
        sb.append("super\t").append(sup == null ? "" : sup.getName()).append('\n');
        // TRANSITIVE. `iface` and `superchain` are what internal/jvmprov/claim.go turns into
        // Claim.Contracts, and Claim.Contracts is what fuse.go tests with isPipelineContract -- so
        // THIS is the emitter that decides the 95 tier on the native path, and it was direct-
        // interfaces-only. Emitting the closure here and in describeCandidate keeps the agent's own
        // ranking and the Go verdict layer reading the same set; fixing only one of them leaves the
        // other silently shallow, which is how the Spring cells scored 80 with `HandlerInterceptor`
        // already in the contract set. See collectTypes and
        // docs/measurements/2026-08-30-memshell-detection-landscape/06-spring-reachability.md.
        List<String> allTypes = new ArrayList<String>();
        try { collectTypes(c, allTypes, new HashSet<Class<?>>(), 0); } catch (Throwable ignored) { }
        for (String t : allTypes) sb.append("iface\t").append(t).append('\n');
        for (Class<?> s = sup; s != null && s != Object.class; s = s.getSuperclass())
            sb.append("superchain\t").append(s.getName()).append('\n');

        // Structural generated-ness check (replaces name-substring allowlisting).
        sb.append("verified_generated\t").append(isVerifiedGenerated(c)).append('\n');
        // The Stage 3 score is threaded through rather than recomputed: calling describe() again
        // here would double the reflection work and could disagree with the number that selected
        // this class for capture in the first place.
        sb.append("suspicion\t").append(suspicion).append('\n');

        // Bytecode-vs-jar diff for classes with a non-null CodeSource (watched/pipeline path).
        // For disk-absent classes (cs == null) this is a no-op: they have no jar to compare against.
        if (cs != null) {
            byte[] fromJar = readFromCodeSource(c);
            // Whether the JVM's OWN ClassLoader was willing to answer. Paired with Go's
            // independent jar read, this is what exposes a fabricating loader: the loader answered
            // where the filesystem does not back the class. On its own it proves nothing -- it is
            // exactly what a hostile loader would forge -- which is why it is emitted as a CLAIM
            // and adjudicated outside the JVM.
            sb.append("loader_read_ok\t").append(fromJar != null).append('\n');
            String diff = diffAgainstSource(fromJar, capturedBytes);
            if ("MISMATCH".equals(diff)) {
                sb.append("provenance_anomaly\t")
                  .append("bytecode-mismatch: ").append(c.getName())
                  .append(" in-memory bytecode differs from ").append(cs).append('\n');
            } else if ("NO_SOURCE".equals(diff)) {
                // Claimed a CodeSource but no class entry in the jar → treat as suspicious.
                sb.append("provenance_anomaly\t")
                  .append("no-source: ").append(c.getName())
                  .append(" claimed CodeSource ").append(cs).append(" but class not found in jar").append('\n');
            }
            // MATCH → no anomaly signal (trusted)
        } else {
            sb.append("loader_read_ok\tfalse\n");
        }

        return sb.toString();
    }

    private static String safeName(Class<?> c) { try { return c.getName(); } catch (Throwable t) { return "<?>"; } }
}
