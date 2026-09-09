package com.shellsight.javamem;

import java.lang.reflect.Proxy;

/** Verified-identity checks that replace name-substring allowlisting. */
/**
 * UNREACHABLE FROM PRODUCTION. Verified 2026-09-03: every method here has ZERO callers in
 * probes/javamem/src -- the single grep hit for {@code readFromCodeSource} is a COMMENT in
 * Reachability.java, not a call.
 *
 * <p>THE LIVE IMPLEMENTATION IS {@code ExtractAgent} (probes/javamem/agent/...). The agent computes
 * generated-ness in the target JVM and writes it into its facts file as {@code verified_generated};
 * both verdict layers then read that FACT -- Go through {@code internal/jvmprov/claim.go}, Java
 * through {@code Extract.java} into {@code Discriminator.assess}. Nothing calls the code below.
 *
 * <p><b>ADD NEW EXEMPTION ARMS TO {@code ExtractAgent}, NOT HERE.</b> This copy is already behind:
 * it lacks the Guice ({@code 96c94e9}), Jasper tag-file/fragment-helper and JDK-trampoline arms. That
 * divergence is harmless only because this class is dead -- which is exactly why it is dangerous to
 * leave unlabelled, since the class looks live and is fully implemented.
 *
 * <p>The duplication is structural, not accidental: the agent jar is standalone and cannot import
 * the probe's classes, which is why two copies exist at all (compare {@code Contracts.java}, whose
 * header carries the same warning about {@code Discriminator.PIPELINE_CONTRACTS}).
 *
 * <p><b>Why it is still here:</b> {@code ProvenanceTests} (19 references) is the only home of the
 * bytecode-normalisation and {@code DiffResult} tests, and {@code DiffResult} is declared ONLY in
 * this file, so deleting the class means porting those tests to {@code ExtractAgent}'s
 * differently-shaped diff API. Recorded as follow-up in
 * docs/measurements/2026-09-03-jetty-jasper-fp/README.md rather than done alongside detector
 * changes. Tests written against THIS class prove nothing about shipped behaviour.
 */
final class Provenance {
    private Provenance() {}

    /**
     * Canonicalize class bytecode so two byte-different-but-equivalent encodings of the SAME class
     * normalize identically. The JVM re-serializes a class on retransform (member + constant-pool
     * order differ from the on-disk jar, especially for classes loaded before the agent attached),
     * so a raw-byte compare false-MISMATCHes every legitimate framework class loaded from a jar.
     * We parse to a tree, SORT methods/fields/interfaces, strip debug+frames, and re-emit with a
     * fresh constant pool — order-independent. A genuine code change (a stomp) still differs.
     * Returns null if ASM cannot parse the input.
     * NOTE: keep this method identical to the copy in ExtractAgent.java.
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

    // NOTE: keep this method identical to the copy in ExtractAgent.java
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
        String n = c.getName();
        // CGLIB/Spring proxy: name marker is forgeable -> also require the generated fingerprint
        // (CGLIB$-prefixed members) and a real (non-Object) enhanced superclass.
        boolean cglibName = n.contains("$$EnhancerBySpringCGLIB$$") || n.contains("$$FastClassBySpringCGLIB$$");
        if (cglibName && c.getSuperclass() != null && c.getSuperclass() != Object.class
            && hasMemberPrefixed(c, "CGLIB$")) return true;
        // JSP: extending HttpJspBase is forgeable -> also require Jasper's generated _jspService method.
        for (Class<?> s = c.getSuperclass(); s != null && s != Object.class; s = s.getSuperclass())
            if ("org.apache.jasper.runtime.HttpJspBase".equals(s.getName()))
                return hasDeclaredMethod(c, "_jspService");
        // Groovy: implementing GroovyObject is forgeable -> also require groovyc's $getStaticMetaClass.
        for (Class<?> s = c; s != null && s != Object.class; s = s.getSuperclass())
            for (Class<?> iface : s.getInterfaces())
                if ("groovy.lang.GroovyObject".equals(iface.getName()))
                    return hasDeclaredMethod(c, "$getStaticMetaClass");
        return false;
    }
    // isHidden() is JDK 15+; call reflectively so this stays compilable at --release 11.

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
        try {
            ClassLoader cl = c.getClassLoader();
            if (cl == null) return false;
            String loaderClass = cl.getClass().getName();
            if (!"jdk.internal.reflect.DelegatingClassLoader".equals(loaderClass)
                && !"sun.reflect.DelegatingClassLoader".equals(loaderClass)) return false;
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

    /** Kept ONLY to prove the old name-only heuristic is gone: a name never implies generated. */
    static boolean nameAloneImpliesGenerated(String name) { return false; }

    enum DiffResult { MATCH, MISMATCH, NO_SOURCE }

    /** Compare in-memory bytecode to the bytes read from the claimed jar entry.
     *  Normalizes both byte arrays with ASM before comparing so cosmetic JVM differences
     *  (constant-pool reordering, debug info) do not produce false MISMATCH results.
     *  If ASM cannot parse either array, returns NO_SOURCE rather than a false MISMATCH. */
    static DiffResult diffAgainstSource(byte[] fromJar, byte[] inMemory) {
        if (fromJar == null) return DiffResult.NO_SOURCE;
        byte[] normJar = normalize(fromJar);
        byte[] normMem = normalize(inMemory);
        if (normJar == null || normMem == null) return DiffResult.NO_SOURCE;
        return java.util.Arrays.equals(normJar, normMem) ? DiffResult.MATCH : DiffResult.MISMATCH;
    }

    /** Read the class's authoritative on-classpath bytes for the in-memory-vs-source diff.
     *  (1) the exact file: jar named by the CodeSource; then (2) the class's own classloader
     *  resources — resolving Spring Boot nested fat-jars, exploded dirs, modules, custom loaders.
     *  Returns null only when nothing backs the class (fileless/injected/spoofed) -> NO_SOURCE.
     *  NOTE: keep this method identical to the copy in ExtractAgent.java */
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
}
