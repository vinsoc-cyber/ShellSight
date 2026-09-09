package com.shellsight.javamem;

import org.objectweb.asm.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

final class ClassFacts {
    final String className; final boolean filelessOrigin; final boolean trustedProvenance;
    final List<String> contracts; final List<String> capabilityHits;
    /** True only when the agent structurally verified this class as runtime-generated (JDK proxy / lambda / CGLIB). */
    final boolean verifiedGenerated;
    /** Non-empty when the agent detected a bytecode-vs-jar mismatch or CodeSource claimed but no source found. */
    final String provenanceAnomaly;
    /**
     * The class has a real file, but outside every repository the container declares.
     *
     * <p>Distinct from filelessOrigin -- and it has to be, because the two are the opposite claims
     * about the same field. A class from /tmp/web-install.jar (CISA AR25-261A) is NOT fileless: its
     * jar exists and contains it. That is exactly why it produced no finding until this existed.
     */
    final boolean outOfContract;
    final String declaredRepos;
    ClassFacts(String className, boolean filelessOrigin, boolean trustedProvenance,
               List<String> contracts, List<String> capabilityHits) {
        this(className, filelessOrigin, trustedProvenance, contracts, capabilityHits, false, "");
    }
    ClassFacts(String className, boolean filelessOrigin, boolean trustedProvenance,
               List<String> contracts, List<String> capabilityHits, boolean verifiedGenerated, String provenanceAnomaly) {
        this(className, filelessOrigin, trustedProvenance, contracts, capabilityHits, verifiedGenerated,
             provenanceAnomaly, false, "");
    }
    ClassFacts(String className, boolean filelessOrigin, boolean trustedProvenance,
               List<String> contracts, List<String> capabilityHits, boolean verifiedGenerated,
               String provenanceAnomaly, boolean outOfContract, String declaredRepos) {
        this.className=className; this.filelessOrigin=filelessOrigin; this.trustedProvenance=trustedProvenance;
        this.contracts=contracts; this.capabilityHits=capabilityHits;
        this.verifiedGenerated=verifiedGenerated; this.provenanceAnomaly=provenanceAnomaly == null ? "" : provenanceAnomaly;
        this.outOfContract=outOfContract;
        this.declaredRepos=declaredRepos == null ? "" : declaredRepos;
    }
}

final class Facts {
    // Non-final: configure() replaces these at startup when mem-contracts.json is present.
    static String[] STRING_NEEDLES = {
        "cmd.exe", "/bin/sh", "/bin/bash",
        "e45e329feb5d925b",     // Behinder AES key = MD5("rebeyond")[:16]
        "3c6e0b8a9c15224a",     // Godzilla key     = MD5("key")[:16]
        "X-Accel-Buffering"     // Suo5 tunnel: the header that stops nginx buffering its stream
    };
    static String[] TYPE_NEEDLES = {
        "java/lang/Runtime", "java/lang/ProcessBuilder",
        "javax/crypto/Cipher",
        "java/lang/ClassLoader",            // defineClass / custom classloader (Godzilla EvilClassLoader)
        "java/lang/reflect/Method",         // Method.invoke — reflection-based command dispatch (Godzilla)
        "javax/crypto/spec/SecretKeySpec",  // AES key setup — Behinder/Godzilla encrypted C2 channel
    };

    // Called once at startup by Probe.run() after loading mem-contracts.json.
    static void configure(String[] typeNeedles, String[] stringNeedles) {
        if (typeNeedles != null && typeNeedles.length > 0)   TYPE_NEEDLES   = typeNeedles;
        if (stringNeedles != null && stringNeedles.length > 0) STRING_NEEDLES = stringNeedles;
    }

    /**
     * Add any STRING_NEEDLE that appears as a string literal in the class's constant pool.
     *
     * <p>Parses the pool directly rather than going through ASM, so it does not depend on which
     * visitor callback a given generator's bytecode happens to trigger. Only CONSTANT_String
     * entries are considered -- not every CONSTANT_Utf8 -- so class names, field names and method
     * descriptors cannot produce a hit.
     *
     * <p>Malformed input is swallowed: this is a best-effort enrichment, and a class we cannot
     * parse still gets everything the ASM path finds.
     */
    static void scanConstantPoolStrings(byte[] b, List<String> hits) {
        try {
            if (b == null || b.length < 10) return;
            int count = ((b[8] & 0xFF) << 8) | (b[9] & 0xFF);
            String[] utf8 = new String[count];
            int[] stringRefs = new int[count];
            int nStr = 0;
            int i = 10;
            for (int idx = 1; idx < count && i < b.length; idx++) {
                int tag = b[i] & 0xFF;
                switch (tag) {
                    case 1: { // CONSTANT_Utf8
                        int len = ((b[i + 1] & 0xFF) << 8) | (b[i + 2] & 0xFF);
                        utf8[idx] = new String(b, i + 3, len, java.nio.charset.StandardCharsets.UTF_8);
                        i += 3 + len;
                        break;
                    }
                    case 8:   // CONSTANT_String -> index of its Utf8
                        stringRefs[nStr++] = ((b[i + 1] & 0xFF) << 8) | (b[i + 2] & 0xFF);
                        i += 3;
                        break;
                    case 7: case 16: case 19: case 20: i += 3; break;  // Class/MethodType/Module/Package
                    case 15: i += 4; break;                            // MethodHandle
                    case 5: case 6: i += 9; idx++; break;              // Long/Double take two slots
                    default: i += 5; break;                            // Fieldref/Methodref/NameAndType/...
                }
            }
            for (int s = 0; s < nStr; s++) {
                int ref = stringRefs[s];
                if (ref <= 0 || ref >= count) continue;
                String lit = utf8[ref];
                if (lit == null) continue;
                for (String n : STRING_NEEDLES)
                    if (lit.contains(n) && !hits.contains(n)) hits.add(n);
            }
        } catch (Throwable ignored) {
            // best effort -- the ASM path still runs
        }
    }

    static ClassFacts build(RecoveredClass rc) {
        AgentFacts af = rc.facts;
        List<String> contracts = new ArrayList<>(af.interfaces);
        if (af.superName != null && !af.superName.isEmpty()) contracts.add(af.superName);
        contracts.addAll(af.superchain);
        List<String> hits = scanBytecode(rc.bytes);
        // Add provenance-anomaly as a capability signal so the discriminator can score it.
        if (af.provenanceAnomaly != null && !af.provenanceAnomaly.isEmpty())
            hits.add("provenance-anomaly");
        boolean trusted = isTrustedLoader(af.loader) || isFileJar(af.codesource);
        return new ClassFacts(rc.name, af.fileless(), trusted, contracts, hits, af.verifiedGenerated,
                              af.provenanceAnomaly, af.outOfContract, af.declaredRepos);
    }

    // Package-private for unit testing via DiscriminatorTests.
    static List<String> scanBytecode(byte[] bytes) {
        List<String> hits = new ArrayList<>();
        // Constant-pool scan FIRST, and it is the authoritative one for string needles.
        //
        // WHY: matching strings only via visitLdcInsn silently missed every family-key marker.
        // Measured 2026-08-31 across 92 real memshells -- the Behinder and Godzilla default keys
        // are present as genuine CONSTANT_String entries and configured as needles, yet produced
        // zero hits, which left family attribution at 0/92. Reading the pool finds a literal
        // however the generator chose to reference it.
        scanConstantPoolStrings(bytes, hits);
        try {
            ClassReader cr = new ClassReader(bytes);
            cr.accept(new ClassVisitor(Opcodes.ASM9) {
                @Override
                public MethodVisitor visitMethod(int access, String name, String descriptor,
                        String signature, String[] exceptions) {
                    return new MethodVisitor(Opcodes.ASM9) {
                        @Override public void visitLdcInsn(Object value) {
                            // Kept as defence in depth. The authoritative string match is the
                            // constant-pool scan below -- see scanConstantPoolStrings.
                            if (value instanceof String) {
                                String s = (String) value;
                                for (String n : STRING_NEEDLES)
                                    if (s.contains(n) && !hits.contains(n)) hits.add(n);
                            }
                        }
                        @Override public void visitMethodInsn(int opcode, String owner,
                                String mname, String desc, boolean iface) {
                            for (String n : TYPE_NEEDLES)
                                if (owner.equals(n) && !hits.contains(n)) hits.add(n);
                        }
                        @Override public void visitTypeInsn(int opcode, String type) {
                            for (String n : TYPE_NEEDLES)
                                if (type.equals(n) && !hits.contains(n)) hits.add(n);
                        }
                        @Override public void visitFieldInsn(int opcode, String owner,
                                String fname, String desc) {
                            for (String n : TYPE_NEEDLES)
                                if (owner.equals(n) && !hits.contains(n)) hits.add(n);
                        }
                    };
                }
            }, ClassReader.SKIP_FRAMES);
        } catch (Exception ignored) {
            // Malformed bytecode: fall back to raw string search for resilience.
            String text = new String(bytes, StandardCharsets.ISO_8859_1);
            for (String n : STRING_NEEDLES) if (text.contains(n) && !hits.contains(n)) hits.add(n);
            for (String n : TYPE_NEEDLES)   if (text.contains(n) && !hits.contains(n)) hits.add(n);
        }
        return hits;
    }

    static boolean isTrustedLoader(String loader) {
        return loader == null || loader.isEmpty() || "null".equals(loader)
            || loader.contains("PlatformClassLoader") || loader.contains("BootClassLoader");
    }
    static boolean isFileJar(String cs) {
        return cs != null && !"null".equals(cs) && cs.startsWith("file:") && cs.endsWith(".jar");
    }
}
