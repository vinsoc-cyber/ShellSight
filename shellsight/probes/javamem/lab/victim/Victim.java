package lab;

import java.io.IOException;
import java.net.URL;
import java.nio.file.*;
import java.security.CodeSource;
import java.security.PermissionCollection;
import java.security.Permissions;
import java.security.ProtectionDomain;
import java.security.cert.Certificate;

public class Victim {
    public static void main(String[] args) throws Exception {
        // Dispatch on first arg: --spoof, --apm, or positional (legacy fileless mode).
        if (args.length >= 4 && "--spoof".equals(args[0])) {
            runSpoof(args[1], args[2], args[3]);
        } else if (args.length >= 4 && "--apm".equals(args[0])) {
            runApm(args[1], args[2], args[3]);
        } else {
            runFileless(args[0], args[1]);
        }
    }

    // -------------------------------------------------------------------------
    // Original mode: define class with null CodeSource (fileless residency).
    // args: <class-file> <fqcn>
    // -------------------------------------------------------------------------
    private static void runFileless(String classFilePath, String fqcn) throws Exception {
        Path classFile = Paths.get(classFilePath);
        byte[] bytes = Files.readAllBytes(classFile);
        ClassLoader loader = new ClassLoader(Victim.class.getClassLoader()) {
            protected Class<?> findClass(String name) throws ClassNotFoundException {
                if (name.equals(fqcn)) return defineClass(name, bytes, 0, bytes.length);
                throw new ClassNotFoundException(name);
            }
        };
        Class<?> held = Class.forName(fqcn, true, loader);
        try { Files.delete(classFile); } catch (IOException ignore) {}   // fileless residency
        waitForStop(classFile.toAbsolutePath().getParent(), held.getName());
    }

    // -------------------------------------------------------------------------
    // Spoof mode: define class with a ProtectionDomain whose CodeSource points
    // at a BENIGN jar — simulating the defineClass(...contextClass) CodeSource-
    // spoof that advanced memshells use.
    //
    // args: --spoof <class-file> <fqcn> <benign-jar-path>
    //
    // The class file is deleted after loading (fileless residency).  The class
    // implements a pipeline contract, so the agent captures it via the pipeline
    // path.  The agent then opens the benign jar and looks for the class entry
    // — it is NOT there → NO_SOURCE → provenance_anomaly fires.
    // Combined with pipeline → Discriminator → LIKELY_MALICIOUS (score=92).
    // -------------------------------------------------------------------------
    private static void runSpoof(String classFilePath, String fqcn, String benignJarPath) throws Exception {
        Path classFile = Paths.get(classFilePath);
        byte[] bytes = Files.readAllBytes(classFile);

        // Build a CodeSource pointing at the benign jar.
        URL jarUrl = Paths.get(benignJarPath).toUri().toURL();
        CodeSource spoofedCs = new CodeSource(jarUrl, (Certificate[]) null);
        PermissionCollection perms = new Permissions();
        ProtectionDomain spoofedPd = new ProtectionDomain(spoofedCs, perms);

        ClassLoader loader = new ClassLoader(Victim.class.getClassLoader()) {
            protected Class<?> findClass(String name) throws ClassNotFoundException {
                if (name.equals(fqcn))
                    return defineClass(name, bytes, 0, bytes.length, spoofedPd);
                throw new ClassNotFoundException(name);
            }
        };
        Class<?> held = Class.forName(fqcn, true, loader);
        try { Files.delete(classFile); } catch (IOException ignore) {}   // fileless residency
        waitForStop(classFile.toAbsolutePath().getParent(), held.getName());
    }

    // -------------------------------------------------------------------------
    // APM mode: simulate a legitimate APM/profiler that retransforms a class
    // (adding timing instrumentation) so the in-memory bytecode differs from
    // the original jar copy.
    //
    // args: --apm <patched-class-file> <fqcn> <apm-jar-path>
    //
    // The apm.jar contains the original (clean) bytes for the class.
    // The patched-class-file contains APM-instrumented bytes (different from
    // the jar copy — adds a static APM_INSTRUMENTED_AT constant).
    //
    // The class is defined with the apm.jar's CodeSource (valid, real jar), but
    // with the patched bytecode.  When the agent runs:
    //   - CodeSource is non-null → tries readFromCodeSource → opens apm.jar
    //     → finds the class entry → reads ORIGINAL bytes
    //   - Compares to captured (patched) in-memory bytes → MISMATCH
    //   - provenance_anomaly = "bytecode-mismatch: ..."
    //   - No pipeline contract, no exec/crypto capability
    //   - Discriminator → SUSPICIOUS (score=65) — NOT malicious.
    // -------------------------------------------------------------------------
    private static void runApm(String patchedClassFilePath, String fqcn, String apmJarPath) throws Exception {
        Path patchedClassFile = Paths.get(patchedClassFilePath);
        byte[] patchedBytes = Files.readAllBytes(patchedClassFile);

        // Build a CodeSource pointing at the apm.jar (which holds the ORIGINAL class).
        URL jarUrl = Paths.get(apmJarPath).toUri().toURL();
        CodeSource apmCs = new CodeSource(jarUrl, (Certificate[]) null);
        PermissionCollection perms = new Permissions();
        ProtectionDomain apmPd = new ProtectionDomain(apmCs, perms);

        // Define the class with the PATCHED bytecode but the JAR's ProtectionDomain.
        // This replicates what a Java agent's ClassFileTransformer does: the JVM loads
        // the class from the jar (original bytes on disk), the transformer intercepts
        // and returns modified bytes, and the final in-memory class has CodeSource = jar
        // but bytecode ≠ jar contents.
        ClassLoader loader = new ClassLoader(Victim.class.getClassLoader()) {
            protected Class<?> findClass(String name) throws ClassNotFoundException {
                if (name.equals(fqcn))
                    return defineClass(name, patchedBytes, 0, patchedBytes.length, apmPd);
                throw new ClassNotFoundException(name);
            }
        };
        Class<?> held = Class.forName(fqcn, true, loader);
        // Do NOT delete the class file — it is not loaded from disk in real APM usage;
        // keeping it allows the harness to clean up the work directory normally.
        waitForStop(patchedClassFile.toAbsolutePath().getParent(), held.getName());
    }

    // -------------------------------------------------------------------------
    // Shared wait loop: write victim_status.txt, wait for STOP sentinel.
    // -------------------------------------------------------------------------
    private static void waitForStop(Path base, String loadedName) throws Exception {
        long pid = ProcessHandle.current().pid();
        Files.writeString(base.resolve("victim_status.txt"), "pid=" + pid + " loaded=" + loadedName);
        System.out.println("[victim] pid=" + pid + " loaded=" + loadedName);
        Path stop = base.resolve("STOP");
        long deadline = System.currentTimeMillis() + 600_000;
        while (!Files.exists(stop) && System.currentTimeMillis() < deadline) Thread.sleep(300);
    }
}
