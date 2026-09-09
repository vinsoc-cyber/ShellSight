package com.shellsight.javamem;

import com.sun.tools.attach.*;
import java.io.IOException;
import java.nio.file.*;
import java.util.*;
import java.util.stream.Collectors;

final class AcquireTarget {
    final long pid; final String name;
    AcquireTarget(long pid, String name) { this.pid=pid; this.name=name; }
    String label() { return "pid:" + pid + "(" + name + ")"; }
}
class AcquireException extends Exception { AcquireException(String m, Throwable c) { super(m, c); } }

// Collected bundles what one attach pass recovers: captured classes + the reachability inventory.
final class Collected {
    final List<RecoveredClass> classes;
    final List<WiredElement> reachability;
    /**
     * The agent's own coverage statement: non-empty when it stopped early, empty when it swept
     * everything it intended to.
     *
     * <p>This was missing, and its absence was a reporting hole rather than a cosmetic gap. The
     * agent has always written "incomplete: &lt;reason&gt;" into errors.log when it exhausts its
     * capture budget, and it still writes DONE afterwards -- so the probe read the handoff, produced
     * whatever findings the partial sweep happened to yield, and reported them as a complete scan.
     * On a JVM holding a real memshell that the sweep never reached, that is a clean bill of health
     * for a compromised host.
     */
    final String incomplete;
    Collected(List<RecoveredClass> classes, List<WiredElement> reachability) {
        this(classes, reachability, "");
    }
    Collected(List<RecoveredClass> classes, List<WiredElement> reachability, String incomplete) {
        this.classes = classes; this.reachability = reachability;
        this.incomplete = incomplete == null ? "" : incomplete;
    }
}

final class Acquire {
    static List<RecoveredClass> attachAndCollect(long pid, Path agentJar) throws AcquireException {
        return attachAndCollect(pid, agentJar, java.util.Collections.emptyList(), java.util.Collections.emptyList()).classes;
    }

    static Collected attachAndCollect(long pid, Path agentJar,
            List<String> pipelineContracts, List<String> retransformWatchlist) throws AcquireException {
        Path handoff;
        try { handoff = Files.createTempDirectory("javamem-" + pid + "-"); }
        catch (IOException e) { throw new AcquireException("temp dir: " + e.getMessage(), e); }

        // Write contracts + watchlist to a temp config file so we never hit the ~945-char
        // Windows VirtualMachine.loadAgent args-string limit regardless of list length.
        // Agent args format: "<handoff_path>|<config_file_path>" (two short paths only).
        Path configFile;
        try {
            configFile = Files.createTempFile("javamem-cfg-" + pid + "-", ".txt");
            writeAgentConfig(configFile, pipelineContracts, retransformWatchlist);
        } catch (IOException e) { throw new AcquireException("config file: " + e.getMessage(), e); }

        String agentArgs = handoff.toString() + "|" + configFile.toString();
        VirtualMachine vm = null;
        try {
            vm = VirtualMachine.attach(String.valueOf(pid));
            vm.loadAgent(agentJar.toString(), agentArgs); // agentmain runs synchronously
        } catch (AttachNotSupportedException | IOException | AgentLoadException | AgentInitializationException e) {
            throw new AcquireException(classify(e), e);
        } finally { if (vm != null) try { vm.detach(); } catch (IOException ignore) {} }
        for (int i = 0; i < 100 && !Files.exists(handoff.resolve("DONE")); i++) sleep(50);
        if (!Files.exists(handoff.resolve("DONE"))) throw new AcquireException("agent did not signal DONE (pid " + pid + ")", null);
        try {
            return new Collected(Extract.readHandoff(handoff), Extract.readReachability(handoff),
                                 readIncomplete(handoff));
        }
        catch (IOException e) { throw new AcquireException("read handoff: " + e.getMessage(), e); }
    }

    /**
     * Read the agent's "incomplete: &lt;reason&gt;" line out of errors.log, or "" when the sweep
     * finished.
     *
     * <p>Best-effort by design: an unreadable errors.log must not fail a scan that otherwise
     * succeeded. It does mean a missing file reads as "complete", which is the same direction the
     * probe already errs in and is why the agent writes the line at all rather than leaving the
     * reader to infer truncation from a short class list.
     */
    static String readIncomplete(Path handoff) {
        try {
            for (String line : Files.readAllLines(handoff.resolve("errors.log"))) {
                String t = line.trim();
                if (t.startsWith("incomplete: ")) return t.substring("incomplete: ".length());
            }
        } catch (Exception ignore) { }
        return "";
    }

    /**
     * Write a simple line-oriented config file that the agent reads at agentmain.
     * Format (no JSON dependency required in the agent):
     *   WATCHLIST\n<entry>\n<entry>\n...\nCONTRACTS\n<entry>\n...
     * Section headers are literal sentinel tokens; entries are one per line, trimmed, no blanks.
     */
    static void writeAgentConfig(Path dest, List<String> contracts, List<String> watchlist) throws IOException {
        StringBuilder sb = new StringBuilder();
        sb.append("WATCHLIST\n");
        if (watchlist != null) for (String s : watchlist) { String t = s.trim(); if (!t.isEmpty()) sb.append(t).append('\n'); }
        sb.append("CONTRACTS\n");
        if (contracts != null) for (String s : contracts) { String t = s.trim(); if (!t.isEmpty()) sb.append(t).append('\n'); }
        Files.writeString(dest, sb.toString());
    }
    static List<AcquireTarget> resolve(TargetSpec spec, boolean[] explicit) {
        if (spec.pids != null && spec.pids.length > 0) {
            explicit[0] = true;
            return Arrays.stream(spec.pids).mapToObj(p -> new AcquireTarget(p, "pid"+p)).collect(Collectors.toList());
        }
        explicit[0] = false; return discoverJvms();
    }
    static List<AcquireTarget> discoverJvms() {
        long self = ProcessHandle.current().pid();
        List<AcquireTarget> out = new ArrayList<>();
        for (VirtualMachineDescriptor d : VirtualMachine.list()) {
            String disp = d.displayName() == null ? "" : d.displayName();
            boolean web = disp.contains("catalina")||disp.contains("org.apache.catalina")||disp.contains("bootstrap.jar")||disp.contains("spring")||disp.contains("tomcat");
            long pid; try { pid = Long.parseLong(d.id()); } catch (NumberFormatException e) { continue; }
            if (web && pid != self) out.add(new AcquireTarget(pid, "java"));
        }
        return out;
    }
    private static String classify(Exception e) {
        String m = String.valueOf(e.getMessage());
        if (e instanceof AttachNotSupportedException) return "attach not supported (not a HotSpot JVM / different user or version): " + m;
        if (m != null && (m.contains("Access is denied") || m.contains("access denied"))) return "access denied (run as same-or-higher privilege than the target JVM)";
        return e.getClass().getSimpleName() + ": " + m;
    }
    private static void sleep(long ms) { try { Thread.sleep(ms); } catch (InterruptedException ignore) {} }
}
