package com.shellsight.javamem;

import java.io.IOException;
import java.nio.file.*;
import java.util.*;

final class AgentFacts {
    String name = "", loader = "null", codesource = "null", superName = "";
    final List<String> interfaces = new ArrayList<>();
    final List<String> superchain = new ArrayList<>();
    boolean verifiedGenerated = false;
    String provenanceAnomaly = ""; // "bytecode-mismatch:<fqcn>..." or "no-source:<fqcn>" or ""
    /** Real file, but outside every repository the container declares. See agent-side Repos. */
    boolean outOfContract = false;
    String declaredRepos = "";
    boolean fileless() { return codesource == null || "null".equals(codesource); }
}
final class RecoveredClass {
    final String name; final byte[] bytes; final AgentFacts facts;
    RecoveredClass(String name, byte[] bytes, AgentFacts facts) { this.name=name; this.bytes=bytes; this.facts=facts; }
}
final class Extract {
    static boolean looksLikeClass(byte[] b) {
        return b != null && b.length > 8 && (b[0]&0xFF)==0xCA && (b[1]&0xFF)==0xFE && (b[2]&0xFF)==0xBA && (b[3]&0xFF)==0xBE;
    }
    static List<RecoveredClass> readHandoff(Path dir) throws IOException {
        List<RecoveredClass> out = new ArrayList<>();
        int n = Integer.parseInt(Files.readString(dir.resolve("DONE")).trim());
        for (int i = 0; i < n; i++) {
            Path cls = dir.resolve(i + ".class"), fct = dir.resolve(i + ".facts");
            if (!Files.exists(cls) || !Files.exists(fct)) continue;
            AgentFacts f = parseFacts(Files.readAllLines(fct));
            out.add(new RecoveredClass(f.name, Files.readAllBytes(cls), f));
        }
        return out;
    }
    // Parse the agent's reachability inventory (one wired element per TSV line). Best-effort: an
    // absent or garbled file yields an empty list (the probe then relies on the enumeration path).
    static List<WiredElement> readReachability(Path dir) {
        List<WiredElement> out = new ArrayList<>();
        Path f = dir.resolve("reachability.tsv");
        if (!Files.exists(f)) return out;
        try {
            for (String ln : Files.readAllLines(f)) {
                String[] p = ln.split("\t", 7);
                if (p.length < 7) continue;
                out.add(new WiredElement(p[0], p[1], "1".equals(p[2]), "1".equals(p[3]), "1".equals(p[4]), p[5], p[6]));
            }
        } catch (IOException e) { /* best-effort */ }
        return out;
    }
    private static AgentFacts parseFacts(List<String> lines) {
        AgentFacts f = new AgentFacts();
        for (String ln : lines) {
            int t = ln.indexOf('\t'); if (t < 0) continue;
            String k = ln.substring(0,t), v = ln.substring(t+1);
            switch (k) {
                case "name": f.name = v; break;  case "loader": f.loader = v; break;
                case "codesource": f.codesource = v; break;  case "super": f.superName = v; break;
                case "iface": f.interfaces.add(v); break;  case "superchain": f.superchain.add(v); break;
                case "verified_generated": f.verifiedGenerated = "true".equals(v); break;
                case "provenance_anomaly": f.provenanceAnomaly = v; break;
                case "out_of_contract": f.outOfContract = "true".equals(v); break;
                case "declared_repos": f.declaredRepos = v; break;
            }
        }
        return f;
    }
}
