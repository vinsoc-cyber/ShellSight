package com.shellsight.javamem;

// WiredElement is one row of the agent's reachability inventory (parsed from reachability.tsv): a
// class found wired into the live request-dispatch path, with provenance facts the agent computed on
// the LIVE Class using identity + actual-source reads — NOT from forgeable strings. (Red-team v2
// E6/E7: the CodeSource-location and loader-toString strings are attacker-controllable; the decision
// must not depend on them.)
final class WiredElement {
    final String hook;               // "filter" | "valve" | "servlet" | "listener"
    final String className;
    final boolean sourcePresent;     // readFromCodeSource(c) != null — the class is genuinely backed by
                                     // an on-disk/nested origin. false = fileless OR CodeSource-spoofed.
    final boolean verifiedGenerated; // JVM-authentic generated (Proxy/lambda/CGLIB/JSP/Groovy)
    final boolean trustedLoader;     // defining loader IS bootstrap/platform — by IDENTITY, not toString()
    final String loader;             // evidence only (never used for the decision)
    final String codeSource;         // evidence only (never used for the decision)

    WiredElement(String hook, String className, boolean sourcePresent, boolean verifiedGenerated,
                 boolean trustedLoader, String loader, String codeSource) {
        this.hook = hook; this.className = className; this.sourcePresent = sourcePresent;
        this.verifiedGenerated = verifiedGenerated; this.trustedLoader = trustedLoader;
        this.loader = loader; this.codeSource = codeSource;
    }
}

// Reachability decides whether a wired element is a memshell. Type-agnostic: a class actively wired
// into the live request path with NO genuine origin (fileless OR CodeSource-spoofed → !sourcePresent),
// that is not a JVM-authentic generated class and not bootstrap/platform-loaded, is an implant. All
// three inputs are agent-computed on the live Class via identity + actual-source reads, so the
// forgeable-string spoofs the red-team found (E6 CodeSource-location, E7 loader-toString) no longer
// apply — a class claiming a real jar it doesn't actually live in reads !sourcePresent and is flagged.
final class Reachability {
    private Reachability() {}

    static boolean isReachableMemshell(WiredElement w) {
        return !w.trustedLoader && !w.verifiedGenerated && !w.sourcePresent;
    }
}
