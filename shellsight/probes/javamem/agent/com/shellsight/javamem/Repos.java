package com.shellsight.javamem;

import java.io.File;
import java.net.URI;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

/**
 * The set of repositories the container itself DECLARES that a class may legitimately come from.
 *
 * <p>WHY THIS EXISTS. A class can be resident, backed by a real file, wired into nothing, and still
 * be a shell -- CISA AR25-261A reconstructed {@code /tmp/web-install.jar} by appending base64 chunks
 * over successive HTTP GETs and loaded its listener from there. Every check ShellSight had asked
 * "does a file back this class?", and the answer was yes, so the class was never even captured.
 * Nobody in the surveyed field asks the other question: <b>is that file somewhere a class may
 * legitimately come from?</b>
 *
 * <p>WHY THIS IS A CONTRACT, NOT A BLOCKLIST. Tomcat documents its own repositories -- WEB-INF/classes
 * and WEB-INF/lib for a webapp, {@code $CATALINA_BASE/lib} and {@code $CATALINA_HOME/lib} for the
 * common loader. So a class from {@code /tmp} is not "in a suspicious directory", it is outside every
 * repository the container documents. That distinction is the whole value: there is no list of bad
 * directories to maintain, and choosing {@code /dev/shm} or a user's home instead does not help.
 * Evidence and citations: docs/measurements/2026-08-30-memshell-detection-landscape/04-codesource-contract.md
 *
 * <p>FALL OPEN, NEVER CLOSED. If the declared set cannot be established, {@link #outOfContract}
 * answers false for everything and this signal contributes nothing. A detector that fires when it
 * cannot tell is a detector that fires on every unfamiliar deployment; the red-team lesson already
 * paid for in this codebase is <i>authenticate, fall open, use structure not names</i>.
 *
 * <p>DELIBERATELY ABSENT: {@code java.io.tmpdir}. Some frameworks extract a WAR there, which is the
 * one false positive this design predicts and does not prevent. It is handled by TIER instead --
 * out-of-contract alone is `suspicious`, and only out-of-contract plus an action-grade capability
 * reaches the alert tier -- because admitting tmpdir here would readmit exactly the location the
 * technique uses.
 */
final class Repos {

    /** Normalised absolute path prefixes. */
    private final List<String> prefixes = new ArrayList<>();
    /** False when nothing could be established -- see FALL OPEN above. */
    private boolean known;
    /**
     * True once an APPLICATION-SCOPED repository has been declared, as opposed to a platform one.
     *
     * <p>WHY THIS IS SEPARATE FROM {@link #known}, measured 2026-09-02. {@code known} was set by any
     * prefix at all, and {@link #discover} always adds {@code java.home} -- which every JVM on earth
     * has. So the check armed itself on every deployment, including ones where it had learned nothing
     * about where the *application's* code lives. On a stock Solr the entire declared set was
     * {@code java.home} plus Jetty's bootstrap {@code start.jar}, and the check then reported 42 of
     * the container's own framework classes as out of contract at alert tier.
     *
     * <p>{@code java.home} and a bootstrap classpath entry are facts about the platform. They say
     * nothing about the application, so they must not license an accusation ABOUT the application.
     * catalina.* is application-scoped because it names a servlet container's own tree; loader URLs
     * and docBases are application-scoped by construction.
     *
     * <p>This is the same principle this project applies in the other direction -- "coverage n/a is
     * not a clean result" -- inverted: an unestablished repository set is not evidence of malice. A
     * detector that converts its own blindness into findings is not being conservative.
     */
    private boolean appScoped;

    private Repos() { }

    /**
     * Build the declared set from the JVM's own configuration.
     *
     * <p>Everything here is a declaration made by whoever started the JVM, not a guess by us:
     * <ul>
     *   <li>{@code catalina.base} / {@code catalina.home} -- one subtree test covers {@code lib/},
     *       {@code bin/}, {@code work/} (compiled JSPs) and {@code webapps/<app>/WEB-INF/lib}.
     *   <li>{@code java.class.path} entries -- covers Spring Boot fat jars and operator additions.
     *   <li>{@code java.home} -- JDK-supplied code.
     *   <li>{@code -javaagent:} / {@code -agentpath:} paths -- APM and profiling agents load from
     *       {@code /opt/...} legitimately all day, and omitting these would false-flag every one.
     * </ul>
     */
    static Repos discover() {
        Repos r = new Repos();
        // catalina.* names a servlet container's own tree, so it is application-scoped: its presence
        // means we recognise this deployment. java.home is not -- every JVM has one.
        if (r.addProp("catalina.base")) r.appScoped = true;
        if (r.addProp("catalina.home")) r.appScoped = true;
        r.addProp("java.home");
        // The classpath is NOT treated as application-scoped on its own. An embedded container
        // (Spring Boot) has no catalina.* properties, but its application repositories are reached
        // through its own loader instead -- see DispatchWalk.WEBAPP_LOADERS, which now recognises
        // LaunchedClassLoader. Counting a bare bootstrap classpath here is what let a Jetty
        // deployment arm this check with two platform paths and accuse everything else.
        String cp = getProp("java.class.path");
        if (cp != null) {
            for (String e : cp.split(java.util.regex.Pattern.quote(File.pathSeparator))) r.add(e);
        }
        r.addAgentPaths();
        r.known = !r.prefixes.isEmpty();
        return r;
    }

    /**
     * Add a live webapp's real path. Tomcat permits {@code <Context docBase="/opt/myapp">} outside
     * CATALINA_BASE, so without this an ordinary externally-deployed application would be reported
     * as out of contract for every one of its classes.
     */
    void addDocBase(String path) {
        // Both callers are application-scoped by construction: DispatchWalk.declaredUrls (a
        // recognised container loader stating its own repositories) and DispatchWalk.docBases (a
        // live webapp's real path). Either one means we have learned where this application's code
        // actually lives, which is what licenses the comparison below.
        if (add(path)) {
            known = true;
            appScoped = true;
        }
    }

    /**
     * Is this CodeSource path outside every declared repository?
     *
     * <p>False for an empty path: a class with no CodeSource at all is `diskAbsent`, which the
     * existing fileless invariant already covers, and answering true here would double-report it.
     */
    boolean outOfContract(String codeSourcePath) {
        // appScoped, not just known: see the field's comment. Without it, java.home alone armed this
        // on every JVM and the check accused the container's own framework classes.
        if (!known || !appScoped || codeSourcePath == null || codeSourcePath.isEmpty()) return false;
        String p = normalise(codeSourcePath);
        if (p == null) return false;
        for (String pref : prefixes) {
            if (contains(pref, p)) return false;
        }
        return true;
    }

    /** Rendered for the evidence string, so a report can say what the class was measured against. */
    String describe() {
        if (!known) return "declared repository set could not be established";
        if (!appScoped) {
            // Say WHICH way it failed. "2 declared repositories" read as a real measurement when it
            // was only java.home and a bootstrap jar, which is how the Solr false positives came to
            // look authoritative in the report.
            return "only platform repositories could be established (" + prefixes.size()
                 + "); no application-scoped repository was declared, so this signal is withheld";
        }
        return prefixes.size() + " declared repositor(ies)";
    }

    // ---------------------------------------------------------------- internals

    private static String getProp(String k) {
        try {
            String v = System.getProperty(k);
            return (v == null || v.isEmpty()) ? null : v;
        } catch (Throwable t) { return null; }
    }

    private boolean addProp(String k) { return add(getProp(k)); }

    private void addAgentPaths() {
        List<String> args;
        try {
            args = java.lang.management.ManagementFactory.getRuntimeMXBean().getInputArguments();
        } catch (Throwable t) {
            return; // java.management absent or restricted -- one source short, not fatal
        }
        if (args == null) return;
        for (String a : args) {
            if (a == null) continue;
            String v = null;
            if (a.startsWith("-javaagent:")) v = a.substring("-javaagent:".length());
            else if (a.startsWith("-agentpath:")) v = a.substring("-agentpath:".length());
            if (v == null) continue;
            int eq = v.indexOf('=');           // -javaagent:/path/a.jar=options
            if (eq >= 0) v = v.substring(0, eq);
            add(v);
        }
    }

    private boolean add(String raw) {
        String p = normalise(raw);
        if (p == null) return false;
        if (!prefixes.contains(p)) prefixes.add(p);
        return true;
    }

    /**
     * Reduce anything that names a location to a comparable absolute path, or null.
     *
     * <p>Accepts a bare path or a {@code file:} URL, because a CodeSource location is a URL while a
     * system property is a path, and both feed this. A {@code jar:} or {@code jrt:} URL normalises to
     * null and therefore never contributes and is never judged -- nested archives are already handled
     * as `Unverifiable` upstream.
     */
    static String normalise(String raw) {
        if (raw == null) return null;
        String s = raw.trim();
        if (s.isEmpty()) return null;
        try {
            // Reject any URL scheme other than file:, BEFORE trying to read it as a path.
            //
            // This is the difference between working and a mass false positive on the commonest
            // Linux Java deployment. A Spring Boot nested CodeSource is
            // `jar:file:/app/app.jar!/BOOT-INF/lib/x.jar` -- it has no "://", so an earlier version
            // fell through to Paths.get(), which happily produced a RELATIVE path, resolved it
            // against the working directory, and reported every nested class as out of contract.
            //
            // A scheme is a colon at index > 1: index 1 is a Windows drive letter (C:\...), which is
            // a path and must survive.
            int colon = s.indexOf(':');
            if (colon > 1 && !s.startsWith("file:")) return null;
            if (s.startsWith("file:")) {
                s = Paths.get(URI.create(s)).toString();
            }
            Path p = Paths.get(s);
            return p.toAbsolutePath().normalize().toString();
        } catch (Throwable t) {
            return null;
        }
    }

    /**
     * Path containment, separator-aware.
     *
     * <p>A plain {@code startsWith} would put {@code /tmpfoo/evil.jar} inside {@code /tmp} and
     * silently exempt it -- which is a bypass, not a cosmetic bug.
     */
    static boolean contains(String prefix, String path) {
        if (prefix == null || path == null) return false;
        if (path.equals(prefix)) return true;
        String p = prefix.endsWith(File.separator) ? prefix : prefix + File.separator;
        return path.startsWith(p);
    }
}
