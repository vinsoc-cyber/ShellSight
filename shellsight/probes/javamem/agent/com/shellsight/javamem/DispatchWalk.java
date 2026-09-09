package com.shellsight.javamem;

import java.lang.reflect.*;
import java.util.*;

// DispatchWalk locates live Tomcat StandardContext(s) from the loaded classes' loaders, extracts the
// wired elements (DispatchExtractor), and produces the reachability inventory: one TSV line per wired
// element with its class + provenance facts computed on the live Class. Tomcat-specific + best-effort
// — failure yields an empty inventory and the probe falls back to the enumeration path (no
// regression). Runs in the agent jar (no Gson available -> hand-rolled TSV).
final class DispatchWalk {
    private DispatchWalk() {}

    // TSV row: hook \t className \t fileless(0/1) \t verifiedGenerated(0/1) \t loader \t codeSource
    static List<String> inventory(Class<?>[] loadedClasses) {
        List<String> lines = new ArrayList<>();
        Set<Object> seen = Collections.newSetFromMap(new IdentityHashMap<>());
        for (Object ctx : findContexts(loadedClasses)) {
            for (DispatchExtractor.Wired w : DispatchExtractor.fromContext(ctx)) {
                if (w.instance == null || !seen.add(w.instance)) continue;
                lines.add(row(w.hook, w.instance.getClass()));
            }
        }
        return lines;
    }

    /**
     * The real path of every live webapp, for {@link Repos}.
     *
     * <p>Reuses findContexts rather than re-deriving the container structure, so "which webapps are
     * live" has exactly one implementation. Best-effort by design: a context that will not yield a
     * real path contributes nothing, which leaves Repos falling open for that path rather than
     * calling an ordinary application out of contract.
     *
     * <p>Tomcat permits {@code <Context docBase="/opt/myapp">} outside CATALINA_BASE, and without
     * this every class of such an application would be reported as out of contract.
     */
    static List<String> docBases(Class<?>[] loadedClasses) {
        List<String> out = new ArrayList<>();
        for (Object ctx : findContexts(loadedClasses)) {
            Object sctx = invoke(ctx, "getServletContext");
            String real = realPath(sctx);
            if (real != null && !real.isEmpty() && !out.contains(real)) out.add(real);
        }
        return out;
    }

    /**
     * The repositories the container's own loaders declare, for {@link Repos}.
     *
     * <p>This is the authoritative source and docBases is the fallback. A Tomcat
     * WebappClassLoaderBase extends URLClassLoader, and its getURLs() is exactly WEB-INF/classes plus
     * every WEB-INF/lib jar -- the container stating its own repositories, with no path convention
     * assumed and no reflection on a ServletContext facade. It is what fixes the measured false
     * positive on an externally-deployed webapp (/opt/extapp), which docBases did not.
     *
     * <p>WALKS UP ONLY, and that is load-bearing. Starting from a webapp loader and following
     * getParent() reaches the common and system loaders -- all legitimate. It never reaches a loader
     * CREATED AT RUNTIME as a child of the webapp loader, which is exactly what a URLClassLoader over
     * /tmp/web-install.jar is. Collecting from arbitrary loaders instead would exempt every class
     * from its own loader's URLs and make the check tautologically true.
     */
    static List<String> declaredUrls(Class<?>[] loadedClasses) {
        List<String> out = new ArrayList<>();
        Set<ClassLoader> seen = Collections.newSetFromMap(new IdentityHashMap<>());
        for (Class<?> c : loadedClasses) {
            ClassLoader cl;
            try { cl = c.getClassLoader(); } catch (Throwable t) { continue; }
            if (cl == null || !isWebappLoader(cl)) continue;
            for (ClassLoader up = cl; up != null && seen.add(up); up = parent(up)) {
                if (!(up instanceof java.net.URLClassLoader)) continue;
                java.net.URL[] urls;
                try { urls = ((java.net.URLClassLoader) up).getURLs(); } catch (Throwable t) { continue; }
                if (urls == null) continue;
                for (java.net.URL u : urls) {
                    if (u == null) continue;
                    String s = u.toString();
                    if (!out.contains(s)) out.add(s);
                }
            }
        }
        return out;
    }

    /** ServletContext.getRealPath("/") reflectively -- the arg-taking case `invoke` cannot cover. */
    private static String realPath(Object servletContext) {
        if (servletContext == null) return null;
        for (Class<?> k = servletContext.getClass(); k != null; k = k.getSuperclass()) {
            try {
                Method m = k.getDeclaredMethod("getRealPath", String.class);
                m.setAccessible(true);
                Object v = m.invoke(servletContext, "/");
                return v == null ? null : v.toString();
            } catch (NoSuchMethodException e) { /* walk up */ }
            catch (Throwable t) { return null; }
        }
        return null;
    }

    private static Set<Object> findContexts(Class<?>[] loadedClasses) {
        Set<Object> contexts = Collections.newSetFromMap(new IdentityHashMap<>());
        Set<ClassLoader> seenLoaders = Collections.newSetFromMap(new IdentityHashMap<>());
        for (Class<?> c : loadedClasses) {
            ClassLoader cl;
            try { cl = c.getClassLoader(); } catch (Throwable t) { continue; }
            for (; cl != null && seenLoaders.add(cl); cl = parent(cl)) {
                if (isWebappLoader(cl)) {
                    Object ctx = invoke(invoke(cl, "getResources"), "getContext");
                    if (ctx != null) contexts.add(ctx);
                }
            }
        }
        return contexts;
    }

    /**
     * The webapp loaders this walk is willing to START from.
     *
     * <p>SPECIFIC CLASS NAMES, NEVER A SHAPE TEST. The comment on {@link #declaredUrls} explains
     * why: accepting "any URLClassLoader" would let a loader created at runtime over
     * {@code /tmp/web-install.jar} contribute its own URLs and declare its own payload legitimate,
     * making the out-of-contract check tautologically true. Extending this list extends the set of
     * recognised starting points; it does not change the direction of travel, which is still up.
     *
     * <p>WHY MORE THAN TOMCAT, measured 2026-09-02. This matched Tomcat alone, and both sources of
     * declared repositories -- {@link #declaredUrls} and {@link #docBases} -- are gated on it. On a
     * stock Solr (Jetty) the walk therefore never started, the declared set fell back to
     * {@code java.home} plus Jetty's bootstrap {@code start.jar}, and 42 of the container's own
     * framework classes were reported at alert tier as coming from outside every declared
     * repository. Full diagnosis and the prior-art review that justifies this change:
     * docs/measurements/2026-09-02-jetty-codesource-fp/.
     *
     * <p>Each name below was verified against that container's official API documentation, and each
     * of these loaders extends {@link java.net.URLClassLoader}, so the existing walk works on them
     * unchanged. WildFly's {@code org.jboss.modules.ModuleClassLoader} is deliberately NOT here: it
     * is not a URLClassLoader, so {@code getURLs()} cannot describe it, and listing it would arm the
     * check with a set it cannot populate. That case is handled by falling open in {@link Repos}.
     */
    private static final String[] WEBAPP_LOADERS = {
        "org.apache.catalina.loader.WebappClassLoaderBase",       // Tomcat, TomEE
        "org.eclipse.jetty.webapp.WebAppClassLoader",             // Jetty 9, 10, 11
        "org.eclipse.jetty.ee9.webapp.WebAppClassLoader",         // Jetty 12, EE9
        "org.eclipse.jetty.ee10.webapp.WebAppClassLoader",        // Jetty 12, EE10
        "org.springframework.boot.loader.LaunchedURLClassLoader", // Spring Boot <= 2.x fat jar
        "org.springframework.boot.loader.launch.LaunchedClassLoader", // Spring Boot 3.x
    };

    private static boolean isWebappLoader(ClassLoader cl) {
        for (Class<?> k = cl.getClass(); k != null; k = k.getSuperclass()) {
            String n = k.getName();
            for (String known : WEBAPP_LOADERS) {
                if (known.equals(n)) return true;
            }
        }
        return false;
    }

    // TSV row: hook \t className \t sourcePresent(0/1) \t verifiedGenerated(0/1) \t trustedLoader(0/1) \t loader \t codeSource
    // The three decision facts are computed on the LIVE Class by identity + actual-source read, NOT from
    // the forgeable CodeSource-location / loader-toString strings (red-team v2 E6/E7). sourcePresent uses
    // readFromCodeSource (null => fileless OR CodeSource-spoofed); trustedLoader compares loader identity.
    private static String row(String hook, Class<?> c) {
        boolean sourcePresent = false;
        try { sourcePresent = ExtractAgent.readFromCodeSource(c) != null; } catch (Throwable ignored) {}
        boolean gen = false;
        try { gen = ExtractAgent.isVerifiedGenerated(c); } catch (Throwable ignored) {}
        ClassLoader cl = null;
        try { cl = c.getClassLoader(); } catch (Throwable ignored) {}
        boolean trusted = cl == null || isPlatformLoader(cl);
        String cs;
        try { cs = ExtractAgent.codeSource(c); } catch (Throwable t) { cs = "null"; }
        return hook + "\t" + c.getName() + "\t" + (sourcePresent ? "1" : "0") + "\t" + (gen ? "1" : "0")
            + "\t" + (trusted ? "1" : "0") + "\t" + clean(String.valueOf(cl)) + "\t" + clean(cs);
    }

    private static boolean isPlatformLoader(ClassLoader cl) {
        try { return cl == ClassLoader.getPlatformClassLoader(); } catch (Throwable t) { return false; }
    }

    private static String clean(String s) {
        return s == null ? "null" : s.replace('\t', ' ').replace('\n', ' ').replace('\r', ' ');
    }

    private static ClassLoader parent(ClassLoader cl) {
        try { return cl.getParent(); } catch (Throwable t) { return null; }
    }

    private static Object invoke(Object o, String method) {
        if (o == null) return null;
        for (Class<?> k = o.getClass(); k != null; k = k.getSuperclass()) {
            try { Method m = k.getDeclaredMethod(method); m.setAccessible(true); return m.invoke(o); }
            catch (NoSuchMethodException e) { /* walk up */ }
            catch (Throwable t) { return null; }
        }
        return null;
    }
}
