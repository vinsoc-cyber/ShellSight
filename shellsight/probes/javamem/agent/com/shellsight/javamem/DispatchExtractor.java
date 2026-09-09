package com.shellsight.javamem;

import java.lang.reflect.*;
import java.util.*;

// DispatchExtractor pulls the live wired elements out of a Tomcat StandardContext-like object using
// reflection BY NAME (duck-typing): it works across Tomcat 8-10 (stable field/method names) and is
// unit-testable with a stand-in object exposing the same names — no Tomcat on the classpath. Returns
// (instance, hook) pairs; the caller resolves each instance's class + provenance. Best-effort: every
// reflective step is guarded, a missing member contributes nothing rather than throwing.
final class DispatchExtractor {
    private DispatchExtractor() {}

    static final class Wired {
        final Object instance; final String hook;
        Wired(Object instance, String hook) { this.instance = instance; this.hook = hook; }
    }

    static List<Wired> fromContext(Object context) {
        List<Wired> out = new ArrayList<>();
        if (context == null) return out;
        // filters: field filterConfigs (Map) -> value.getFilter()
        Object fcs = getField(context, "filterConfigs");
        if (fcs instanceof Map) {
            for (Object cfg : ((Map<?, ?>) fcs).values()) {
                Object filter = invoke(cfg, "getFilter");
                if (filter != null) out.add(new Wired(filter, "filter"));
            }
        }
        // valves: getPipeline().getValves(), recursing up parent containers (Context->Host->Engine)
        addValves(out, context, 0);
        // servlets: findChildren() -> Wrapper -> getServlet()
        Object children = invoke(context, "findChildren");
        if (children instanceof Object[]) {
            for (Object child : (Object[]) children) {
                Object servlet = invoke(child, "getServlet");
                if (servlet != null) out.add(new Wired(servlet, "servlet"));
            }
        }
        // listeners: applicationEventListenersList / applicationLifecycleListenersList
        addListeners(out, getField(context, "applicationEventListenersList"));
        addListeners(out, getField(context, "applicationLifecycleListenersList"));
        return out;
    }

    private static void addValves(List<Wired> out, Object container, int depth) {
        if (container == null || depth > 8) return; // depth cap: defensive against any cyclic getParent
        Object valves = invoke(invoke(container, "getPipeline"), "getValves");
        if (valves instanceof Object[]) {
            for (Object v : (Object[]) valves) if (v != null) out.add(new Wired(v, "valve"));
        }
        addValves(out, invoke(container, "getParent"), depth + 1);
    }

    private static void addListeners(List<Wired> out, Object listeners) {
        Iterable<?> it = null;
        if (listeners instanceof Object[]) it = Arrays.asList((Object[]) listeners);
        else if (listeners instanceof Iterable) it = (Iterable<?>) listeners;
        if (it == null) return;
        for (Object l : it) if (l != null) out.add(new Wired(l, "listener"));
    }

    private static Object getField(Object o, String name) {
        if (o == null) return null;
        for (Class<?> c = o.getClass(); c != null; c = c.getSuperclass()) {
            try { Field f = c.getDeclaredField(name); f.setAccessible(true); return f.get(o); }
            catch (NoSuchFieldException e) { /* walk up */ }
            catch (Throwable t) { return null; }
        }
        return null;
    }

    private static Object invoke(Object o, String method) {
        if (o == null) return null;
        for (Class<?> c = o.getClass(); c != null; c = c.getSuperclass()) {
            try { Method m = c.getDeclaredMethod(method); m.setAccessible(true); return m.invoke(o); }
            catch (NoSuchMethodException e) { /* walk up */ }
            catch (Throwable t) { return null; }
        }
        return null;
    }
}
