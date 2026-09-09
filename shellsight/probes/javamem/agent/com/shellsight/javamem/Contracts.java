package com.shellsight.javamem;

import java.util.*;

/**
 * The request-pipeline contract set, inside the agent.
 *
 * <p>NOTE: keep this list identical to Discriminator.PIPELINE_CONTRACTS. The agent jar and the
 * probe jar are separate artifacts with separate classpaths, so the set cannot simply be shared.
 * ContractParityTests asserts the two have not drifted -- if they do, the agent captures a class
 * the verdict layer then declines to treat as pipeline-wired, which is a miss with no error
 * anywhere.
 */
final class Contracts {
    private static Set<String> PIPELINE = new HashSet<>(Arrays.asList(
        "javax.servlet.Filter","javax.servlet.Servlet","javax.servlet.http.HttpServlet",
        "javax.servlet.ServletRequestListener","javax.servlet.http.HttpSessionListener",
        "javax.servlet.ServletContextListener",
        "jakarta.servlet.Filter","jakarta.servlet.Servlet","jakarta.servlet.http.HttpServlet",
        "jakarta.servlet.ServletRequestListener","jakarta.servlet.http.HttpSessionListener",
        "jakarta.servlet.ServletContextListener",
        "org.apache.catalina.Valve","org.apache.catalina.valves.ValveBase","org.apache.catalina.Container",
        "org.apache.catalina.LifecycleListener",
        "org.apache.coyote.Adapter",
        "org.springframework.web.servlet.HandlerInterceptor",
        "org.springframework.web.servlet.handler.HandlerInterceptorAdapter",
        "org.springframework.web.servlet.mvc.Controller",
        "org.springframework.web.filter.OncePerRequestFilter",
        "com.opensymphony.xwork2.interceptor.Interceptor",
        "org.apache.struts2.interceptor.AbstractInterceptor",
        "org.eclipse.jetty.server.Handler",
        "org.eclipse.jetty.server.handler.AbstractHandler",
        "io.undertow.server.HttpHandler",
        "javax.websocket.Endpoint","jakarta.websocket.Endpoint",
        "javax.websocket.server.ServerEndpointConfig",
        "java.lang.instrument.ClassFileTransformer"
    ));

    /** Replace the set from mem-contracts.json at agent init. */
    static void configure(Collection<String> contracts) {
        if (contracts != null && !contracts.isEmpty())
            PIPELINE = Collections.unmodifiableSet(new HashSet<>(contracts));
    }

    static boolean isPipeline(String typeName) { return PIPELINE.contains(typeName); }
    static Set<String> all() { return Collections.unmodifiableSet(PIPELINE); }

    private Contracts() {}
}
