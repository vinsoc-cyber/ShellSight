namespace ShellSight.DotnetMem;

// One component found wired into a live dispatch chain: which chain, its position, the instance, and
// any enrichment field-names present on it (capability hints, never the gate — see Decide).
public sealed record WiredComponent(string Chain, int Position, ClrObjectRef Instance, IReadOnlyList<string> FieldHits);

// The System.Web internal field/type names the walks traverse. System.Web is FROZEN (no new .NET
// Framework versions), so these are low version-risk. The names confirmed from yzddmr6's source are
// noted; the rest are verified against the live runtime on the Win11 integration run (Task 8) — if a
// walk returns empty on a known-implanted target, re-check the corresponding name here.
public static class ReachabilityChains
{
    public const string HostingEnvType = "System.Web.Hosting.HostingEnvironment";
    public const string HostingEnvStatic = "_theHostingEnvironment";   // yzddmr6-confirmed
    public const string VppHeadField = "_virtualPathProvider";         // yzddmr6-confirmed
    public const string VppPrevField = "_previous";                    // yzddmr6-confirmed

    public const string FiltersType = "System.Web.Mvc.GlobalFilters";
    public const string FiltersStatic = "<Filters>k__BackingField";   // GlobalFilters.Filters static auto-prop backing field (live-verified via reflection, MVC 5.2.9)
    public const string FilterInstanceField = "<Instance>k__BackingField"; // Filter.Instance auto-prop backing field -> the wired filter obj (live-verified)
    public const string RouteTableType = "System.Web.Routing.RouteTable";
    public const string RoutesStatic = "_instance";                   // RouteCollection
    public const string RouteHandlerField = "<RouteHandler>k__BackingField"; // Route.RouteHandler auto-prop backing field (live-verified)
    public const string HttpAppType = "System.Web.HttpApplication";
    public const string ModuleCollectionField = "_moduleCollection";  // HttpModuleCollection
    public const string OwinMiddlewareType = "Microsoft.Owin.OwinMiddleware";   // Katana OWIN middleware abstract base

    // Enrichment field shapes used by Godzilla/AntSword (yzddmr6-confirmed). Capability hints only.
    public static readonly string[] EnrichFields = { "password", "key", "_fileContent", "_virtualDir" };
}

public static partial class Reachability
{
    // Walk the VirtualPathProvider chain: HostingEnvironment._theHostingEnvironment -> _virtualPathProvider
    // -> follow _previous to the end. Yields each provider in dispatch order (position 0 = head).
    public static IEnumerable<WiredComponent> WalkVpp(IManagedHeap heap)
    {
        ClrObjectRef? he = heap.ReadStaticObject(ReachabilityChains.HostingEnvType, ReachabilityChains.HostingEnvStatic);
        if (he == null) yield break;
        ClrObjectRef? cur = heap.ReadInstanceObject(he.Value, ReachabilityChains.VppHeadField);
        var seen = new HashSet<ulong>();
        int pos = 0;
        while (cur != null && seen.Add(cur.Value.Address))
        {
            yield return new WiredComponent("vpp", pos++, cur.Value, FieldHits(heap, cur.Value));
            cur = heap.ReadInstanceObject(cur.Value, ReachabilityChains.VppPrevField);
        }
    }

    // MVC global filters: GlobalFilters._filters (a GlobalFilterCollection) -> items; each item is a
    // System.Web.Mvc.Filter whose .Instance is the actual filter object (fall back to the item itself
    // if there is no .Instance edge).
    public static IEnumerable<WiredComponent> WalkFilters(IManagedHeap heap)
    {
        ClrObjectRef? coll = heap.ReadStaticObject(ReachabilityChains.FiltersType, ReachabilityChains.FiltersStatic);
        if (coll == null) yield break;
        int pos = 0;
        foreach (ClrObjectRef item in heap.EnumerateItems(coll.Value))
        {
            ClrObjectRef inst = heap.ReadInstanceObject(item, ReachabilityChains.FilterInstanceField) ?? item;
            yield return new WiredComponent("filter", pos++, inst, FieldHits(heap, inst));
        }
    }

    // Routing: RouteTable._instance (a RouteCollection) -> items are the routes. Yields each route item
    // AND, if the route exposes an IRouteHandler, that handler too — a memshell can hide in the handler
    // behind a stock framework Route (disk-backed -> gated), so the handler's backing module must be
    // judged on its own (spec §6). The handler field is the Route.RouteHandler auto-property backing
    // field; verify the name on the live runtime if the handler is not reached.
    public static IEnumerable<WiredComponent> WalkRoutes(IManagedHeap heap)
    {
        ClrObjectRef? routes = heap.ReadStaticObject(ReachabilityChains.RouteTableType, ReachabilityChains.RoutesStatic);
        if (routes == null) yield break;
        int pos = 0;
        foreach (ClrObjectRef item in heap.EnumerateItems(routes.Value))
        {
            yield return new WiredComponent("route", pos, item, FieldHits(heap, item));
            ClrObjectRef? handler = heap.ReadInstanceObject(item, ReachabilityChains.RouteHandlerField);
            if (handler != null) yield return new WiredComponent("route", pos, handler.Value, FieldHits(heap, handler.Value));
            pos++;
        }
    }

    // HTTP modules: every HttpApplication instance has a _moduleCollection (HttpModuleCollection) whose
    // items are the registered IHttpModule instances.
    public static IEnumerable<WiredComponent> WalkModules(IManagedHeap heap)
    {
        int pos = 0;
        foreach (ClrObjectRef app in heap.InstancesOf(ReachabilityChains.HttpAppType))
        {
            ClrObjectRef? coll = heap.ReadInstanceObject(app, ReachabilityChains.ModuleCollectionField);
            if (coll == null) continue;
            foreach (ClrObjectRef item in heap.EnumerateItems(coll.Value))
                yield return new WiredComponent("module", pos++, item, FieldHits(heap, item));
        }
    }

    // OWIN (Katana) middleware: every middleware derives from the Microsoft.Owin.OwinMiddleware abstract
    // base. InstancesOf is subclass-aware, so this finds all live middleware instances (the pipeline links
    // them via each instance's Next field, but every instance is reachable here regardless of linkage).
    // Convention-based middleware (Invoke method, no base class) is NOT reached here — that is caught by
    // the module-scan axis when fileless; disk-backed convention middleware remains a residual gap.
    public static IEnumerable<WiredComponent> WalkOwin(IManagedHeap heap, IEnumerable<string>? conventionTypes = null)
    {
        int pos = 0;
        foreach (ClrObjectRef m in heap.InstancesOf(ReachabilityChains.OwinMiddlewareType))
            yield return new WiredComponent("owin", pos++, m, FieldHits(heap, m));
        // Convention-based OWIN middleware: types that declare Invoke/InvokeAsync(IOwinContext) but DON'T
        // derive from OwinMiddleware. These type names are collected by a pre-pass that scans webroot-dropped
        // modules for the ConventionMiddleware flag (Facts.DeclaresInvoke). InstancesOf them as wired components.
        if (conventionTypes != null)
            foreach (string tn in conventionTypes)
                foreach (ClrObjectRef m in heap.InstancesOf(tn))
                    yield return new WiredComponent("owin", pos++, m, FieldHits(heap, m));
    }

    // All five chains, de-duplicated by instance address (a single object reachable via two chains is
    // reported once, by the first chain that reaches it). conventionOwinTypes: type names collected by a
    // pre-pass for convention-based OWIN middleware (Invoke/IOwinContext, no OwinMiddleware base).
    public static IEnumerable<WiredComponent> WalkAll(IManagedHeap heap, IEnumerable<string>? conventionOwinTypes = null)
    {
        var seen = new HashSet<ulong>();
        foreach (var wc in WalkVpp(heap).Concat(WalkFilters(heap)).Concat(WalkRoutes(heap)).Concat(WalkModules(heap)).Concat(WalkOwin(heap, conventionOwinTypes)))
            if (seen.Add(wc.Instance.Address)) yield return wc;
    }

    // Enrichment field-names present on the instance (capability hints; see Decide for how they're used).
    internal static List<string> FieldHits(IManagedHeap heap, ClrObjectRef obj)
    {
        var hits = new List<string>();
        foreach (string f in ReachabilityChains.EnrichFields)
            if (heap.HasField(obj, f)) hits.Add(f);
        return hits;
    }
}

// The reachability decision for one wired component. Suppressed == the backing module is benign
// (framework-verified / authentic-generated), so being wired is expected and no finding is emitted.
public sealed record ReachabilityVerdict(bool Suppressed, AssessTier Tier, int Score, IReadOnlyList<string> Signals, string Evidence);

public static partial class Reachability
{
    // Gate + tiering. `backing` is the Assessment of the wired component's backing CLR module
    // (Discriminator.Assess), or null if the module could not be resolved/carved.
    //   backing == null            -> suspicious(55) (wired component, unresolvable backing — anomalous)
    //   backing.Allowlisted/Clean  -> suppressed (framework/authentic VP/filter/route — FP safety)
    //   otherwise                  -> likely; 95 if capability present (field hit OR backing api:/str:), else 85
    public static ReachabilityVerdict Decide(WiredComponent wc, Assessment? backing)
    {
        var sig = new List<string> { $"reachable:{wc.Chain}@{wc.Position}" };
        foreach (string f in wc.FieldHits) sig.Add("field:" + f);

        if (backing == null)
            return new ReachabilityVerdict(false, AssessTier.Suspicious, 55, sig,
                $"component wired into the {wc.Chain} chain (position {wc.Position}) with an unresolvable backing module; warrants analyst review");

        if (backing.Allowlisted || backing.Tier == AssessTier.Clean)
            return new ReachabilityVerdict(true, AssessTier.Clean, 0, sig, "wired component backed by a benign (framework-verified / authentic-generated) module");

        sig.AddRange(backing.Signals);
        bool capability = wc.FieldHits.Count > 0
            || backing.Signals.Any(s => s.StartsWith("api:", StringComparison.Ordinal) || s.StartsWith("str:", StringComparison.Ordinal));
        int score = capability ? 95 : 85;
        return new ReachabilityVerdict(false, AssessTier.LikelyMalicious, score, sig,
            $"component '{wc.Instance.TypeName}' is wired into the live {wc.Chain} chain (position {wc.Position}); "
            + "its backing CLR module is path-less and not framework-verified"
            + (capability ? "; carries capability indicators" : ""));
    }
}

public static partial class Reachability
{
    // Merge the module-first findings with the reachability findings, de-duplicating by backing-module
    // image base. When the same module appears in both axes, the reachability finding (which carries the
    // stronger "actually wired" evidence) is kept and annotated corroborated_by=module-scan; the
    // module-first duplicate is dropped. Non-overlapping findings from both axes are all retained.
    public static List<Finding> Merge(List<Finding> moduleFirst, List<Finding> reachability)
    {
        var reachBases = new HashSet<string>();
        foreach (Finding r in reachability)
            if (r.Context != null && r.Context.TryGetValue("backing_image_base", out string? b) && !string.IsNullOrEmpty(b))
                reachBases.Add(b);

        var result = new List<Finding>();
        foreach (Finding m in moduleFirst)
        {
            string? ib = m.Context != null && m.Context.TryGetValue("image_base", out string? v) ? v : null;
            if (ib != null && reachBases.Contains(ib)) continue; // dropped — superseded by the reachability finding
            result.Add(m);
        }
        var moduleBases = new HashSet<string>(moduleFirst
            .Where(m => m.Context != null && m.Context.ContainsKey("image_base"))
            .Select(m => m.Context!["image_base"]));
        foreach (Finding r in reachability)
        {
            if (r.Context != null && r.Context.TryGetValue("backing_image_base", out string? b) && b != null && moduleBases.Contains(b))
            {
                r.Context["corroborated_by"] = "module-scan";
                r.Detection.Evidence += "; corroborated: reached AND carved fileless by the module scan";
            }
            result.Add(r);
        }
        return result;
    }
}
