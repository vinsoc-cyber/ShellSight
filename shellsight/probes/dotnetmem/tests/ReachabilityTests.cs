using ShellSight.DotnetMem;
using Xunit;

public class ReachabilityTests
{
    // ---- FakeHeap: an in-memory object graph implementing IManagedHeap. ----
    // Each object is an id (ulong address) with a type name, a backing module image base, a set of
    // present field names, named object-field edges, and (for collections) an ordered item list.
    private sealed class FakeHeap : IManagedHeap
    {
        private sealed class Obj
        {
            public ulong Addr; public string Type = ""; public ulong Base;
            public Dictionary<string, ulong> Fields = new();   // fieldName -> target addr (0 = null edge)
            public HashSet<string> Present = new();            // field names that "exist" (HasField)
            public List<ulong> Items = new();                  // collection elements
            public HashSet<string> BaseTypes = new();          // base-type names (subclass matching)
        }
        private readonly Dictionary<ulong, Obj> _objs = new();
        private readonly Dictionary<(string type, string field), ulong> _statics = new();
        private ulong _next = 0x1000;

        public ulong New(string type, ulong backingBase, params string[] presentFields)
        {
            ulong a = _next; _next += 0x1000;
            var o = new Obj { Addr = a, Type = type, Base = backingBase };
            foreach (var f in presentFields) o.Present.Add(f);
            _objs[a] = o; return a;
        }
        public void Field(ulong obj, string field, ulong target) { _objs[obj].Fields[field] = target; _objs[obj].Present.Add(field); }
        public void Item(ulong collection, ulong item) { _objs[collection].Items.Add(item); }
        public void Derives(ulong obj, string baseType) { _objs[obj].BaseTypes.Add(baseType); }
        public void Static(string type, string field, ulong target) => _statics[(type, field)] = target;

        private ClrObjectRef Ref(ulong a) { var o = _objs[a]; return new ClrObjectRef(a, o.Type, o.Base); }

        public ClrObjectRef? ReadStaticObject(string type, string field)
            => _statics.TryGetValue((type, field), out var a) && a != 0 ? Ref(a) : (ClrObjectRef?)null;
        public ClrObjectRef? ReadInstanceObject(ClrObjectRef obj, string field)
            => _objs.TryGetValue(obj.Address, out var o) && o.Fields.TryGetValue(field, out var a) && a != 0 ? Ref(a) : (ClrObjectRef?)null;
        public IEnumerable<ClrObjectRef> InstancesOf(string type)
            => _objs.Values.Where(o => o.Type == type || o.BaseTypes.Contains(type)).Select(o => Ref(o.Addr));
        public IEnumerable<ClrObjectRef> EnumerateItems(ClrObjectRef collection)
            => _objs.TryGetValue(collection.Address, out var o) ? o.Items.Select(Ref) : Enumerable.Empty<ClrObjectRef>();
        public bool HasField(ClrObjectRef obj, string field)
            => _objs.TryGetValue(obj.Address, out var o) && o.Present.Contains(field);
    }

    [Fact] // the abstraction round-trips a static -> instance-field chain
    public void FakeHeap_WalksStaticThenInstanceField()
    {
        var h = new FakeHeap();
        ulong he = h.New("System.Web.Hosting.HostingEnvironment", 0);
        ulong vp = h.New("Evil.Shell", 0xBEEF);
        h.Static("System.Web.Hosting.HostingEnvironment", "_theHostingEnvironment", he);
        h.Field(he, "_virtualPathProvider", vp);

        ClrObjectRef? root = h.ReadStaticObject("System.Web.Hosting.HostingEnvironment", "_theHostingEnvironment");
        Assert.NotNull(root);
        ClrObjectRef? first = h.ReadInstanceObject(root!.Value, "_virtualPathProvider");
        Assert.NotNull(first);
        Assert.Equal("Evil.Shell", first!.Value.TypeName);
        Assert.Equal(0xBEEFUL, first.Value.BackingImageBase);
    }

    [Fact] // the VPP chain walk yields each wired provider with its position
    public void VppWalk_YieldsWiredProvidersInOrder()
    {
        var h = new FakeHeap();
        ulong he = h.New("System.Web.Hosting.HostingEnvironment", 0);
        ulong evil = h.New("Godzilla.VirtualPathProvider", 0xBEEF, "password"); // enrichment field present
        ulong fx = h.New("System.Web.Hosting.MapPathBasedVirtualPathProvider", 0x1000);
        h.Static("System.Web.Hosting.HostingEnvironment", "_theHostingEnvironment", he);
        h.Field(he, "_virtualPathProvider", evil);  // head of chain
        h.Field(evil, "_previous", fx);             // -> framework VP

        var found = Reachability.WalkVpp(h).ToList();

        Assert.Equal(2, found.Count);
        Assert.Equal("vpp", found[0].Chain);
        Assert.Equal(0, found[0].Position);
        Assert.Equal("Godzilla.VirtualPathProvider", found[0].Instance.TypeName);
        Assert.Contains("password", found[0].FieldHits);   // enrichment captured during the walk
        Assert.Equal(1, found[1].Position);
        Assert.Equal("System.Web.Hosting.MapPathBasedVirtualPathProvider", found[1].Instance.TypeName);
        Assert.Empty(found[1].FieldHits);
    }

    [Fact] // graceful degradation: no HostingEnvironment -> empty, no throw
    public void VppWalk_NoHostingEnvironment_ReturnsEmpty()
    {
        Assert.Empty(Reachability.WalkVpp(new FakeHeap()).ToList());
    }

    [Fact] // MVC global filters: GlobalFilters._filters -> items -> each item's .Instance is the filter
    public void FilterWalk_YieldsRegisteredFilterInstances()
    {
        var h = new FakeHeap();
        ulong coll = h.New("System.Web.Mvc.GlobalFilterCollection", 0);
        ulong f0 = h.New("System.Web.Mvc.Filter", 0);
        ulong evil = h.New("Behinder.ActionFilter", 0xCAFE);
        h.Static("System.Web.Mvc.GlobalFilters", "<Filters>k__BackingField", coll);
        h.Item(coll, f0);
        h.Field(f0, "<Instance>k__BackingField", evil);

        var found = Reachability.WalkFilters(h).ToList();
        Assert.Single(found);
        Assert.Equal("filter", found[0].Chain);
        Assert.Equal("Behinder.ActionFilter", found[0].Instance.TypeName);
    }

    [Fact] // routing: RouteTable._instance -> items are the route handlers
    public void RouteWalk_YieldsRouteHandlers()
    {
        var h = new FakeHeap();
        ulong routes = h.New("System.Web.Routing.RouteCollection", 0);
        ulong evil = h.New("Evil.RouteHandler", 0xD00D);
        h.Static("System.Web.Routing.RouteTable", "_instance", routes);
        h.Item(routes, evil);

        var found = Reachability.WalkRoutes(h).ToList();
        Assert.Single(found);
        Assert.Equal("route", found[0].Chain);
        Assert.Equal("Evil.RouteHandler", found[0].Instance.TypeName);
    }

    [Fact] // a stock Route with a RouteHandler edge -> WalkRoutes yields the handler too (spec §6 fix)
    public void RouteWalk_DescendsIntoRouteHandler()
    {
        var h = new FakeHeap();
        ulong routes = h.New("System.Web.Routing.RouteCollection", 0);
        ulong stockRoute = h.New("System.Web.Routing.Route", 0x1000);  // framework, disk-backed
        ulong evilHandler = h.New("Evil.RouteHandler", 0xD00D);        // path-less implant behind it
        h.Static("System.Web.Routing.RouteTable", "_instance", routes);
        h.Item(routes, stockRoute);
        h.Field(stockRoute, "<RouteHandler>k__BackingField", evilHandler);

        var found = Reachability.WalkRoutes(h).ToList();
        Assert.Contains(found, w => w.Instance.TypeName == "Evil.RouteHandler"); // the handler is reached
    }

    [Fact] // HTTP modules: each HttpApplication._moduleCollection -> items are IHttpModule instances
    public void ModuleWalk_YieldsRegisteredModules()
    {
        var h = new FakeHeap();
        ulong app = h.New("System.Web.HttpApplication", 0);
        ulong coll = h.New("System.Web.HttpModuleCollection", 0);
        ulong evil = h.New("Evil.HttpModule", 0xF00D);
        // InstancesOf("System.Web.HttpApplication") finds app; its _moduleCollection holds the modules.
        h.Field(app, "_moduleCollection", coll);
        h.Item(coll, evil);

        var found = Reachability.WalkModules(h).ToList();
        Assert.Single(found);
        Assert.Equal("module", found[0].Chain);
        Assert.Equal("Evil.HttpModule", found[0].Instance.TypeName);
    }

    [Fact] // real apps subclass HttpApplication (Global.asax type) -> the module walk must match subclasses
    public void ModuleWalk_FindsModulesOnHttpApplicationSubclass()
    {
        var h = new FakeHeap();
        ulong app = h.New("MvcLabApp.MvcApplication", 0);
        h.Derives(app, "System.Web.HttpApplication");          // subclass of HttpApplication
        ulong coll = h.New("System.Web.HttpModuleCollection", 0);
        ulong evil = h.New("Evil.HttpModule", 0xF00D);
        h.Field(app, "_moduleCollection", coll);
        h.Item(coll, evil);

        var found = Reachability.WalkModules(h).ToList();
        Assert.Contains(found, w => w.Instance.TypeName == "Evil.HttpModule");
    }

    [Fact] // OWIN (Katana) middleware: InstancesOf(Microsoft.Owin.OwinMiddleware) finds middleware subclasses
    public void OwinWalk_YieldsMiddlewareInstances()
    {
        var h = new FakeHeap();
        ulong evil = h.New("Evil.OwinMiddleware", 0xBEEF, "key");   // derives from OwinMiddleware, has a memshell field
        ulong fx = h.New("Microsoft.Owin.Security.AuthenticationMiddleware", 0x1000);
        h.Derives(evil, "Microsoft.Owin.OwinMiddleware");
        h.Derives(fx, "Microsoft.Owin.OwinMiddleware");

        var found = Reachability.WalkOwin(h).ToList();
        Assert.Equal(2, found.Count);
        Assert.All(found, w => Assert.Equal("owin", w.Chain));
        Assert.Contains(found, w => w.Instance.TypeName == "Evil.OwinMiddleware");
        Assert.Contains(found, w => w.Instance.TypeName == "Evil.OwinMiddleware" && w.FieldHits.Contains("key"));
    }

    [Fact] // no OWIN loaded -> empty, no throw (apps without Microsoft.Owin)
    public void OwinWalk_None_ReturnsEmpty()
    {
        Assert.Empty(Reachability.WalkOwin(new FakeHeap()).ToList());
    }

    [Fact] // convention-OWIN: WalkOwin finds non-OwinMiddleware types when given their type names
    public void OwinWalk_ConventionTypes_FindsNonSubclassInstances()
    {
        var h = new FakeHeap();
        ulong conv = h.New("Evil.ConventionMiddleware", 0xBEEF);
        h.Derives(conv, "System.Object"); // does NOT derive from OwinMiddleware
        var convTypes = new[] { "Evil.ConventionMiddleware" };

        var found = Reachability.WalkOwin(h, convTypes).ToList();
        Assert.Single(found);
        Assert.Equal("owin", found[0].Chain);
        Assert.Equal("Evil.ConventionMiddleware", found[0].Instance.TypeName);
    }

    [Fact] // all four chains combined, de-duplicated by instance address
    public void WalkAll_CombinesChains()
    {
        var h = new FakeHeap();
        ulong he = h.New("System.Web.Hosting.HostingEnvironment", 0);
        ulong vp = h.New("Evil.Vpp", 0x11);
        h.Static("System.Web.Hosting.HostingEnvironment", "_theHostingEnvironment", he);
        h.Field(he, "_virtualPathProvider", vp);

        var all = Reachability.WalkAll(h).ToList();
        Assert.Single(all);          // only the VPP chain populated
        Assert.Equal("vpp", all[0].Chain);
    }

    private static WiredComponent Wc(string type = "Evil.Vpp", string chain = "vpp", int pos = 0, params string[] fieldHits)
        => new WiredComponent(chain, pos, new ClrObjectRef(0x500, type, 0xBEEF), fieldHits);

    private static Assessment Backing(AssessTier tier, int score, bool allowlisted, params string[] signals)
        => new Assessment(tier, score, allowlisted, signals, "evid");

    [Fact] // wired + path-less backing, no capability -> likely(85); wired IS the corroboration
    public void Decide_WiredNonCleanBacking_IsLikely85()
    {
        var v = Reachability.Decide(Wc(), Backing(AssessTier.Suspicious, 50, false, "fileless-unexplained"));
        Assert.False(v.Suppressed);
        Assert.Equal(AssessTier.LikelyMalicious, v.Tier);
        Assert.Equal(85, v.Score);
        Assert.Contains(v.Signals, s => s == "reachable:vpp@0");
    }

    [Fact] // wired + Clean (framework-verified / authentic-generated) backing -> suppressed (FP safety)
    public void Decide_WiredCleanBacking_IsSuppressed()
    {
        var v = Reachability.Decide(Wc("System.Web.Hosting.MapPathBasedVirtualPathProvider"),
                                    Backing(AssessTier.Clean, 0, true, "framework-verified:b03f5f7f11d50a3a"));
        Assert.True(v.Suppressed);
    }

    [Fact] // capability signal on the backing module -> 95
    public void Decide_WiredWithBackingCapability_Is95()
    {
        var v = Reachability.Decide(Wc(), Backing(AssessTier.LikelyMalicious, 95, false, "pipeline:System.Web.IHttpModule", "api:Process.Start"));
        Assert.Equal(95, v.Score);
    }

    [Fact] // enrichment field present on the instance -> 95 even without backing capability
    public void Decide_WiredWithFieldHit_Is95()
    {
        var v = Reachability.Decide(Wc("Godzilla.Vpp", "vpp", 0, "password"), Backing(AssessTier.Suspicious, 50, false, "fileless-unexplained"));
        Assert.Equal(95, v.Score);
        Assert.Contains(v.Signals, s => s == "field:password");
    }

    [Fact] // unresolved backing module (null) -> suspicious(55), not suppressed
    public void Decide_UnresolvedBacking_IsSuspicious55()
    {
        var v = Reachability.Decide(Wc(), null);
        Assert.False(v.Suppressed);
        Assert.Equal(AssessTier.Suspicious, v.Tier);
        Assert.Equal(55, v.Score);
    }

    private static Finding ModuleFinding(string imageBase, string id = "m1")
        => new Finding { Id = id, View = "dotnet-mem", Tier = "suspicious", Score = 50,
                         Detection = new Detection { Basis = "structural-heuristic" },
                         Artifact = new Artifact { Identity = "Mod" },
                         Context = new Dictionary<string, string> { ["image_base"] = imageBase } };

    private static Finding ReachFinding(string backingImageBase, string id = "r1")
        => new Finding { Id = id, View = "dotnet-mem", Tier = "likely-malicious", Score = 85,
                         Detection = new Detection { Basis = "reachability-dispatch" },
                         Artifact = new Artifact { Identity = "Mod" },
                         Context = new Dictionary<string, string> { ["backing_image_base"] = backingImageBase } };

    [Fact] // same image base in both axes -> one finding, reachability kept, marked corroborated
    public void Merge_SameImageBase_CorroboratesAndKeepsReachability()
    {
        var merged = Reachability.Merge(new List<Finding> { ModuleFinding("0xBEEF") }, new List<Finding> { ReachFinding("0xBEEF") });
        Assert.Single(merged);
        Assert.Equal("reachability-dispatch", merged[0].Detection.Basis);
        Assert.Equal("module-scan", merged[0].Context!["corroborated_by"]);
    }

    [Fact] // different image bases -> both findings retained
    public void Merge_DifferentImageBase_KeepsBoth()
    {
        var merged = Reachability.Merge(new List<Finding> { ModuleFinding("0xAAA") }, new List<Finding> { ReachFinding("0xBBB") });
        Assert.Equal(2, merged.Count);
    }
}
