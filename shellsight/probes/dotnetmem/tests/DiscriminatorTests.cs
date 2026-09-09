using System.Runtime.InteropServices;
using ShellSight.DotnetMem;
using Xunit;

public class DiscriminatorTests
{
    private static ModuleFacts MakeFacts(
        string name, string? pkt = null, string[]? contracts = null, string[]? apis = null, string[]? strs = null,
        bool conventionMw = false, string? publicKeyHex = null, bool strongNameValid = false, string[]? attributeTypes = null,
        string[]? typeFullNames = null)
        => new ModuleFacts(name, pkt, pkt != null, typeFullNames ?? Array.Empty<string>(),
                           contracts ?? Array.Empty<string>(), apis ?? Array.Empty<string>(), strs ?? Array.Empty<string>(),
                           conventionMw, publicKeyHex, strongNameValid, attributeTypes ?? Array.Empty<string>());

    // The authentic anchors a REAL runtime-compiled Razor view carries (captured from a live ASP.NET
    // Core build via the probe's --explain): the Razor compiler emits [RazorCompiledItem], a type in
    // the AspNetCoreGeneratedDocument namespace, and a RazorPage base. NONE of these is the assembly
    // NAME — that is Path.GetRandomFileName() at runtime, so an assembly-name check both misses real
    // views (FP) and is trivially forgeable (#9-dotnet).
    private static readonly string[] RazorAttrs = { "Microsoft.AspNetCore.Razor.Hosting.RazorCompiledItemAttribute" };
    private static readonly string[] RazorTypes = { "AspNetCoreGeneratedDocument.Views_Home_Index" };
    private static readonly string[] RazorBase = { "Microsoft.AspNetCore.Mvc.Razor.RazorPage`1" };

    // NOTE: mutates Discriminator.FrameworkPublicKeySet (static state). Call at the start of each
    // test that needs frameworkVerified=true; tests that don't call this run with the empty default set.
    // Configure Discriminator with the actual public key of System.Core.dll (the ECMA/b77a key).
    // Returns the public key hex that was configured.
    private static string ConfigureWithSystemCoreKey()
    {
        string dll = Path.Combine(RuntimeEnvironment.GetRuntimeDirectory(), "System.Core.dll");
        var f = Facts.Parse(File.ReadAllBytes(dll));
        string key = f.PublicKeyHex ?? throw new Exception("System.Core.dll has no public key");
        Discriminator.Configure(null, null, new[] { key });
        return key;
    }

    [Fact] // pipeline implant => likely-malicious
    public void HttpHandlerImplantIsLikelyMalicious()
    {
        var a = Discriminator.Assess(MakeFacts("MemoryShell", contracts: new[] { "System.Web.IHttpHandler" },
                                           apis: new[] { "System.Diagnostics.Process.Start" }, strs: new[] { "cmd.exe" }));
        Assert.Equal(AssessTier.LikelyMalicious, a.Tier);
        Assert.False(a.Allowlisted);
        Assert.Contains(a.Signals, s => s.StartsWith("pipeline:"));
        Assert.True(a.Score >= 90);
    }

    [Fact] // genuine framework assembly: verified strong-name → suppressed even if path-less
    public void FrameworkSignedAssemblyIsAllowlisted()
    {
        string key = ConfigureWithSystemCoreKey();
        // Parse a real framework DLL to get facts with StrongNameValid=true
        string dll = Path.Combine(RuntimeEnvironment.GetRuntimeDirectory(), "System.Core.dll");
        var f = Facts.Parse(File.ReadAllBytes(dll));
        var a = Discriminator.Assess(f);
        Assert.Equal(AssessTier.Clean, a.Tier);
        Assert.True(a.Allowlisted);
        Assert.Contains(a.Signals, s => s.StartsWith("framework-verified:"));
    }

    [Fact] // FP fix: a REAL Razor view (random assembly name + RazorCompiledItem + AspNetCoreGeneratedDocument type + RazorPage base) is suppressed
    public void AuthenticRazorViewIsAllowlisted()
    {
        // "kx3l0v2p.q1a" mimics Path.GetRandomFileName() — does NOT contain any known generated NAME.
        var a = Discriminator.Assess(MakeFacts("kx3l0v2p.q1a",
            contracts: RazorBase, attributeTypes: RazorAttrs, typeFullNames: RazorTypes));
        Assert.True(a.Allowlisted);
        Assert.Equal(AssessTier.Clean, a.Tier);
    }

    [Fact] // authentic sgen/XmlSerializer assembly (.XmlSerializers name + generated structure) is suppressed
    public void AuthenticXmlSerializersIsAllowlisted()
    {
        var a = Discriminator.Assess(MakeFacts("MyTypes.XmlSerializers",
            typeFullNames: new[] { "Microsoft.Xml.Serialization.GeneratedAssembly.XmlSerializerContract" }));
        Assert.True(a.Allowlisted);
        Assert.Equal(AssessTier.Clean, a.Tier);
    }

    [Fact] // #9-dotnet: a forged generated NAME with NO authentic structure is NOT suppressed (free pass removed)
    public void ForgedGeneratedNameWithoutStructureIsNotAllowlisted()
    {
        foreach (string forged in new[] { "AspNetCoreGeneratedDocument.Evil", "App_Web_evil", "<evil",
                                          "Anonymously Hosted DynamicMethods Assembly", "x.XmlSerializers", "Microsoft.GeneratedCode" })
        {
            var a = Discriminator.Assess(MakeFacts(forged)); // name only — no attributes, no generated types, no generator base
            Assert.False(a.Allowlisted, $"forged name '{forged}' must not be allowlisted on name alone");
            Assert.NotEqual(AssessTier.Clean, a.Tier);
        }
    }

    [Fact] // the RazorCompiledItem attribute ALONE (forgeable metadata) without a generated type/base is insufficient
    public void RazorAttributeAloneWithoutStructureIsNotAllowlisted()
    {
        var a = Discriminator.Assess(MakeFacts("whatever", attributeTypes: RazorAttrs)); // attr but no AspNetCoreGeneratedDocument type / RazorPage base
        Assert.False(a.Allowlisted);
    }

    [Fact] // a forged framework NAME but NO valid token + a pipeline implant must NOT be suppressed
    public void ForgedNameWithImplantIsNotAllowlisted()
    {
        var a = Discriminator.Assess(MakeFacts("System.Web", contracts: new[] { "System.Web.IHttpModule" }));
        Assert.Equal(AssessTier.LikelyMalicious, a.Tier);
        Assert.False(a.Allowlisted);
    }

    [Fact] // path-less, unexplained, no signal => suspicious (worth an analyst's eyes, not auto-malicious)
    public void UnexplainedFilelessModuleIsSuspicious()
    {
        var a = Discriminator.Assess(MakeFacts("Newtonsoft.Json.Dynamic"));
        Assert.Equal(AssessTier.Suspicious, a.Tier);
        Assert.False(a.Allowlisted);
    }

    [Fact] // Facts.Parse reads name + public-key-token from a real framework DLL (validates PKT computation)
    public void ParseReadsAssemblyNameAndToken()
    {
#if NETFRAMEWORK
        // System.Text.Json isn't in the .NET Framework runtime dir; System.Core is, and is strong-named
        // with the well-known ECMA public-key token — same validation of Facts.Parse name + PKT.
        string dll = Path.Combine(RuntimeEnvironment.GetRuntimeDirectory(), "System.Core.dll");
        var facts = Facts.Parse(File.ReadAllBytes(dll));
        Assert.Equal("System.Core", facts.AssemblyName);
        Assert.Equal("b77a5c561934e089", facts.PublicKeyTokenHex);
#else
        string dll = Path.Combine(RuntimeEnvironment.GetRuntimeDirectory(), "System.Text.Json.dll");
        var facts = Facts.Parse(File.ReadAllBytes(dll));
        Assert.Equal("System.Text.Json", facts.AssemblyName);
        Assert.Equal("cc7b13ffcd2ddd51", facts.PublicKeyTokenHex);
#endif
        Assert.True(facts.IsStrongNamed);
    }

    [Fact] // convention middleware: InvokeAsync(HttpContext), no interface → pipeline → likely-malicious
    public void ConventionMiddlewareByMethodShapeIsLikelyMalicious()
    {
        var a = Discriminator.Assess(MakeFacts("MwShell", conventionMw: true));
        Assert.Equal(AssessTier.LikelyMalicious, a.Tier);
        Assert.Contains(a.Signals, s => s.StartsWith("pipeline:") && s.Contains("convention-middleware"));
    }

    [Fact] // FP fix: AUTHENTIC Razor structure WINS over the convention-middleware shape (no escalation)
    public void AuthenticRazorWithConventionShapeIsAllowlisted()
    {
        var a = Discriminator.Assess(MakeFacts("kx3l0v2p.q1a", conventionMw: true,
            contracts: RazorBase, attributeTypes: RazorAttrs, typeFullNames: RazorTypes));
        Assert.True(a.Allowlisted);
        Assert.Equal(AssessTier.Clean, a.Tier);
    }

    [Fact] // #9-dotnet twin: a forged generated NAME no longer suppresses the convention-middleware escalation
    public void ForgedGeneratedNameWithConventionShapeIsLikelyMalicious()
    {
        var a = Discriminator.Assess(MakeFacts("AspNetCoreGeneratedDocument.Evil", conventionMw: true)); // forged name, no Razor structure
        Assert.Equal(AssessTier.LikelyMalicious, a.Tier);
        Assert.False(a.Allowlisted);
        Assert.Contains(a.Signals, s => s.Contains("convention-middleware"));
    }

    [Fact] // FP fix: a framework-VERIFIED assembly is not escalated by middleware shape.
    public void FrameworkSignedWithConventionShapeIsAllowlisted()
    {
        string key = ConfigureWithSystemCoreKey();
        // System.Core uses the b77a5c561934e089 token — create fake facts that are "verified" for that token+key
        var a = Discriminator.Assess(MakeFacts("System.Core.Whatever", pkt: "b77a5c561934e089",
            publicKeyHex: key, strongNameValid: true, conventionMw: true));
        Assert.True(a.Allowlisted);
        Assert.Equal(AssessTier.Clean, a.Tier);
    }

    [Fact] // Facts.Parse extracts StrongNameValid=true and a non-null PublicKeyHex from a genuine framework DLL
    public void ParseExtractsStrongNameValidAndPublicKeyHex()
    {
#if NETFRAMEWORK
        string dll = Path.Combine(RuntimeEnvironment.GetRuntimeDirectory(), "System.Core.dll");
#else
        string dll = Path.Combine(RuntimeEnvironment.GetRuntimeDirectory(), "System.Text.Json.dll");
#endif
        var facts = Facts.Parse(File.ReadAllBytes(dll));
        Assert.True(facts.StrongNameValid, "genuine framework assembly should have a valid strong-name signature");
        Assert.NotNull(facts.PublicKeyHex);
        Assert.True(facts.PublicKeyHex!.Length > 0, "public key hex should be non-empty");
    }

    [Fact] // Facts.Parse resolves a GENERIC base type to its generic type name (TypeSpec decode)
    public void ParseResolvesGenericBaseTypeName()
    {
        // GenericDerived : List<int>  → contracts must include the generic type name (contains "List")
        var facts = Facts.Parse(File.ReadAllBytes(typeof(DiscriminatorTests).Assembly.Location));
        Assert.Contains(facts.Contracts, c => c.Contains("List"));
    }

    [Fact] // Facts.Parse extracts assembly- and type-level custom-attribute type names (the anchor for the authentic-generated check)
    public void ParseExtractsAttributeTypes()
    {
#if NETFRAMEWORK
        string dll = Path.Combine(RuntimeEnvironment.GetRuntimeDirectory(), "System.Core.dll");
#else
        string dll = Path.Combine(RuntimeEnvironment.GetRuntimeDirectory(), "System.Text.Json.dll");
#endif
        var facts = Facts.Parse(File.ReadAllBytes(dll));
        Assert.NotEmpty(facts.AttributeTypes);
        Assert.Contains(facts.AttributeTypes, a => a.EndsWith("Attribute", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("System.Web.Hosting.VirtualPathProvider")]
    [InlineData("Microsoft.AspNetCore.Routing.IRouter")]
    [InlineData("Microsoft.AspNetCore.Routing.IEndpointRouteBuilder")]
    public void NewPipelineContractIsDetected(string contract)
    {
        var a = Discriminator.Assess(MakeFacts("EvilShell", contracts: new[] { contract }));
        Assert.Equal(AssessTier.LikelyMalicious, a.Tier);
        Assert.False(a.Allowlisted);
        Assert.Contains(a.Signals, s => s.StartsWith("pipeline:"));
    }

    [Theory]
    [InlineData("System.Web.HttpApplication")]           // Global.asax — most common IIS injection point
    [InlineData("Microsoft.AspNetCore.Hosting.IStartupFilter")] // startup-time injection
    [InlineData("Microsoft.Owin.IOwinMiddleware")]        // OWIN legacy IIS
    [InlineData("Microsoft.AspNetCore.Mvc.RazorPages.PageModel")] // Razor Pages backend
    public void ExtendedPipelineContractIsDetected(string contract)
    {
        var a = Discriminator.Assess(MakeFacts("EvilShell2", contracts: new[] { contract }));
        Assert.Equal(AssessTier.LikelyMalicious, a.Tier);
        Assert.False(a.Allowlisted);
        Assert.Contains(a.Signals, s => s.StartsWith("pipeline:"));
    }

    [Theory]
    [InlineData(new[] { "MethodInfo.Invoke" }, AssessTier.Suspicious)]       // single capability → suspicious
    [InlineData(new[] { "MethodInfo.Invoke", "File.WriteAllBytes" }, AssessTier.LikelyMalicious)] // two → likely
    [InlineData(new[] { "WebClient.DownloadString", "Assembly.Load" }, AssessTier.LikelyMalicious)] // C2+load → likely
    public void NewCapabilityNeedlesEscalateCorrectly(string[] apis, AssessTier expected)
    {
        // Prefix apis with a qualifying namespace so EndsWith match fires.
        var qualified = apis.Select(a => "System." + a).ToArray();
        var assessment = Discriminator.Assess(MakeFacts("ShellNoHook", apis: qualified));
        Assert.Equal(expected, assessment.Tier);
    }

    [Fact] // genuine framework assembly with no pipeline: verified → Clean (FP guard)
    public void GenuineFrameworkNoPipelineIsClean()
    {
        string key = ConfigureWithSystemCoreKey();
        string dll = Path.Combine(RuntimeEnvironment.GetRuntimeDirectory(), "System.Core.dll");
        var f = Facts.Parse(File.ReadAllBytes(dll));
        Assert.Equal(AssessTier.Clean, Discriminator.Assess(f).Tier);
    }

    [Fact] // forged framework PKT (SN verification fails) → no longer suppressed; emits spoofed-strong-name signal
    public void ForgedPktInvalidSigEmitsSpoofSignal()
    {
        // No Configure needed: StrongNameValid=false short-circuits frameworkVerified regardless of key set.
        // pkt matches a framework token BUT StrongNameValid=false (forged PKT, no real signature)
        var f = MakeFacts("EvilAssembly", pkt: "b77a5c561934e089",
            publicKeyHex: null, strongNameValid: false);
        var a = Discriminator.Assess(f);
        Assert.NotEqual(AssessTier.Clean, a.Tier); // free-pass removed
        Assert.Contains(a.Signals, s => s.Contains("spoofed-strong-name"));
    }

    [Fact] // forged PKT + ≥2 capability indicators → likely-malicious (suppression gone, capability escalates)
    public void ForgedPktWithCapabilityIsLikely()
    {
        ConfigureWithSystemCoreKey();
        var f = MakeFacts("EvilAssembly2", pkt: "b77a5c561934e089",
            apis: new[] { "System.Diagnostics.Process.Start", "System.Reflection.Assembly.Load" },
            strongNameValid: false);
        Assert.Equal(AssessTier.LikelyMalicious, Discriminator.Assess(f).Tier);
    }
}

// A type whose BASE is a generic instantiation (TypeSpecification) — exercises generic-base resolution.
public class GenericDerived : System.Collections.Generic.List<int> { }
