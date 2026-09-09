namespace ShellSight.DotnetMem;

public enum AssessTier { Clean, Suspicious, LikelyMalicious }

public sealed record Assessment(AssessTier Tier, int Score, bool Allowlisted, IReadOnlyList<string> Signals, string Evidence);

// Turns module facts into a tier. Path-less-ness got us here; this decides malicious vs benign.
public static class Discriminator
{
    // Provenance heuristic: framework assemblies carry these public-key tokens. NOTE: the token is
    // derived from the (public) key and is NOT strong-name-signature-verified here, so a determined
    // attacker could embed a framework public key to forge it. It still suppresses the
    // overwhelmingly-common benign case, and the pipeline check below does NOT depend on it — so a
    // pipeline implant is escalated regardless of a forged token. Strong-name signature verification
    // is now available via ModuleFacts.StrongNameValid (added in T8/T9); Assess uses it in T10.
    private static readonly HashSet<string> FrameworkTokens = new(StringComparer.OrdinalIgnoreCase)
    {
        "b77a5c561934e089", "b03f5f7f11d50a3a", "31bf3856ad364e35", // mscorlib / System / framework
        "cc7b13ffcd2ddd51", "adb9793829ddae60", "7cec85d7bea7798e", // System.*, ASP.NET Core, System.Web
    };

    // Non-readonly: Configure() replaces these at startup when mem-contracts.json is present.
    private static HashSet<string> PipelineContracts = new(StringComparer.Ordinal)
    {
        // Classic System.Web / IIS pipeline
        "System.Web.IHttpModule", "System.Web.IHttpHandler", "System.Web.IHttpAsyncHandler",
        "System.Web.HttpApplication",                                    // Global.asax subclass — most common IIS injection point
        "System.Web.UI.Page", "System.Web.Mvc.Controller", "System.Web.Http.ApiController",
        "System.Web.Hosting.VirtualPathProvider",
        // ASP.NET Core pipeline
        "Microsoft.AspNetCore.Http.IMiddleware",
        "Microsoft.AspNetCore.Mvc.Controller",
        "Microsoft.AspNetCore.Mvc.Filters.IAsyncActionFilter", "Microsoft.AspNetCore.Mvc.Filters.IActionFilter",
        "Microsoft.AspNetCore.Routing.IRouter", "Microsoft.AspNetCore.Routing.IEndpointRouteBuilder",
        "Microsoft.AspNetCore.Hosting.IStartupFilter",                   // injects middleware before app starts
        "Microsoft.AspNetCore.Mvc.RazorPages.PageModel",                 // Razor Pages backend
        // OWIN (still prevalent in enterprise legacy IIS)
        "Microsoft.Owin.IOwinMiddleware",
    };

    private static string[] CapabilityApis =
    {
        // Execution
        "Process.Start",
        // Reflective load / IL emit
        "Assembly.Load", "DynamicMethod", "Marshal.GetDelegateForFunctionPointer",
        // Decode / crypto
        "Convert.FromBase64String",
        // Reflection-based command dispatch (Godzilla / Behinder avoid Process.Start; use MethodInfo.Invoke)
        "MethodInfo.Invoke",
        // Dropper patterns
        "File.WriteAllBytes", "File.WriteAllText",
        // C2 download patterns
        "WebClient.DownloadString", "WebClient.DownloadData",
        "HttpClient.GetAsync", "HttpClient.PostAsync",
    };

    // Populated from mem-contracts.json "framework_public_keys" via Configure; consumed in Assess (T10).
    private static HashSet<string> FrameworkPublicKeySet = new(StringComparer.OrdinalIgnoreCase);

    // Called once at startup by Program after loading mem-contracts.json.
    public static void Configure(IReadOnlyList<string>? contracts, IReadOnlyList<string>? apis, IReadOnlyList<string>? frameworkPublicKeys = null)
    {
        if (contracts is { Count: > 0 })
            PipelineContracts = new HashSet<string>(contracts, StringComparer.Ordinal);
        if (apis is { Count: > 0 })
            CapabilityApis = apis.ToArray();
        if (frameworkPublicKeys is { Count: > 0 })
            FrameworkPublicKeySet = new HashSet<string>(frameworkPublicKeys, StringComparer.OrdinalIgnoreCase);
    }

    public static Assessment Assess(ModuleFacts f)
    {
        bool claimsFramework = f.PublicKeyTokenHex != null && FrameworkTokens.Contains(f.PublicKeyTokenHex);
        bool frameworkVerified = claimsFramework && f.StrongNameValid
            && f.PublicKeyHex != null && FrameworkPublicKeySet.Contains(f.PublicKeyHex);
        bool spoofed = claimsFramework && !frameworkVerified;
        bool authenticGenerated = IsAuthenticGenerated(f);

        bool hasPipeline = f.Contracts.Any(PipelineContracts.Contains);
        var pipelineHits = f.Contracts.Where(PipelineContracts.Contains).ToList();

        // Convention-based ASP.NET Core middleware implements NO interface — Facts flags a type that
        // declares Invoke/InvokeAsync(HttpContext ...) (signature-precise, per-type). Trustworthy
        // provenance WINS: don't let an AUTHENTIC compiled Razor view (verified by structure, not name)
        // or a framework-signed assembly be escalated by shape. ModuleScan already restricted us to
        // path-less modules, so a non-allowlisted fileless middleware is the implant.
        if (f.ConventionMiddleware && !frameworkVerified && !authenticGenerated)
        {
            hasPipeline = true;
            pipelineHits.Add("convention-middleware");
        }

        int capCount = 0; var capSignals = new List<string>();
        foreach (string api in CapabilityApis)
            if (f.ReferencedApis.Any(a => a.EndsWith(api, StringComparison.Ordinal))) { capCount++; capSignals.Add("api:" + api); }
        foreach (string s in f.CapabilityStringHits) { capCount++; capSignals.Add("str:" + s); }

        string? spoofSignal = spoofed ? "spoofed-strong-name:" + f.PublicKeyTokenHex : null; // PKT non-null: claimsFramework requires f.PublicKeyTokenHex != null

        // Suppress (trustworthy): framework assembly with VERIFIED strong-name signature + no pipeline hook.
        if (frameworkVerified && !hasPipeline)
            return new Assessment(AssessTier.Clean, 0, true, new[] { "framework-verified:" + f.PublicKeyTokenHex },
                $"strong-name-VERIFIED framework assembly (public key token {f.PublicKeyTokenHex}); no request-pipeline implant");

        // Suppress (trustworthy): an AUTHENTIC runtime-generated assembly, verified by the generator's
        // forgery-resistant STRUCTURE (Razor [RazorCompiledItem]+view type / sgen serializer types) —
        // never the attacker-controlled assembly NAME. Still requires no pipeline hook and no capability,
        // so even a structurally-valid forgery is provably inert while suppressed.
        if (authenticGenerated && !hasPipeline && capCount == 0)
            return new Assessment(AssessTier.Clean, 0, true, new[] { "authentic-generated" },
                $"authentic runtime-generated assembly (generator structure verified, not the assembly name '{f.AssemblyName}'); no request-pipeline implant or capability indicators");

        // Escalate: fileless assembly that hooks the request pipeline.
        if (hasPipeline)
        {
            var sig = new List<string> { "pipeline:" + string.Join("+", pipelineHits) };
            int score = 85;
            if (capCount > 0) { sig.AddRange(capSignals); score = 95; }
            if (spoofSignal != null) sig.Add(spoofSignal);
            return new Assessment(AssessTier.LikelyMalicious, score, false, sig,
                $"path-less CLR module implements request-pipeline contract(s) [{string.Join(", ", pipelineHits)}]"
                + (capCount > 0 ? $" and carries capability indicators [{string.Join(", ", capSignals)}]" : "")
                + (spoofSignal != null ? "; forged framework token" : "")
                + "; not framework-verified");
        }

        // Capability without a pipeline hook: strong if multiple indicators, else worth review.
        if (capCount >= 2)
        {
            var sig = new List<string>(capSignals);
            if (spoofSignal != null) sig.Add(spoofSignal);
            return new Assessment(AssessTier.LikelyMalicious, 80, false, sig,
                $"path-less CLR module with multiple webshell capability indicators [{string.Join(", ", capSignals)}] and no benign provenance"
                + (spoofSignal != null ? "; forged framework token" : ""));
        }
        if (capCount == 1)
        {
            var sig = new List<string>(capSignals);
            if (spoofSignal != null) sig.Add(spoofSignal);
            return new Assessment(AssessTier.Suspicious, 55, false, sig,
                $"path-less CLR module with a capability indicator [{string.Join(", ", capSignals)}]; warrants analyst review"
                + (spoofSignal != null ? "; forged framework token" : ""));
        }

        // Unexplained fileless residency (or lone spoof): not framework-verified, not a known generated name.
        // Deliberate: spoof signal replaces (not augments) fileless-unexplained — it's a strictly more informative signal.
        var fallSignals = spoofSignal != null ? new[] { spoofSignal } : new[] { "fileless-unexplained" };
        return new Assessment(AssessTier.Suspicious, 50, false, fallSignals,
            $"path-less CLR module '{f.AssemblyName}' with no benign provenance"
            + (spoofSignal != null ? "; forged framework token (spoofed-strong-name)" : " (not framework-verified, not a known generated assembly)")
            + "; no strong malicious signal; warrants analyst review");
    }

    // AUTHENTICATE a runtime-generated assembly by the GENERATOR'S STRUCTURE, never its (attacker-
    // controlled) name. Verified against a real ASP.NET Core build: a runtime-compiled Razor view's
    // assembly name is Path.GetRandomFileName(), so a name check both FALSE-POSITIVES on every real view
    // and is trivially forged (#9-dotnet — an Assembly.Load(byte[]) named "AspNetCoreGeneratedDocument.x"
    // got a free pass). We instead require the forgery-resistant markers the generator emits; combined
    // with the call-site's "no pipeline hook + no capability" guard, even a structural forgery is inert.
    private static bool IsAuthenticGenerated(ModuleFacts f)
    {
        // ASP.NET Core Razor view/page: the Razor compiler emits [RazorCompiledItem(Metadata)] AND puts
        // the generated type in the AspNetCoreGeneratedDocument namespace (deriving it from RazorPage).
        // Require the attribute AND the generated structure — the attribute alone is forgeable metadata.
        bool razorAttr = f.AttributeTypes.Any(a =>
            a == "Microsoft.AspNetCore.Razor.Hosting.RazorCompiledItemAttribute" ||
            a == "Microsoft.AspNetCore.Razor.Hosting.RazorCompiledItemMetadataAttribute");
        bool razorStructure =
            f.TypeFullNames.Any(t => t.StartsWith("AspNetCoreGeneratedDocument.", StringComparison.Ordinal)) ||
            f.Contracts.Any(c => c.StartsWith("Microsoft.AspNetCore.Mvc.Razor.RazorPage", StringComparison.Ordinal) ||
                                 c.StartsWith("Microsoft.AspNetCore.Mvc.RazorPages.Page", StringComparison.Ordinal));
        if (razorAttr && razorStructure) return true;

        // sgen / XmlSerializer (.NET Framework): the reliable '<types>.XmlSerializers' name convention
        // CORROBORATED by the generated serializer structure (in-memory ones are path-less candidates).
        if (f.AssemblyName.EndsWith(".XmlSerializers", StringComparison.Ordinal) &&
            (f.TypeFullNames.Any(t => t.StartsWith("Microsoft.Xml.Serialization.GeneratedAssembly.", StringComparison.Ordinal)) ||
             f.Contracts.Any(c => c == "System.Xml.Serialization.XmlSerializationWriter" ||
                                  c == "System.Xml.Serialization.XmlSerializationReader" ||
                                  c == "System.Xml.Serialization.XmlSerializerImplementation")))
            return true;

        return false;
    }
}
