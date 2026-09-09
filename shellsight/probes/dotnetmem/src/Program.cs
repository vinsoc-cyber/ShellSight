using System.Collections.Concurrent;
using System.Security.Cryptography;
using Microsoft.Diagnostics.Runtime;
using ShellSight.DotnetMem;
// ClrMD also defines a ModuleInfo; this alias resolves the ambiguity to our candidate-module record.
using ModuleInfo = ShellSight.DotnetMem.ModuleInfo;

// dotnetmem — the .NET/IIS in-memory webshell view. Reads a TargetSpec on stdin, acquires each
// target (live snapshot or dump), finds fileless CLR modules, discriminates real request-pipeline
// implants from benign dynamic assemblies, recovers + decompiles the malicious ones, and emits
// []Finding on stdout.
//
// Coverage honesty (project invariant): exit non-zero when we could not analyze what was asked, so
// the core marks the view failed rather than reporting a silent clean.
//   exit 0 = analyzed (findings may be empty)
//   exit 2 = coverage failure (no analyzable target / all targets failed / bad spec)

const int ExitOK = 0, ExitInternal = 1, ExitCoverage = 2;

string artifactsDir = ArgValue(args, "--artifacts-dir")
    ?? Path.Combine(Path.GetTempPath(), "shellsight-dotnetmem-artifacts");

// Diagnostic: print facts+tier for EVERY path-less candidate (incl. suppressed/Clean) to stderr. Used
// to measure real-benign FPR and capture generated-assembly ground truth; does NOT change behavior.
bool explain = args.Contains("--explain");

// Load mem-contracts.json and override compiled-in defaults.
var mc = MemContractsLoader.TryLoad(MemContractsLoader.ResolvePath(args));
if (mc?.Dotnet != null)
{
    Discriminator.Configure(mc.Dotnet.PipelineContracts, mc.Dotnet.CapabilityApis, mc.Dotnet.FrameworkPublicKeys);
    Facts.Configure(mc.Dotnet.StringNeedles);
}

string stdin = await Console.In.ReadToEndAsync();
TargetSpec spec;
try { spec = Contract.ParseSpec(stdin); }
catch (Exception ex) { Console.Error.WriteLine("dotnetmem: bad TargetSpec on stdin: " + ex.Message); return ExitCoverage; }

List<AcquireTarget> targets = Acquire.Resolve(spec, out bool requestedExplicit, out List<string> deferred);
// Degraded coverage (never silent): w3wp of the other bitness this probe can't analyze. The companion
// (dotnet-mem-x86 / dotnet-mem) probe — run automatically by the core — covers them.
foreach (string d in deferred) Console.Error.WriteLine("dotnetmem: degraded coverage: " + d);
if (targets.Count == 0)
{
    if (requestedExplicit) { Console.Error.WriteLine("dotnetmem: requested target(s) not present"); return ExitCoverage; }
    if (deferred.Count > 0)
        Console.Error.WriteLine($"dotnetmem: no w3wp of this probe's bitness; {deferred.Count} worker(s) deferred to the companion probe");
    else
        Console.Error.WriteLine("dotnetmem: no w3wp.exe found to analyze");
    Console.Out.Write("[]");
    return ExitOK; // nothing of our bitness (companion covers the rest) — not a failure
}

Directory.CreateDirectory(artifactsDir);
var findings = new List<Finding>();
int analyzedOK = 0; var failures = new List<string>(); int moduleIdx = 0; int allowlisted = 0;

// 30s safety timeout: prevents hanging indefinitely on a stuck target or ETW session.
using var probeCts = new CancellationTokenSource(TimeSpan.FromSeconds(30));

foreach (AcquireTarget t in targets)
{
    if (probeCts.Token.IsCancellationRequested)
    {
        Console.Error.WriteLine("dotnetmem: 30s probe timeout; skipping remaining targets");
        failures.Add("probe timeout reached");
        break;
    }

    // Start ETW channel in parallel with ClrMD scan (catches reflective loads not in module list).
    var etwFindings = new ConcurrentBag<string>();
    var etw = new ETWChannel(t.IsDump ? -1 : t.Pid, name => etwFindings.Add(name));

    DataTarget? dt = Acquire.Open(t, out string? err);
    if (dt == null) { etw.Dispose(); failures.Add(err ?? (t.Label + ": unknown error")); continue; }
    try
    {
        using (dt)
        {
            if (dt.ClrVersions.Length == 0)
            {
                // Attached, but no managed runtime is exposed. For an operator-named dump/PID this
                // usually means a truncated capture or missing DAC — NOT "no memshell". Treat as a
                // failure to analyze (coverage honesty), never a silent clean.
                failures.Add($"{t.Label}: no CLR runtime available (truncated dump / missing DAC / non-managed target)");
                continue;
            }
            ClrRuntime runtime = dt.ClrVersions[0].CreateRuntime();
            analyzedOK++;

            foreach (ModuleInfo mi in ModuleScan.Suspicious(ModuleScan.Enumerate(runtime)))
            {
                try
                {
                    byte[] image = Extract.ReadModuleImage(dt, mi.ImageBase, mi.Size);
                    if (!Extract.LooksLikePe(image)) continue;
                    ModuleFacts facts = Facts.Parse(image);
                    Assessment a = Discriminator.Assess(facts);
                    if (explain)
                        Console.Error.WriteLine($"dotnetmem: [explain] name='{facts.AssemblyName}' tier={a.Tier} score={a.Score} pkt={facts.PublicKeyTokenHex ?? "none"} snValid={facts.StrongNameValid} convMw={facts.ConventionMiddleware} base/iface=[{string.Join(";", facts.Contracts)}] attrs=[{string.Join(";", facts.AttributeTypes)}] types=[{string.Join(";", facts.TypeFullNames.Take(6))}] signals=[{string.Join(",", a.Signals)}]");
                    if (a.Tier == AssessTier.Clean) { allowlisted++; continue; } // suppress benign dynamic assemblies
                    findings.Add(MapFinding(spec.Host, t, mi, image, facts, a, artifactsDir, ref moduleIdx));
                }
                catch (Exception ex)
                {
                    // One hostile/corrupt/unwritable module must not abort the rest of the scan.
                    Console.Error.WriteLine($"dotnetmem: {t.Label}: module @ 0x{mi.ImageBase:x} skipped: {ex.Message}");
                }
            }

            // ---- Reachability axis: walk the live dispatch chains, judge each wired component by
            // its backing module's provenance (reuses carve+Facts+Discriminator). Additive: any
            // failure logs and leaves the module-first findings intact (no regression). ----
            var reachFindings = new List<Finding>();
            try
            {
                var byBase = new Dictionary<ulong, ModuleInfo>();
                foreach (ModuleInfo m in ModuleScan.Enumerate(runtime)) byBase[m.ImageBase] = m;
                var heap = new ClrMdHeap(runtime);
                // Reachability axis (was gated by a blunt `if (bm.HasDiskPath) continue` that suppressed EVERY
                // disk-backed wired component — including malicious inline-.aspx temp assemblies — making the
                // entire disk-backed-pipeline-memshell class invisible). Now: carve + Discriminator.Assess each
                // UNIQUE backing module once (cached by image base), then judge per wired component via three
                // gates: (1) framework assembly suppressed, (2) capability required, (3) Decide tier.
                var assessedBacking = new Dictionary<ulong, Assessment>();
                var backingIsFramework = new Dictionary<ulong, bool>();
                var backingIsTempAsm = new Dictionary<ulong, bool>();

                // Pre-pass: collect convention-OWIN type names from webroot-dropped modules. These are
                // convention-middleware types (Invoke/IOwinContext, no OwinMiddleware base) loaded disk-backed
                // via Assembly.LoadFrom — invisible to WalkOwin's InstancesOf("OwinMiddleware") because they
                // don't derive from it. Only scans webroot-dropped (non-bin\) non-framework non-temp modules
                // (the attack delivery pattern), so zero overhead on clean apps.
                var conventionOwinTypes = new List<string>();
                foreach (ModuleInfo mi in ModuleScan.Enumerate(runtime))
                {
                    if (!mi.HasDiskPath || !File.Exists(mi.Name)) continue;
                    if (!IsDroppedWebrootAssembly(mi.Name)) continue;
                    if (assessedBacking.ContainsKey(mi.ImageBase)) continue;
                    try {
                        byte[] img = Extract.ReadModuleImage(dt, mi.ImageBase, mi.Size);
                        if (!Extract.LooksLikePe(img)) continue;
                        ModuleFacts f = Facts.Parse(img);
                        if (f.ConventionMiddleware)
                            foreach (string tn in f.TypeFullNames)
                                conventionOwinTypes.Add(tn);
                    } catch { }
                }

                foreach (WiredComponent wc in Reachability.WalkAll(heap, conventionOwinTypes.Count > 0 ? conventionOwinTypes : null))
                {
                    Assessment? backing = null;
                    bool fwBacking = false, tempBacking = false, droppedBacking = false, pathlessBacking = false;
                    if (wc.Instance.BackingImageBase != 0 && byBase.TryGetValue(wc.Instance.BackingImageBase, out ModuleInfo? bm))
                    {
                        if (!assessedBacking.TryGetValue(bm.ImageBase, out Assessment? cached))
                        {
                            try
                            {
                                byte[] bimg = Extract.ReadModuleImage(dt, bm.ImageBase, bm.Size);
                                if (Extract.LooksLikePe(bimg))
                                {
                                    ModuleFacts f = Facts.Parse(bimg);
                                    cached = Discriminator.Assess(f);
                                    backingIsFramework[bm.ImageBase] = IsFrameworkAssemblyName(f.AssemblyName);
                                    backingIsTempAsm[bm.ImageBase] = IsAspNetTempAssembly(f.AssemblyName);
                                }
                            }
                            catch (Exception ex) { Console.Error.WriteLine($"dotnetmem: reachability backing carve @0x{bm.ImageBase:x} failed: {ex.Message}"); }
                            if (cached != null) assessedBacking[bm.ImageBase] = cached;
                        }
                        backing = cached;
                        fwBacking = backingIsFramework.TryGetValue(bm.ImageBase, out bool fb) && fb;
                        tempBacking = backingIsTempAsm.TryGetValue(bm.ImageBase, out bool tb) && tb;
                        droppedBacking = IsDroppedWebrootAssembly(bm.Name);
                        pathlessBacking = !bm.HasDiskPath;   // fileless (Assembly.Load(byte[])) backing
                    }
                    // (1) Suppress real framework/system backing assemblies (System.Web/System.Web.Mvc/...) by
                    //     their ASSEMBLY identity (name), NOT the wired-type namespace. The type namespace is
                    //     attacker-controllable (a dropped DLL can declare type "System.Web.EvilModule"); a
                    //     type-namespace check would false-suppress such a name-spoofed memshell. ASP.NET temp
                    //     assemblies (App_Web_*, the inline-.aspx backing) and dropped attacker DLLs are
                    //     non-framework -> not suppressed here.
                    if (fwBacking || (backing != null && (backing.Allowlisted || backing.Tier == AssessTier.Clean)))
                    {
                        allowlisted++;
                        continue;
                    }
                    // (2) ANOMALOUS-BACKING gate (was: a capability gate). A wired component is escalated ONLY
                    //     if its backing load pattern is ANOMALOUS — fileless (Assembly.Load(byte[]), path-less),
                    //     an inline-.aspx/Global.asax temp assembly (App_Web_*/App_Code/App_global), or a
                    //     webroot-dropped DLL (not bin\). Capability indicators (carved api:/str: or Godzilla/
                    //     AntSword field shapes) are now a TIER BOOST inside Decide, NOT the gate — because real
                    //     apps' OWN bin\ assemblies legitimately reference crypto/reflection/base64, so a
                    //     capability gate false-positives on legit app modules (proven live: mojoPortal's
                    //     UrlRewriter/AuthHandler/CultureHelper/etc. all flagged). Anomalous load pattern is the
                    //     principled memshell signal: memshells load fileless/temp/webroot-dropped; legit app
                    //     code ships in bin\. (Residual: a memshell dropped INTO bin\ is indistinguishable from
                    //     the app's own code by static backing analysis alone.)
                    bool anomalous = tempBacking || droppedBacking || pathlessBacking || backing == null;
                    if (!anomalous) { allowlisted++; continue; }
                    ReachabilityVerdict rv = Reachability.Decide(wc, backing);
                    if (rv.Suppressed) { allowlisted++; continue; }
                    reachFindings.Add(MapReachFinding(spec.Host, t, wc, rv, ref moduleIdx));
                }
            }
            catch (Exception ex) { Console.Error.WriteLine($"dotnetmem: {t.Label}: reachability axis skipped: {ex.Message}"); }
            if (reachFindings.Count > 0) { var merged = Reachability.Merge(findings, reachFindings); findings.Clear(); findings.AddRange(merged); }

            // ---- Stomp-diff: compare .text SECTION (IL code) between in-memory PE and disk file for each
            // disk-backed, pure-IL module. Managed IL is position-independent -> .text bytes match exactly.
            // A mismatch = the module's IL was overwritten in memory (stomped). Emits a suspicious finding.
            // Skips mixed-mode assemblies (CorFlags IL-only check) whose .text has relocated native code. ----
            {
                foreach (ModuleInfo mi in ModuleScan.Enumerate(runtime)) {
                    if (!mi.HasDiskPath || !File.Exists(mi.Name)) continue;
                    try {
                        byte[] inMem = Extract.ReadModuleImage(dt, mi.ImageBase, mi.Size);
                        byte[] disk = System.IO.File.ReadAllBytes(mi.Name);
                        string? stompResult = TextSectionCompare(inMem, disk);
                        if (stompResult != null) {
                            string sha = Net462Compat.ToHex(Net462Compat.Sha256(inMem));
                            findings.Add(new Finding {
                                SchemaVersion = "1.0",
                                Id = "stomp-" + sha.Substring(0, 12) + "-" + Sanitize(System.IO.Path.GetFileNameWithoutExtension(mi.Name)),
                                Host = spec.Host,
                                View = "dotnet-mem",
                                Target = new Target { Kind = "process", Process = new ProcessRef { Pid = t.Pid, Name = t.Name } },
                                Artifact = new Artifact { Kind = "stomped-module", Identity = System.IO.Path.GetFileName(mi.Name), Location = $"in-memory .text differs from disk ({mi.Name}, pid {t.Pid})" },
                                Detection = new Detection { Basis = "stomp-diff", KnowledgeRef = "heuristic:dotnet/stomp-diff", Evidence = $"in-memory .text section differs from on-disk PE: {stompResult}; module '{mi.Name}' IL may have been overwritten (stomped)", Allowlisted = false },
                                Score = 50,
                                Tier = "suspicious",
                                Context = new Dictionary<string, string> { ["path"] = mi.Name, ["image_base"] = "0x" + mi.ImageBase.ToString("x"), ["source"] = t.IsDump ? "dump" : "live-snapshot" },
                            });
                            if (explain) Console.Error.WriteLine($"dotnetmem: [stomp-diff] FINDING {System.IO.Path.GetFileName(mi.Name)} ({stompResult})");
                        }
                    } catch { }
                }
            }
        }
    }
    catch (Exception ex)
    {
        // One bad target (corrupt CLR view, enumeration/CreateRuntime failure) must not abort the others.
        failures.Add($"{t.Label}: analysis error: {ex.Message}");
    }
    finally { etw.Dispose(); } // cancel + wait 2s for rundown to complete

    // ETW supplementary findings: reflective loads not already covered by ClrMD module carving.
    var knownIds = new HashSet<string>(findings.Select(f => f.Artifact.Identity));
    foreach (string name in etwFindings.Distinct())
    {
        if (!knownIds.Contains(name) && !string.IsNullOrWhiteSpace(name))
            findings.Add(MapEtwFinding(spec.Host, t, name, ref moduleIdx));
    }
}

if (analyzedOK == 0) // had targets but analyzed none → failed view, no findings lost
{
    foreach (string f in failures) Console.Error.WriteLine("dotnetmem: " + f);
    Console.Error.WriteLine("dotnetmem: no targets could be analyzed");
    return ExitCoverage;
}
foreach (string f in failures) Console.Error.WriteLine("dotnetmem: warning: " + f); // partial: keep findings, log the rest
Console.Error.WriteLine($"dotnetmem: analyzed={analyzedOK} findings={findings.Count} allowlisted(suppressed)={allowlisted}");

try { Console.Out.Write(Contract.Serialize(findings)); }
catch (Exception ex) { Console.Error.WriteLine("dotnetmem: serialize: " + ex.Message); return ExitInternal; }
return ExitOK;

static Finding MapFinding(string host, AcquireTarget t, ModuleInfo mi, byte[] image, ModuleFacts facts, Assessment a, string artifactsDir, ref int idx)
{
    string sha = Net462Compat.ToHex(Net462Compat.Sha256(image));
    string raw = Path.Combine(artifactsDir, $"module_{idx}.bin");
    File.WriteAllBytes(raw, image);
    string? csPath = null;
    try { string cs = Decompile.ToCSharp(image, facts.AssemblyName); csPath = Path.Combine(artifactsDir, $"module_{idx}.cs"); File.WriteAllText(csPath, cs); }
    catch (Exception ex) { Console.Error.WriteLine($"dotnetmem: decompile module_{idx} failed: {ex.Message}"); }
    idx++;

    string tier = a.Tier == AssessTier.LikelyMalicious ? "likely-malicious" : "suspicious";
    var ctx = new Dictionary<string, string>
    {
        ["image_base"] = "0x" + mi.ImageBase.ToString("x"),
        ["module_size"] = mi.Size.ToString(),
        ["public_key_token"] = facts.PublicKeyTokenHex ?? "none",
        ["signals"] = string.Join(",", a.Signals),
        ["source"] = t.IsDump ? "dump" : "live-snapshot",
    };
    if (t.IsDump) ctx["dump_path"] = t.DumpPath;

    bool isSpoofFinding = a.Signals.Any(s => s.StartsWith("spoofed-strong-name", StringComparison.Ordinal))
        && !a.Signals.Any(s => s.StartsWith("pipeline:", StringComparison.Ordinal) || s.StartsWith("api:", StringComparison.Ordinal) || s.StartsWith("str:", StringComparison.Ordinal));
    string basis = isSpoofFinding ? "provenance-anomaly" : "structural-heuristic";
    string knowledgeRef = isSpoofFinding ? "heuristic:dotnet/spoofed-strong-name"
        : a.Tier == AssessTier.LikelyMalicious ? "heuristic:dotnet/pipeline-implant" : "heuristic:dotnet/fileless-module";
    return new Finding
    {
        SchemaVersion = "1.0",
        Id = sha.Substring(0, 12) + "-" + Sanitize(facts.AssemblyName),
        Host = host,
        View = "dotnet-mem",
        Target = new Target { Kind = "process", Process = new ProcessRef { Pid = t.Pid, Name = t.Name } },
        Artifact = new Artifact { Kind = "dotnet-memory-module", Identity = facts.AssemblyName, Location = $"in-memory @ 0x{mi.ImageBase:x} (pid {t.Pid})" },
        Detection = new Detection { Basis = basis, KnowledgeRef = knowledgeRef, Evidence = a.Evidence, Allowlisted = false },
        Score = a.Score,
        Tier = tier,
        Artifacts = new Artifacts { Raw = raw, Decompiled = csPath ?? "" },
        Context = ctx,
    };
}

static Finding MapEtwFinding(string host, AcquireTarget t, string asmName, ref int idx)
    => new Finding
    {
        SchemaVersion = "1.0",
        Id = "etw-" + Math.Abs(asmName.GetHashCode()).ToString("x8") + "-" + idx++,
        Host = host,
        View = "dotnet-mem",
        Target = new Target { Kind = "process", Process = new ProcessRef { Pid = t.Pid, Name = t.Name } },
        Artifact = new Artifact
        {
            Kind = "clr-dynamic-assembly",
            Identity = asmName,
            Location = $"in-memory reflective load (pid {t.Pid})"
        },
        Detection = new Detection
        {
            Basis = "etw-dynamic-load",
            KnowledgeRef = "etw:DotNETRuntimeRundown/ModuleDCStop",
            Evidence = $"ETW DotNETRuntimeRundown detected path-less CLR module '{asmName}' (ModuleILPath empty); artifact may not be recoverable via ClrMD memory carve",
        },
        Score = 50,
        Tier = "suspicious",
        Context = new Dictionary<string, string>
        {
            ["source"] = "etw-dynamic-load",
            ["pid"] = t.Pid.ToString(),
        },
    };

static Finding MapReachFinding(string host, AcquireTarget t, WiredComponent wc, ReachabilityVerdict rv, ref int idx)
{
    string tier = rv.Tier == AssessTier.LikelyMalicious ? "likely-malicious" : "suspicious";
    idx++;
    return new Finding
    {
        SchemaVersion = "1.0",
        Id = "reach-" + Math.Abs(wc.Instance.TypeName.GetHashCode()).ToString("x8") + "-" + idx,
        Host = host,
        View = "dotnet-mem",
        Target = new Target { Kind = "process", Process = new ProcessRef { Pid = t.Pid, Name = t.Name } },
        Artifact = new Artifact { Kind = "dotnet-wired-component", Identity = wc.Instance.TypeName,
                                  Location = $"wired into {wc.Chain} chain (position {wc.Position}, pid {t.Pid})" },
        Detection = new Detection { Basis = "reachability-dispatch", KnowledgeRef = "heuristic:dotnet/reachable-dispatch", Evidence = rv.Evidence, Allowlisted = false },
        Score = rv.Score,
        Tier = tier,
        Context = new Dictionary<string, string>
        {
            ["chain"] = wc.Chain,
            ["chain_position"] = wc.Position.ToString(),
            ["backing_image_base"] = "0x" + wc.Instance.BackingImageBase.ToString("x"),
            ["signals"] = string.Join(",", rv.Signals),
            ["source"] = t.IsDump ? "dump" : "live-snapshot",
        },
    };
}

static string Sanitize(string s) => new string(s.Select(c => char.IsLetterOrDigit(c) ? c : '_').ToArray());

// Real framework/system assembly names. Suppresses wired components whose BACKING ASSEMBLY identity is a
// known framework assembly (System.Web/System.Web.Mvc/etc. -> FP-safe). A dropped attacker DLL or an ASP.NET
// temp assembly (App_Web_*, the inline-.aspx memshell backing) does NOT match -> escalated. Residual: an
// attacker who literally NAMES their assembly "System.Web" (rare; its strong-name signature won't verify and
// it cannot co-load with the real System.Web in the same AppDomain).
static bool IsFrameworkAssemblyName(string? name)
{
    if (string.IsNullOrEmpty(name)) return false;
    if (name.StartsWith("App_", StringComparison.OrdinalIgnoreCase)) return false; // ASP.NET temp assembly
    return name.StartsWith("System.", StringComparison.OrdinalIgnoreCase)
        || name.StartsWith("Microsoft.", StringComparison.OrdinalIgnoreCase)
        || name.Equals("mscorlib", StringComparison.OrdinalIgnoreCase)
        || name.Equals("System", StringComparison.OrdinalIgnoreCase)
        || name.Equals("netstandard", StringComparison.OrdinalIgnoreCase);
}

// ASP.NET dynamically-compiled ("temp") assemblies produced by the ASP.NET build system at runtime.
// App_Web_* = pages/controls/inline .aspx; App_Code = the App_Code folder; App_global* = Global.asax /
// global resources. A wired component backed by one of these is runtime-compiled code in a dispatch chain
// — the inline-.aspx / Global.asax memshell pattern. Legit app pipeline components compile into the app's
// own assembly, not temp assemblies, so this is a list-independent memshell signal. (Note: this overlaps
// with IsFrameworkAssemblyName's App_ exclusion — temp assemblies are neither framework nor legit-app.)
static bool IsAspNetTempAssembly(string? name)
{
    if (string.IsNullOrEmpty(name)) return false;
    return name.StartsWith("App_Web_", StringComparison.OrdinalIgnoreCase)
        || name.StartsWith("App_Code", StringComparison.OrdinalIgnoreCase)
        || name.StartsWith("App_global", StringComparison.OrdinalIgnoreCase);
}

// A disk-backed assembly loaded from the WEBROOT (or any non-standard location) -- NOT the app's bin\,
// NOT a framework/GAC path, NOT the ASP.NET temp dir. Attackers drop a DLL into the writable/served
// webroot and Assembly.LoadFrom it; legit app modules ship in bin\. Catches the capability-stripped
// dropped-DLL memshell whose backing is otherwise structurally identical to a legit app module. The path
// is ClrMD's module Name (a real filesystem path when HasDiskPath; path-less modules return false here --
// they're handled by the module-scan axis). CAVEAT: a drop INTO bin\ evades this, and a legit app that
// LoadFroms a non-bin plugin would FP -> this is a corroboration signal in the capability gate, not a
// sole determinant.
static bool IsDroppedWebrootAssembly(string? path)
{
    if (string.IsNullOrEmpty(path) || path.IndexOf('\\') < 0) return false; // no real on-disk path
    string p = path.ToLowerInvariant();
    if (p.Contains(@"\bin\")) return false;                       // app's bin -> legit
    if (p.Contains(@"\temporary asp.net files\")) return false;   // ASP.NET temp (App_Web) -> name signal
    if (p.Contains(@"\windows\microsoft.net\")) return false;     // framework runtime dir
    if (p.Contains(@"\windows\assembly\")) return false;          // GAC
    return true;                                                   // webroot / non-standard drop
}

// Check if the PE is pure-IL (COMIMAGE_FLAGS_IL_ONLY = 0x1). Mixed-mode assemblies (native+managed) have
// relocated native code in .text -> would false-positive the stomp-diff. Parses PE Optional Header ->
// DataDirectory[14] (CLR header) -> IMAGE_COR20_HEADER.Flags.
static bool IsPureIL(byte[] pe, int e_lfanew)
{
    try {
        int optStart = e_lfanew + 24;
        if (optStart + 2 > pe.Length) return false;
        ushort magic = BitConverter.ToUInt16(pe, optStart);            // 0x10b=PE32, 0x20b=PE32+
        int dataDirStart = optStart + (magic == 0x20b ? 112 : 96);
        int corDirOff = dataDirStart + 14 * 8;                          // DataDirectory[14] = CLR header
        if (corDirOff + 8 > pe.Length) return false;
        uint corRVA = BitConverter.ToUInt32(pe, corDirOff);
        uint corSize = BitConverter.ToUInt32(pe, corDirOff + 4);
        if (corSize == 0 || corRVA == 0 || corRVA + 0x14 > pe.Length) return false;
        uint flags = BitConverter.ToUInt32(pe, (int)corRVA + 0x10);     // IMAGE_COR20_HEADER.Flags
        return (flags & 0x1) != 0;                                      // COMIMAGE_FLAGS_IL_ONLY
    } catch { return false; }
}

// Stomp-diff: compare the .text section (IL code) between the in-memory PE image and the on-disk PE file.
// Managed IL is position-independent -> the .text section bytes should match exactly between memory and disk
// (unlike headers/padding which the CLR modifies during loading). Returns null on match, or a mismatch-
// description string. Parses the PE section table to locate .text, then compares SizeOfRawData bytes at the
// respective offsets (VirtualAddress in memory, PointerToRawData in the file).
static string? TextSectionCompare(byte[] inMem, byte[] disk)
{
    if (inMem.Length < 0x40 || disk.Length < 0x40) return null;
    int e_lfanew = BitConverter.ToInt32(inMem, 0x3C);
    if (e_lfanew < 0 || e_lfanew + 24 >= inMem.Length) return null;
    if (inMem[e_lfanew] != (byte)'P' || inMem[e_lfanew + 1] != (byte)'E') return null; // PE sig
    // Skip mixed-mode assemblies (native+managed): their .text contains relocated native code (not just IL)
    // -> would false-positive. Check the CLR header Flags for COMIMAGE_FLAGS_IL_ONLY (0x1).
    if (!IsPureIL(inMem, e_lfanew)) return null;
    int numSections = BitConverter.ToUInt16(inMem, e_lfanew + 6);
    int sizeOfOptHeader = BitConverter.ToUInt16(inMem, e_lfanew + 20);
    int sectionTableOffset = e_lfanew + 24 + sizeOfOptHeader;
    for (int i = 0; i < numSections; i++)
    {
        int sec = sectionTableOffset + i * 40;
        if (sec + 40 > inMem.Length) break;
        string name = System.Text.Encoding.ASCII.GetString(inMem, sec, 8).TrimEnd('\0');
        if (name != ".text") continue;
        uint virtualAddress = BitConverter.ToUInt32(inMem, sec + 12);
        uint sizeOfRawData = BitConverter.ToUInt32(inMem, sec + 16);
        uint pointerToRawData = BitConverter.ToUInt32(inMem, sec + 20);
        long inMemEnd = (long)virtualAddress + sizeOfRawData;
        long diskEnd = (long)pointerToRawData + sizeOfRawData;
        if (inMemEnd > inMem.Length || diskEnd > disk.Length) return null; // bounds
        int diffs = 0;
        for (uint j = 0; j < sizeOfRawData; j++)
            if (inMem[virtualAddress + j] != disk[pointerToRawData + j]) diffs++;
        if (diffs > 0) return $".text: {diffs} diffs in {sizeOfRawData} bytes";
        return null; // .text matches
    }
    return null; // no .text section
}
static string? ArgValue(string[] args, string name)
{
    for (int i = 0; i < args.Length - 1; i++) if (args[i] == name) return args[i + 1];
    return null;
}
