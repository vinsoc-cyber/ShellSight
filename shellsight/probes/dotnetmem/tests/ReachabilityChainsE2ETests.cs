using System.Diagnostics;
using System.Text.Json;
using Xunit;

// Live integration for the filter + route reachability chains: lab/reachvictim wires a benign-inert
// component into the real System.Web chain via the public API, the probe attaches out-of-process.
// Fileless backing -> reachability-dispatch likely; disk-backed -> gated (0-FP). Skips if the lab isn't
// built (same convention as ReachabilityE2ETests).
public class ReachabilityChainsE2ETests
{
    private static string LabRoot => Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "lab"));
    private static string Victim => Path.Combine(LabRoot, "reachvictim", "bin", "Release", "net48", "ReachVictim.exe");
    private static string Fixture(string name) => Path.Combine(LabRoot, "fixtures", name, "bin", "Release", "net48", name + ".dll");

    // Launch reachvictim for a chain; copy a fresh fixture dll beside it (fileless mode deletes it).
    private static Process Start(string fixtureName, string[] extraArgs, bool fileless)
    {
        string dir = Path.GetDirectoryName(Victim)!;
        File.Delete(Path.Combine(dir, "STOP"));
        File.Delete(Path.Combine(dir, "reachvictim_status.txt"));
        File.Copy(Fixture(fixtureName), Path.Combine(dir, fixtureName + ".dll"), overwrite: true);
        var psi = new ProcessStartInfo(Victim) { UseShellExecute = false, CreateNoWindow = true,
            Arguments = string.Join(" ", extraArgs) + (fileless ? " --fileless" : "") };
        var p = Process.Start(psi)!;
        string status = Path.Combine(dir, "reachvictim_status.txt");
        for (int i = 0; i < 100 && !File.Exists(status); i++) Thread.Sleep(100);
        Thread.Sleep(400);
        return p;
    }

    private static void Stop(Process p)
    {
        try { File.WriteAllText(Path.Combine(Path.GetDirectoryName(p.MainModule!.FileName)!, "STOP"), "x"); } catch { }
        try { if (!p.WaitForExit(3000)) p.Kill(); } catch { }
    }

    private static System.Collections.Generic.List<JsonElement> ReachFindings(int pid)
    {
        var (outp, code) = ProbeHarness.Run($$"""{"host":"WEB01","pids":[{{pid}}]}""");
        Assert.Equal(0, code);
        using var doc = JsonDocument.Parse(outp);
        return doc.RootElement.EnumerateArray()
            .Where(f => f.GetProperty("detection").GetProperty("basis").GetString() == "reachability-dispatch")
            .Select(f => f.Clone()).ToList();
    }

    [Fact] // fileless filter wired into GlobalFilters -> reachability-dispatch likely, reachable:filter@0
    public void FilelessWiredFilter_IsReachabilityDispatchLikely()
    {
        if (!File.Exists(Victim) || !File.Exists(Fixture("BenignReachFilter"))) return; // lab not built — skip
        Process v = Start("BenignReachFilter", new[] { "--chain", "filter" }, fileless: true);
        try
        {
            var reach = ReachFindings(v.Id);
            Assert.Contains(reach, f => f.GetProperty("tier").GetString() == "likely-malicious");
            Assert.Contains(reach, f => f.GetProperty("context").GetProperty("signals").GetString()!.Contains("reachable:filter@"));
        }
        finally { Stop(v); }
    }

    [Fact] // disk-backed filter -> gated -> no reachability finding (FP-safety)
    public void DiskBackedWiredFilter_YieldsNoReachabilityFinding()
    {
        if (!File.Exists(Victim) || !File.Exists(Fixture("BenignReachFilter"))) return;
        Process v = Start("BenignReachFilter", new[] { "--chain", "filter" }, fileless: false);
        try { Assert.Empty(ReachFindings(v.Id)); }
        finally { Stop(v); }
    }

    [Fact] // custom RouteBase wired into RouteTable -> the route item itself is the path-less implant
    public void FilelessWiredRouteBase_IsReachabilityDispatchLikely()
    {
        if (!File.Exists(Victim) || !File.Exists(Fixture("BenignReachRoute"))) return;
        Process v = Start("BenignReachRoute", new[] { "--chain", "route", "--route-shape", "base" }, fileless: true);
        try
        {
            var reach = ReachFindings(v.Id);
            Assert.Contains(reach, f => f.GetProperty("tier").GetString() == "likely-malicious");
            Assert.Contains(reach, f => f.GetProperty("context").GetProperty("signals").GetString()!.Contains("reachable:route@"));
        }
        finally { Stop(v); }
    }

    [Fact] // custom IRouteHandler BEHIND a stock Route -> caught only via the RouteHandler descent (spec §6)
    public void FilelessRouteHandlerBehindStockRoute_IsReachabilityDispatchLikely()
    {
        if (!File.Exists(Victim) || !File.Exists(Fixture("BenignReachRoute"))) return;
        Process v = Start("BenignReachRoute", new[] { "--chain", "route", "--route-shape", "handler" }, fileless: true);
        try
        {
            var reach = ReachFindings(v.Id);
            Assert.Contains(reach, f => f.GetProperty("artifact").GetProperty("identity").GetString()!.Contains("RouteHandler"));
        }
        finally { Stop(v); }
    }
}
