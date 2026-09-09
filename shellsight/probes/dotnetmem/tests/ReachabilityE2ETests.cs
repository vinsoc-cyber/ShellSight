using System.Diagnostics;
using System.Text.Json;
using Xunit;

// Live integration for the reachability axis: the lab/reachvictim harness wires a benign-inert VPP
// (lab/fixtures/BenignReachVpp) into the real System.Web HostingEnvironment chain, and the probe attaches
// out-of-process. Fileless backing -> reachability-dispatch likely; disk-backed -> gated (0-FP). Mirrors
// AcquireTests.StartVictim's stale-sentinel cleanup so there is no premature-attach race. Skips if the
// lab isn't built (same convention as ProbeE2ETests / AcquireTests).
public class ReachabilityE2ETests
{
    private static (string victimExe, string vppDll) Lab()
    {
        string root = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "lab"));
        string v = Path.Combine(root, "reachvictim", "bin", "Release", "net48", "ReachVictim.exe");
        string d = Path.Combine(root, "fixtures", "BenignReachVpp", "bin", "Release", "net48", "BenignReachVpp.dll");
        return (File.Exists(v) && File.Exists(d)) ? (v, d) : ("", "");
    }

    // fileless => path-less backing (implant); else disk-backed (clean). A fresh VPP dll is copied beside
    // the harness each run (the fileless mode deletes it to simulate fileless residency).
    private static Process StartVictim(string victimExe, string vppDll, bool fileless)
    {
        string dir = Path.GetDirectoryName(victimExe)!;
        File.Delete(Path.Combine(dir, "STOP"));
        File.Delete(Path.Combine(dir, "reachvictim_status.txt")); // clear stale readiness sentinel
        File.Copy(vppDll, Path.Combine(dir, "BenignReachVpp.dll"), overwrite: true);
        var psi = new ProcessStartInfo(victimExe) { UseShellExecute = false, CreateNoWindow = true };
        if (fileless) psi.Arguments = "--fileless";
        var p = Process.Start(psi)!;
        string status = Path.Combine(dir, "reachvictim_status.txt");
        for (int i = 0; i < 100 && !File.Exists(status); i++) Thread.Sleep(100); // wait until wired
        Thread.Sleep(400);
        return p;
    }

    private static void StopVictim(Process p)
    {
        try { File.WriteAllText(Path.Combine(Path.GetDirectoryName(p.MainModule!.FileName)!, "STOP"), "x"); } catch { }
        try { if (!p.WaitForExit(3000)) p.Kill(); } catch { }
    }

    [Fact] // fileless VPP wired into the live chain -> reachability-dispatch likely, evidence reachable:vpp@0
    public void FilelessWiredVpp_IsReachabilityDispatchLikely()
    {
        var (v, d) = Lab();
        if (v == "") return; // lab not built — skip
        Process victim = StartVictim(v, d, fileless: true);
        try
        {
            var (outp, code) = ProbeHarness.Run($$"""{"host":"WEB01","pids":[{{victim.Id}}]}""");
            Assert.Equal(0, code);
            using var doc = JsonDocument.Parse(outp);
            var reach = doc.RootElement.EnumerateArray()
                .Where(f => f.GetProperty("detection").GetProperty("basis").GetString() == "reachability-dispatch").ToList();
            Assert.NotEmpty(reach);
            Assert.Contains(reach, f => f.GetProperty("tier").GetString() == "likely-malicious");
            Assert.Contains(reach, f => f.GetProperty("context").GetProperty("signals").GetString()!.Contains("reachable:vpp@0"));
        }
        finally { StopVictim(victim); }
    }

    [Fact] // disk-backed (framework-analogue) VPP -> gated out -> no reachability finding (FP-safety)
    public void DiskBackedWiredVpp_YieldsNoReachabilityFinding()
    {
        var (v, d) = Lab();
        if (v == "") return; // lab not built — skip
        Process victim = StartVictim(v, d, fileless: false);
        try
        {
            var (outp, code) = ProbeHarness.Run($$"""{"host":"WEB01","pids":[{{victim.Id}}]}""");
            Assert.Equal(0, code);
            using var doc = JsonDocument.Parse(outp);
            Assert.DoesNotContain(doc.RootElement.EnumerateArray(),
                f => f.GetProperty("detection").GetProperty("basis").GetString() == "reachability-dispatch");
        }
        finally { StopVictim(victim); }
    }
}
