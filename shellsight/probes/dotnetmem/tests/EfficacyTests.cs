using System.Diagnostics;
using System.Text.Json;
using Xunit;

public class EfficacyTests
{
    // Run the built probe against a live PID; return the parsed findings array.
    private static JsonElement RunProbe(int pid)
    {
        // Probe is retargeted to net462 (commit f80dbb2); ClrMD reads any target CLR regardless of the
        // probe's own TFM, so the net462 probe scans both the net48 and net8.0 victims below.
        string exe = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "src", "bin", "Release", "net462", "dotnetmem.exe"));
        var psi = new ProcessStartInfo(exe, "--artifacts-dir " + Path.Combine(Path.GetTempPath(), "sseval-art"))
        { RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false };
        using var p = Process.Start(psi)!;
        p.StandardInput.Write($$"""{"host":"EVAL","pids":[{{pid}}]}""");
        p.StandardInput.Close();
        string o = p.StandardOutput.ReadToEnd();
        p.WaitForExit(30000);
        return JsonDocument.Parse(o == "" ? "[]" : o).RootElement.Clone();
    }

    // Highest tier among the findings ("clean" if none).
    private static string TopTier(JsonElement findings)
    {
        string[] order = { "clean", "suspicious", "likely-malicious", "confirmed" };
        int max = 0;
        foreach (var f in findings.EnumerateArray())
        {
            int r = Array.IndexOf(order, f.GetProperty("tier").GetString());
            if (r > max) max = r;
        }
        return order[max];
    }

    // Load a sample DLL into the net48 victim and return the probe's top tier for it.
    private static string ScanNet48Sample(string sampleDll)
    {
        var (v, _) = AcquireTests.Lab();
        if (v == "") return "SKIP";
        Process victim = AcquireTests.StartVictim(v, sampleDll);
        try { return TopTier(RunProbe(victim.Id)); }
        finally { AcquireTests.StopVictim(victim); }
    }

    internal static string LabFile(params string[] parts)
        => Path.GetFullPath(Path.Combine(new[] { AppContext.BaseDirectory, "..", "..", "..", "..", "lab" }.Concat(parts).ToArray()));

    [Fact]
    public void MemoryEfficacyConfusionMatrix()
    {
        string memshell = LabFile("fixtures", "MemoryShell", "bin", "Release", "net48", "MemoryShell.dll");
        string benignPlugin = LabFile("fixtures", "BenignPlugin", "bin", "Release", "net48", "BenignPlugin.dll");
        if (!File.Exists(memshell) || !File.Exists(benignPlugin)) return; // lab not built — skip

        string malTier = ScanNet48Sample(memshell);
        string benTier = ScanNet48Sample(benignPlugin);
        if (malTier == "SKIP") return;

        // Detection: the IHttpHandler memshell must be at least likely-malicious.
        Assert.True(malTier == "likely-malicious" || malTier == "confirmed",
            $"malicious memshell must be likely/confirmed, got {malTier}");
        // FP discipline: the benign path-less plugin must NOT be malicious (suspicious is the
        // documented recall-biased outcome; likely/confirmed would be a false positive).
        Assert.True(benTier == "clean" || benTier == "suspicious",
            $"benign plugin must not be malicious, got {benTier}");

        Console.Error.WriteLine($"MEM efficacy (net48): memshell={malTier} benign-plugin={benTier}");
    }

    // Load a net8 sample into the net8 victim and return the probe's top tier.
    private static string ScanNet8Sample(string sampleDll)
    {
        string victim8 = LabFile("core", "victim8", "bin", "Release", "net8.0", "Victim8.exe");
        if (!File.Exists(victim8) || !File.Exists(sampleDll)) return "SKIP";
        string dir = Path.GetDirectoryName(victim8)!;
        File.Delete(Path.Combine(dir, "STOP"));
        File.Copy(sampleDll, Path.Combine(dir, "MemoryShell.dll"), overwrite: true);
        File.Delete(Path.Combine(dir, "victim_status.txt"));
        var p = Process.Start(new ProcessStartInfo(victim8) { UseShellExecute = false, CreateNoWindow = true })!;
        try
        {
            string status = Path.Combine(dir, "victim_status.txt");
            for (int i = 0; i < 100 && !File.Exists(status); i++) Thread.Sleep(100);
            Thread.Sleep(300);
            return TopTier(RunProbe(p.Id));
        }
        finally
        {
            try { File.WriteAllText(Path.Combine(dir, "STOP"), "x"); } catch { }
            try { if (!p.WaitForExit(3000)) p.Kill(); } catch { }
        }
    }

    // CHARACTERIZATION (Task 3): the convention middleware (no interface; capability hidden via
    // reflection + string concat) is recovered as a path-less module but currently UNDER-tiered at
    // `suspicious`. Asserting the current state keeps this commit GREEN and documents the gap;
    // Task 4 hardens the discriminator and flips this assertion to likely-malicious.
    [Fact]
    public void ConventionMiddlewareTier()
    {
        string mw = LabFile("core", "MwShell", "bin", "Release", "net8.0", "MwShell.dll");
        string tier = ScanNet8Sample(mw);
        if (tier == "SKIP") return;
        Console.Error.WriteLine($"MEM efficacy (net8 convention-mw): {tier}");
        Assert.True(tier == "likely-malicious" || tier == "confirmed",
            $"convention-middleware implant must be likely/confirmed after hardening, got {tier}");
    }

    [Fact]
    public void GodzillaVirtualPathProviderIsDetected()
    {
        string vpp = LabFile("fixtures", "GodzillaVirtualPathProvider", "bin", "Release", "net48", "GodzillaVirtualPathProvider.dll");
        string tier = ScanNet48Sample(vpp);
        if (tier == "SKIP") return; // lab victim not built — skip
        Console.Error.WriteLine($"MEM efficacy (net48 godzilla-vpp): {tier}");
        Assert.True(tier == "likely-malicious" || tier == "confirmed",
            $"GodzillaVirtualPathProvider must be likely/confirmed after VirtualPathProvider added to PipelineContracts, got {tier}");
    }
}
