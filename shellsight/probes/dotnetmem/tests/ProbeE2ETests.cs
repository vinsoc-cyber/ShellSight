using System.Diagnostics;
using System.Text.Json;
using Xunit;

public class ProbeE2ETests
{
    [Fact]
    public void DetectsLiveMemshellAsLikelyMalicious()
    {
        var (v, m) = AcquireTests.Lab();
        if (v == "") return; // lab not built — skip
        Process victim = AcquireTests.StartVictim(v, m);
        try
        {
            var (outp, code) = ProbeHarness.Run($$"""{"host":"WEB01","pids":[{{victim.Id}}]}""");
            Assert.Equal(0, code);
            using var doc = JsonDocument.Parse(outp);
            var likely = doc.RootElement.EnumerateArray()
                .Where(f => f.GetProperty("view").GetString() == "dotnet-mem"
                         && f.GetProperty("tier").GetString() == "likely-malicious").ToList();
            Assert.NotEmpty(likely);
            Assert.Contains(likely, f => f.GetProperty("artifact").GetProperty("identity").GetString()!.Contains("MemoryShell"));
            Assert.Contains(likely, f => f.GetProperty("detection").GetProperty("evidence").GetString()!.Contains("IHttpHandler"));
        }
        finally { AcquireTests.StopVictim(victim); }
    }

    [Fact]
    public void BogusPidIsCoverageFailureNotSilentClean()
    {
        var (outp, code) = ProbeHarness.Run("""{"host":"WEB01","pids":[2147483632]}""");
        Assert.NotEqual(0, code); // non-zero => core marks the view failed, never a silent clean
    }
}
