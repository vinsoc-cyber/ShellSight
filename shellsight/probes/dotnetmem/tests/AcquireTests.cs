using System.Diagnostics;
using ShellSight.DotnetMem;
using Xunit;

public class AcquireTests
{
    // Locate the built victim + a fresh memshell dll; "" if the lab isn't built (test then skips).
    internal static (string victimExe, string memshellDll) Lab()
    {
        string root = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "lab"));
        string v = Path.Combine(root, "victim", "bin", "Release", "net48", "Victim.exe");
        string m = Path.Combine(root, "fixtures", "MemoryShell", "bin", "Release", "net48", "MemoryShell.dll");
        return (File.Exists(v) && File.Exists(m)) ? (v, m) : ("", "");
    }

    // Start the victim with a fresh copy of the memshell beside it; return the running process.
    internal static Process StartVictim(string victimExe, string memshellDll)
    {
        string dir = Path.GetDirectoryName(victimExe)!;
        File.Delete(Path.Combine(dir, "STOP"));
        File.Delete(Path.Combine(dir, "victim_status.txt")); // clear stale readiness sentinel → no premature-attach race
        File.Copy(memshellDll, Path.Combine(dir, "MemoryShell.dll"), overwrite: true); // victim loads then deletes it
        var p = Process.Start(new ProcessStartInfo(victimExe) { UseShellExecute = false, CreateNoWindow = true })!;
        string status = Path.Combine(dir, "victim_status.txt");
        for (int i = 0; i < 100 && !File.Exists(status); i++) Thread.Sleep(100); // wait until it has loaded the shell
        Thread.Sleep(300);
        return p;
    }

    internal static void StopVictim(Process p)
    {
        try { File.WriteAllText(Path.Combine(Path.GetDirectoryName(p.MainModule!.FileName)!, "STOP"), "x"); } catch { }
        try { if (!p.WaitForExit(3000)) p.Kill(); } catch { }
    }

    [Fact]
    public void SnapshotAttachToLiveVictimYieldsRuntime()
    {
        var (v, m) = Lab();
        if (v == "") { return; } // lab not built — skip
        Process victim = StartVictim(v, m);
        try
        {
            using var dt = Acquire.Open(new AcquireTarget(victim.Id, "Victim.exe"), out string? err);
            Assert.Null(err);
            Assert.NotNull(dt);
            Assert.NotEmpty(dt!.ClrVersions);
        }
        finally { StopVictim(victim); }
    }

    [Fact]
    public void BogusPidFailsCleanly()
    {
        using var dt = Acquire.Open(new AcquireTarget(0x7FFFFFF0, "ghost.exe"), out string? err);
        Assert.NotNull(err);   // a failure reason, not a silent null-success
        Assert.Null(dt);
    }
}
