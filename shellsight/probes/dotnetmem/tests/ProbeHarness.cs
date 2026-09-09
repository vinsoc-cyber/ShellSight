using System.Diagnostics;

// Shared helper for the live-attach E2E tests (ProbeE2ETests, ReachabilityE2ETests): locate the built
// dotnet-mem probe exe and run it with a TargetSpec on stdin.
internal static class ProbeHarness
{
    // Run the built probe exe with a TargetSpec on stdin; return (stdout, exitCode).
    public static (string outp, int code) Run(string spec)
    {
        string exe = ResolveProbeExe();
        var psi = new ProcessStartInfo(exe) { RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false };
        using var p = Process.Start(psi)!;
        p.StandardInput.Write(spec); p.StandardInput.Close();
        string o = p.StandardOutput.ReadToEnd();
        p.WaitForExit(30000);
        return (o, p.ExitCode);
    }

    // Locate the built probe exe regardless of platform/TFM layout. The probe builds to
    // src\bin\<x64|x86>\Release\net462\dotnetmem.exe (Platforms=x64;x86, net462), so a hardcoded
    // relative path is brittle. Walk up to the probe root, search src\bin, and prefer the test's bitness.
    public static string ResolveProbeExe()
    {
        DirectoryInfo? dir = new(AppContext.BaseDirectory);
        while (dir != null && !Directory.Exists(Path.Combine(dir.FullName, "src", "bin")))
            dir = dir.Parent;
        if (dir == null)
            throw new FileNotFoundException("could not locate the dotnetmem probe root (src\\bin) from " + AppContext.BaseDirectory);
        string srcBin = Path.Combine(dir.FullName, "src", "bin");
        string[] matches = Directory.GetFiles(srcBin, "dotnetmem.exe", SearchOption.AllDirectories);
        if (matches.Length == 0)
            throw new FileNotFoundException("dotnetmem.exe not built under " + srcBin + " — build the probe (Release) first");
        // Prefer the test's bitness; among those pick the MOST RECENTLY BUILT, so a stale older-platform
        // build (e.g. a pre-feature x64\Debug) can never shadow a fresh one and silently run an old probe.
        string wantPlat = Environment.Is64BitProcess ? "x64" : "x86";
        string[] pool = matches.Where(p => p.Replace('/', '\\').Contains("\\" + wantPlat + "\\")).ToArray();
        if (pool.Length == 0) pool = matches;
        return pool.OrderByDescending(File.GetLastWriteTimeUtc).First();
    }
}
