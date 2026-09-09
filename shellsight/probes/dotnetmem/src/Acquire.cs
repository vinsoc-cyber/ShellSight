using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Diagnostics.Runtime;

namespace ShellSight.DotnetMem;

// A thing to analyze: a live PID (snapshot) or a dump file. Named AcquireTarget (not Target) so it
// never collides with the contract's Target type in Program.cs.
public sealed record AcquireTarget(int Pid, string Name, bool IsDump = false, string DumpPath = "")
{
    public static AcquireTarget Dump(string path) => new(0, Path.GetFileName(path), true, path);
    public string Label => IsDump ? $"dump:{DumpPath}" : $"pid:{Pid}({Name})";
}

public static class Acquire
{
    // Open a DataTarget for the target. On failure returns null and sets err (NEVER a silent null-success).
    public static DataTarget? Open(AcquireTarget t, out string? err)
    {
        err = null;
        try
        {
            if (t.IsDump)
            {
                if (!File.Exists(t.DumpPath)) { err = $"dump not found: {t.DumpPath}"; return null; }
                return DataTarget.LoadDump(t.DumpPath);
            }
            // Live: low-impact PSS snapshot (clones the process; minimal pause). Needs same bitness and,
            // for a service in another session, elevation — both surface here as a failure reason.
            return DataTarget.CreateSnapshotAndAttach(t.Pid);
        }
        catch (Exception ex)
        {
            err = $"{t.Label}: {Classify(ex)}";
            return null;
        }
    }

    private static string Classify(Exception ex)
    {
        string m = ex.Message;
        if (m.Contains("Access is denied", StringComparison.OrdinalIgnoreCase) || m.Contains("0x5") || ex is UnauthorizedAccessException)
            return "access denied (run elevated / as the same or higher privilege; for a service account, SeDebugPrivilege)";
        if (m.Contains("32-bit", StringComparison.OrdinalIgnoreCase) || m.Contains("WOW64", StringComparison.OrdinalIgnoreCase))
            return "bitness mismatch (32-bit target needs the 32-bit probe, or provide a dump)";
        return ex.GetType().Name + ": " + m;
    }

    // Resolve the targets to analyze from the spec: dump > explicit pids > auto-discover w3wp.
    // requestedExplicit=true means the operator named a target (so 'none found' is a failure, not 'n/a').
    // deferred lists auto-discovered w3wp of the OTHER bitness, skipped for the companion probe (Task 5).
    public static List<AcquireTarget> Resolve(TargetSpec spec, out bool requestedExplicit, out List<string> deferred)
    {
        deferred = new List<string>();
        if (!string.IsNullOrWhiteSpace(spec.DumpPath)) { requestedExplicit = true; return new() { AcquireTarget.Dump(spec.DumpPath) }; }
        if (spec.Pids is { Length: > 0 })
        {
            // Operator named these explicitly — analyze exactly them; don't bitness-filter (a true
            // mismatch then surfaces via Open()/Classify, not a silent skip).
            requestedExplicit = true;
            return spec.Pids.Select(p => new AcquireTarget(p, SafeName(p))).ToList();
        }
        requestedExplicit = false;
        return DiscoverW3wp(out deferred);
    }

    // Auto-discover IIS workers, returning only those of THIS probe's bitness. Workers of the other
    // bitness are skipped and recorded in `deferred` (the x86/x64 companion probe covers them) — never
    // silently dropped. Bitness we can't determine (e.g. access denied) is INCLUDED, so we attempt
    // analysis rather than miss a worker; a real mismatch then surfaces via Open()/Classify.
    private static List<AcquireTarget> DiscoverW3wp(out List<string> deferred)
    {
        deferred = new List<string>();
        var targets = new List<AcquireTarget>();
        bool probe64 = Environment.Is64BitProcess;
        foreach (Process p in Process.GetProcessesByName("w3wp"))
        {
            try
            {
                if (TryGetProcessIs32Bit(p.Id, out bool is32Bit) && !ShouldAnalyze(probe64, is32Bit))
                {
                    string bits = is32Bit ? "32-bit" : "64-bit";
                    string sibling = is32Bit ? "dotnet-mem-x86" : "dotnet-mem (x64)";
                    deferred.Add($"w3wp pid {p.Id} is {bits}; deferred to the {sibling} probe");
                    continue;
                }
                targets.Add(new AcquireTarget(p.Id, "w3wp.exe"));
            }
            finally { p.Dispose(); }
        }
        return targets;
    }

    // A single-bitness probe analyzes only same-bitness targets. 64-bit Windows assumed (Server 2016+):
    // a WOW64 process is 32-bit, otherwise 64-bit.
    public static bool ShouldAnalyze(bool probeIs64Bit, bool targetIs32Bit) => probeIs64Bit != targetIs32Bit;

    // Determine a process's bitness via IsWow64Process. Returns false if it can't be queried (the caller
    // then attempts analysis rather than skipping). Uses PROCESS_QUERY_LIMITED_INFORMATION so it works
    // for cross-session service workers when the probe is elevated.
    public static bool TryGetProcessIs32Bit(int pid, out bool is32Bit)
    {
        is32Bit = false;
        IntPtr h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (h == IntPtr.Zero) return false;
        try
        {
            if (!IsWow64Process(h, out bool wow64)) return false;
            is32Bit = wow64; // WOW64 == 32-bit process on 64-bit Windows
            return true;
        }
        finally { CloseHandle(h); }
    }

    private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsWow64Process(IntPtr hProcess, [MarshalAs(UnmanagedType.Bool)] out bool wow64Process);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr hObject);

    private static string SafeName(int pid)
    {
        try { using Process p = Process.GetProcessById(pid); return p.ProcessName + ".exe"; }
        catch { return "pid" + pid; }
    }
}
