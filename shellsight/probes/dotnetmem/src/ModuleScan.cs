using Microsoft.Diagnostics.Runtime;

namespace ShellSight.DotnetMem;

public sealed record ModuleInfo(string Name, ulong ImageBase, ulong Size, bool IsDynamic, bool HasDiskPath);

public static class ModuleScan
{
    // Enumerate every managed module in the target and classify it.
    public static List<ModuleInfo> Enumerate(ClrRuntime runtime)
    {
        var result = new List<ModuleInfo>();
        foreach (ClrModule mod in runtime.EnumerateModules())
        {
            string name = mod.Name ?? "<null>";
            // A normal disk assembly has a real filesystem path in Name. An Assembly.Load(byte[])
            // module is dynamic OR has no resolvable on-disk file.
            bool hasDiskPath = !string.IsNullOrEmpty(name) && name.IndexOf('\\') >= 0 && File.Exists(name);
            result.Add(new ModuleInfo(name, mod.ImageBase, mod.Size, mod.IsDynamic, hasDiskPath));
        }
        return result;
    }

    // A recoverable memshell *candidate*: path-less AND backed by a contiguous in-memory PE image
    // (ImageBase/Size > 0). Assembly.Load(byte[]) memshells satisfy this (verified: IsDynamic is
    // false, the image is mapped). Reflection.Emit dynamic assemblies (ImageBase==0, no recoverable
    // PE) are EXCLUDED — they can't be carved or decompiled, so attempting them is pure noise and
    // they were never recoverable evidence anyway. The malicious/benign TIER is still decided by the
    // Discriminator, because benign apps also Assembly.Load(byte[]) (plugins, embedded assemblies).
    public static IEnumerable<ModuleInfo> Suspicious(IEnumerable<ModuleInfo> modules) =>
        modules.Where(m => !m.HasDiskPath && m.ImageBase != 0 && m.Size > 0);
}
