using System.Text.Json;
using System.Text.Json.Serialization;

namespace ShellSight.DotnetMem;

// Mirrors the JSON structure of kb/rules/mem-contracts.json.
// Missing/null sections mean "use compiled-in defaults".
sealed record DotnetSection(
    [property: JsonPropertyName("pipeline_contracts")]    IReadOnlyList<string>? PipelineContracts,
    [property: JsonPropertyName("capability_apis")]       IReadOnlyList<string>? CapabilityApis,
    [property: JsonPropertyName("string_needles")]        IReadOnlyList<string>? StringNeedles,
    [property: JsonPropertyName("framework_public_keys")] IReadOnlyList<string>? FrameworkPublicKeys);

sealed record MemContractsFile(
    [property: JsonPropertyName("dotnet")] DotnetSection? Dotnet);

static class MemContractsLoader
{
    static readonly JsonSerializerOptions Opts = new() { PropertyNameCaseInsensitive = true };

    public static MemContractsFile? TryLoad(string? path)
    {
        if (string.IsNullOrEmpty(path) || !File.Exists(path)) return null;
        try
        {
            string json = File.ReadAllText(path);
            return JsonSerializer.Deserialize<MemContractsFile>(json, Opts);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"dotnetmem: mem-contracts: {ex.Message} — using compiled-in defaults");
            return null;
        }
    }

    // Resolve --mem-contracts arg; fall back to binary-relative kb/rules/mem-contracts.json.
    public static string? ResolvePath(string[] args)
    {
        for (int i = 0; i < args.Length - 1; i++)
            if (args[i] == "--mem-contracts") return args[i + 1];
        string? exeDir = Path.GetDirectoryName(
            System.Diagnostics.Process.GetCurrentProcess().MainModule?.FileName);
        if (exeDir == null) return null;
        string candidate = Path.Combine(exeDir, "kb", "rules", "mem-contracts.json");
        return File.Exists(candidate) ? candidate : null;
    }
}
