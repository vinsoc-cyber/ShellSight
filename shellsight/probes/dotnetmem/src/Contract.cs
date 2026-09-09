using System.Text.Json;
using System.Text.Json.Serialization;

namespace ShellSight.DotnetMem;

// The input half of the probe contract (mirrors Go finding.TargetSpec).
public sealed class TargetSpec
{
    [JsonPropertyName("host")] public string Host { get; set; } = "";
    [JsonPropertyName("pids")] public int[]? Pids { get; set; }
    [JsonPropertyName("webroots")] public string[]? Webroots { get; set; }
    [JsonPropertyName("dump_path")] public string DumpPath { get; set; } = "";
}

// The output half (mirrors Go finding.Finding). JSON property names == Go json tags.
public sealed class Finding
{
    [JsonPropertyName("schema_version")] public string SchemaVersion { get; set; } = "1.0";
    [JsonPropertyName("id")] public string Id { get; set; } = "";
    [JsonPropertyName("host")] public string Host { get; set; } = "";
    [JsonPropertyName("view")] public string View { get; set; } = "dotnet-mem";
    [JsonPropertyName("target")] public Target Target { get; set; } = new();
    [JsonPropertyName("artifact")] public Artifact Artifact { get; set; } = new();
    [JsonPropertyName("detection")] public Detection Detection { get; set; } = new();
    [JsonPropertyName("score")] public int Score { get; set; }
    [JsonPropertyName("tier")] public string Tier { get; set; } = "suspicious";
    [JsonPropertyName("classification")] public Classification Classification { get; set; } = new();
    [JsonPropertyName("artifacts")] public Artifacts Artifacts { get; set; } = new();
    [JsonPropertyName("context")] public Dictionary<string, string>? Context { get; set; }
}

public sealed class Target
{
    [JsonPropertyName("kind")] public string Kind { get; set; } = "process";
    [JsonPropertyName("process")] public ProcessRef? Process { get; set; }
    [JsonPropertyName("file")] public FileRef? File { get; set; }
}
public sealed class ProcessRef
{
    [JsonPropertyName("pid")] public int Pid { get; set; }
    [JsonPropertyName("name")] public string Name { get; set; } = "";
    [JsonPropertyName("app_pool")] [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)] public string AppPool { get; set; } = "";
    [JsonPropertyName("bitness")] [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)] public string Bitness { get; set; } = "";
}
public sealed class FileRef
{
    [JsonPropertyName("path")] public string Path { get; set; } = "";
    [JsonPropertyName("sha256")] public string Sha256 { get; set; } = "";
}
public sealed class Artifact
{
    [JsonPropertyName("kind")] public string Kind { get; set; } = "";
    [JsonPropertyName("identity")] public string Identity { get; set; } = "";
    [JsonPropertyName("location")] public string Location { get; set; } = "";
}
public sealed class Detection
{
    [JsonPropertyName("basis")] public string Basis { get; set; } = "structural-heuristic";
    [JsonPropertyName("knowledge_ref")] public string KnowledgeRef { get; set; } = "";
    [JsonPropertyName("evidence")] public string Evidence { get; set; } = "";
    [JsonPropertyName("allowlisted")] public bool Allowlisted { get; set; }
}
// The architected-in hook: always emitted, always null in v1 (stable schema for the future classifier).
public sealed class Classification
{
    [JsonPropertyName("family")] public string? Family { get; set; }
    [JsonPropertyName("capability")] public string[]? Capability { get; set; }
    [JsonPropertyName("source")] public string? Source { get; set; }
    [JsonPropertyName("confidence")] public double Confidence { get; set; }
}
public sealed class Artifacts
{
    [JsonPropertyName("raw")] [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)] public string Raw { get; set; } = "";
    [JsonPropertyName("decompiled")] [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)] public string Decompiled { get; set; } = "";
    [JsonPropertyName("features")] [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)] public string Features { get; set; } = "";
}

public static class Contract
{
    private static readonly JsonSerializerOptions Opts = new()
    {
        // Property names are set explicitly via [JsonPropertyName]; do not auto-rename.
        DefaultIgnoreCondition = JsonIgnoreCondition.Never, // classification nulls MUST be emitted
        WriteIndented = false,
    };
    private static readonly JsonSerializerOptions ParseOpts = new() { PropertyNameCaseInsensitive = true };

    public static string Serialize(IEnumerable<Finding> findings) => JsonSerializer.Serialize(findings, Opts);
    public static TargetSpec ParseSpec(string json) =>
        string.IsNullOrWhiteSpace(json) ? new TargetSpec() : (JsonSerializer.Deserialize<TargetSpec>(json, ParseOpts) ?? new TargetSpec());
}
