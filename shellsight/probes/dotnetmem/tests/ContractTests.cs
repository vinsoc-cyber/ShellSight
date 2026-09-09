using System.Text.Json;
using ShellSight.DotnetMem;
using Xunit;

public class ContractTests
{
    [Fact]
    public void FindingSerializesWithGoCompatibleNames()
    {
        var f = new Finding
        {
            SchemaVersion = "1.0",
            Id = "abc123-MemoryShell",
            Host = "WEB01",
            View = "dotnet-mem",
            Target = new Target { Kind = "process", Process = new ProcessRef { Pid = 4321, Name = "w3wp.exe" } },
            Artifact = new Artifact { Kind = "dotnet-memory-module", Identity = "MemoryShell", Location = "in-memory @ 0x1a2b0000" },
            Detection = new Detection { Basis = "structural-heuristic", KnowledgeRef = "heuristic:dotnet/pipeline-implant", Evidence = "implements IHttpHandler", Allowlisted = false },
            Score = 95,
            Tier = "likely-malicious",
        };
        string json = Contract.Serialize(new[] { f });

        using var doc = JsonDocument.Parse(json);
        JsonElement e = doc.RootElement[0];
        Assert.Equal("1.0", e.GetProperty("schema_version").GetString());
        Assert.Equal("dotnet-mem", e.GetProperty("view").GetString());
        Assert.Equal("process", e.GetProperty("target").GetProperty("kind").GetString());
        Assert.Equal(4321, e.GetProperty("target").GetProperty("process").GetProperty("pid").GetInt32());
        Assert.Equal("structural-heuristic", e.GetProperty("detection").GetProperty("basis").GetString());
        Assert.False(e.GetProperty("detection").GetProperty("allowlisted").GetBoolean());
        Assert.Equal("likely-malicious", e.GetProperty("tier").GetString());
        // Classification is the architected-in hook: present-but-null in v1.
        JsonElement c = e.GetProperty("classification");
        Assert.Equal(JsonValueKind.Null, c.GetProperty("family").ValueKind);
    }

    [Fact]
    public void TargetSpecDeserializesFromGoJson()
    {
        var spec = Contract.ParseSpec("""{"host":"WEB01","pids":[1234,5678],"dump_path":"C:\\dumps\\w3wp.dmp"}""");
        Assert.Equal("WEB01", spec.Host);
        Assert.Equal(new[] { 1234, 5678 }, spec.Pids);
        Assert.Equal(@"C:\dumps\w3wp.dmp", spec.DumpPath);
    }
}
