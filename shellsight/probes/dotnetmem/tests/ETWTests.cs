using ShellSight.DotnetMem;
using Xunit;

public class ETWTests
{
    [Fact]
    public void ETWChannelCanBeCreatedAndDisposed()
    {
        // Smoke test: ETWChannel in stub mode (pid <= 0) constructs and disposes cleanly.
        // Actual ETW session tests require elevation and a live .NET process.
        using var ch = new ETWChannel(pid: -1, onEvent: _ => { });
        Assert.NotNull(ch);
    }
}
