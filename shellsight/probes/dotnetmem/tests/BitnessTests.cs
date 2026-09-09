using System.Diagnostics;
using ShellSight.DotnetMem;
using Xunit;

// Task 5: a net462 probe is single-bitness. The x64 probe analyzes 64-bit w3wp; the x86 companion
// analyzes 32-bit app pools. These hermetic tests pin the bitness decision + P/Invoke (no IIS needed).
public class BitnessTests
{
    [Theory] // a probe analyzes ONLY its own bitness; the other bitness is deferred to the companion probe
    [InlineData(true,  false, true)]   // 64-bit probe + 64-bit worker -> analyze
    [InlineData(true,  true,  false)]  // 64-bit probe + 32-bit worker -> defer
    [InlineData(false, true,  true)]   // 32-bit probe + 32-bit worker -> analyze
    [InlineData(false, false, false)]  // 32-bit probe + 64-bit worker -> defer
    public void ProbeAnalyzesOnlyItsOwnBitness(bool probeIs64Bit, bool targetIs32Bit, bool expected)
        => Assert.Equal(expected, Acquire.ShouldAnalyze(probeIs64Bit, targetIs32Bit));

    [Fact] // IsWow64Process P/Invoke resolves a real process's bitness (the test host itself)
    public void DetectsCurrentProcessBitness()
    {
        bool ok = Acquire.TryGetProcessIs32Bit(Process.GetCurrentProcess().Id, out bool is32Bit);
        Assert.True(ok);
        Assert.Equal(!Environment.Is64BitProcess, is32Bit);
    }

    [Fact] // explicit pids are NOT bitness-filtered (operator named them); only auto-discovery defers
    public void ExplicitTargetsAreNotDeferred()
    {
        var spec = new TargetSpec { Pids = new[] { Process.GetCurrentProcess().Id } };
        var targets = Acquire.Resolve(spec, out bool explicitReq, out var deferred);
        Assert.True(explicitReq);
        Assert.Empty(deferred);
        Assert.Single(targets);
    }
}
