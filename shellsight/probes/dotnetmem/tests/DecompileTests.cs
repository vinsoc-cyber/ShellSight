using ShellSight.DotnetMem;
using Xunit;

public class DecompileTests
{
    // A real on-disk DLL is a flat PE — perfect hermetic input (no dump/process needed).
    [Fact]
    public void LooksLikePeAndDecompilesOwnAssembly()
    {
        byte[] self = File.ReadAllBytes(typeof(DecompileTests).Assembly.Location);
        Assert.True(Extract.LooksLikePe(self));
        string cs = Decompile.ToCSharp(self, "self");
        Assert.Contains("DecompileTests", cs); // a type we defined
    }
}
