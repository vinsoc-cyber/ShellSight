using System.Runtime.InteropServices;
using ShellSight.DotnetMem;
using Xunit;

public class StrongNameTests
{
    [Fact]
    public void GenuineFrameworkAssemblyVerifies()
    {
        // On net462, typeof(object).Assembly.Location is mscorlib.dll — validly strong-name signed.
        string p = typeof(object).Assembly.Location;
        byte[] img = System.IO.File.ReadAllBytes(p);
        Assert.Equal(SnResult.Valid, StrongName.Verify(img));
    }

    [Fact]
    public void TamperedImageFailsVerification()
    {
        byte[] img = System.IO.File.ReadAllBytes(typeof(object).Assembly.Location);
        img[img.Length / 2] ^= 0xFF; // corrupt the body → signature must fail
        Assert.Equal(SnResult.Invalid, StrongName.Verify(img));
    }
}
