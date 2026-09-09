using ShellSight.DotnetMem;
using Xunit;

public class ModuleScanTests
{
    // A candidate must be path-less AND have a recoverable in-memory PE image. Disk-backed modules
    // and image-less Reflection.Emit dynamics (ImageBase/Size == 0) are not candidates.
    [Fact]
    public void SuspiciousRequiresPathlessRecoverableImage()
    {
        var mods = new[]
        {
            new ModuleInfo(@"C:\app\bin\App.dll", 0x1000, 0x2000, false, true), // disk-backed -> no
            new ModuleInfo("RefEmitDynamic", 0, 0, true, false),                 // dynamic, no image -> no
            new ModuleInfo("XmlSerializers", 0, 0, true, false),                 // benign dynamic, no image -> no
            new ModuleInfo("MemShell", 0x1a2b0000, 0x8000, false, false),        // path-less + image -> YES
        };
        var s = ModuleScan.Suspicious(mods).ToList();
        Assert.Single(s);
        Assert.Equal("MemShell", s[0].Name);
    }
}
