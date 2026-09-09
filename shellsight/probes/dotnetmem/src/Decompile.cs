using System.Reflection.PortableExecutable;
using ICSharpCode.Decompiler;
using ICSharpCode.Decompiler.CSharp;
using ICSharpCode.Decompiler.Metadata;
using DecompilerPEFile = ICSharpCode.Decompiler.Metadata.PEFile;

namespace ShellSight.DotnetMem;

public static class Decompile
{
    // The bytes from Extract may be MAPPED (sections at virtual offsets) or FLAT, so try both.
    public static string ToCSharp(byte[] image, string assemblyName = "extracted")
    {
        Exception? last = null;
        foreach (var opts in new[]
                 {
                     PEStreamOptions.PrefetchEntireImage,                                 // flat layout (Assembly.Load(byte[]))
                     PEStreamOptions.PrefetchEntireImage | PEStreamOptions.IsLoadedImage  // mapped layout
                 })
        {
            try
            {
                var peReader = new PEReader(new MemoryStream(image, writable: false), opts);
                var peFile = new DecompilerPEFile(assemblyName, peReader);
                var resolver = new UniversalAssemblyResolver(assemblyName, throwOnError: false, peFile.DetectTargetFrameworkId());
                return new CSharpDecompiler(peFile, resolver, new DecompilerSettings()).DecompileWholeModuleAsString();
            }
            catch (Exception ex) { last = ex; }
        }
        throw new InvalidOperationException("decompile failed for both mapped and flat layouts", last);
    }
}
