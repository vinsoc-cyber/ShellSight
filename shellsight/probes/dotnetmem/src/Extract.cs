using Microsoft.Diagnostics.Runtime;

namespace ShellSight.DotnetMem;

public static class Extract
{
    // Read [ImageBase, ImageBase+Size) out of the target. For an Assembly.Load(byte[]) module the CLR
    // maps the image contiguously, so this reconstructs the LOADED (mapped) PE image.
    public static byte[] ReadModuleImage(DataTarget dt, ulong imageBase, ulong size)
    {
        if (imageBase == 0 || size == 0 || size > 256UL * 1024 * 1024)
            throw new ArgumentException($"implausible module range base=0x{imageBase:x} size={size}");

        // ClrMD's Read does SHORT reads (often one page), so loop page-by-page to fill the whole
        // range. Unreadable pages are left zero-filled (harmless for parsing a small mapped image).
        var buffer = new byte[size];
        const int PAGE = 0x1000;
        ulong off = 0;
        bool any = false;
        while (off < size)
        {
            int want = (int)Math.Min((ulong)PAGE, size - off);
            int n = dt.DataReader.Read(imageBase + off, buffer.AsSpan((int)off, want));
            if (n > 0) { any = true; off += (ulong)n; } // advance by bytes actually read (fill contiguously)
            else off += (ulong)PAGE;                     // nothing readable here — skip the page
        }
        if (!any)
            throw new InvalidOperationException("no bytes readable at ImageBase");
        return buffer;
    }

    // A mapped PE starts with 'MZ'.
    public static bool LooksLikePe(byte[] image) =>
        image.Length > 0x40 && image[0] == (byte)'M' && image[1] == (byte)'Z';
}
