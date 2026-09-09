using System.Runtime.InteropServices;
namespace ShellSight.DotnetMem;

public enum SnResult { Valid, Invalid, Unknown }

public static class StrongName
{
    private const int SN_INFLAG_FORCE_VER = 0x1; // verify even if on the sn -Vr skip list

    [DllImport("mscoree.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int StrongNameSignatureVerificationFromImage(
        byte[] pbBase, int dwLength, int dwInFlags, out int pdwOutFlags);

    /// Verify the strong-name signature embedded in a carved assembly image.
    public static SnResult Verify(byte[] image)
    {
        if (image == null || image.Length == 0) return SnResult.Unknown;
        try
        {
            int hr = StrongNameSignatureVerificationFromImage(image, image.Length, SN_INFLAG_FORCE_VER, out _); // outFlags (SN_OUTFLAG_NO_SIGNATURE etc.) intentionally ignored — caller needs pass/fail only
            // The flat API returns TRUE(1)/FALSE(0); errors surface as HRESULTs <= 0 via Marshal.
            if (hr == 1) return SnResult.Valid;
            if (hr == 0) return SnResult.Invalid;
            return SnResult.Unknown; // error HRESULT — could not verify (corrupt image, bad PE, etc.)
        }
        catch (DllNotFoundException) { return SnResult.Unknown; }
        catch (EntryPointNotFoundException) { return SnResult.Unknown; }
    }
}
