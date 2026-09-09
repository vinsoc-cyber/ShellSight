#if !NET5_0_OR_GREATER
// Polyfills that let the net8-era probe source compile on net462 (.NET Framework 4.6.2).
// Guarded to pre-net5 so a future multi-target to net5+/net8 (where these all exist in-box) stays clean.
using System;
using System.Security.Cryptography;
using System.Text;

namespace System.Runtime.CompilerServices
{
    // Positional `record` types emit init-only setters that reference this type, which net4x lacks.
    internal static class IsExternalInit { }
}

namespace ShellSight.DotnetMem
{
    // SHA1.HashData / SHA256.HashData / Convert.ToHexString are net5+ static one-shots; reimplement for net462.
    internal static class Net462Compat
    {
        public static byte[] Sha1(byte[] data)
        {
            using var algo = SHA1.Create();
            return algo.ComputeHash(data);
        }

        public static byte[] Sha256(byte[] data)
        {
            using var algo = SHA256.Create();
            return algo.ComputeHash(data);
        }

        // Lowercase hex, matching the prior `Convert.ToHexString(...).ToLowerInvariant()` call sites.
        public static string ToHex(byte[] data)
        {
            var sb = new StringBuilder(data.Length * 2);
            foreach (byte b in data) sb.Append(b.ToString("x2"));
            return sb.ToString();
        }
    }

    // Restores the net5+ `string.Contains(string, StringComparison)` overload the source relies on
    // (net462's string has only Contains(string)). Not a char overload — that would collide with LINQ's
    // Enumerable.Contains over IEnumerable<char>; char call sites use IndexOf instead.
    internal static class StringCompatExtensions
    {
        public static bool Contains(this string s, string value, StringComparison comparison)
            => s.IndexOf(value, comparison) >= 0;
    }
}
#endif
