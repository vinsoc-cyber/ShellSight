using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using System.Security.Cryptography;
using System.Text;

namespace ShellSight.DotnetMem;

// What the discriminator reasons over. Pure data — extracted once, asserted hermetically.
public sealed record ModuleFacts(
    string AssemblyName,
    string? PublicKeyTokenHex,                 // null if not strong-named
    bool IsStrongNamed,
    IReadOnlyList<string> TypeFullNames,
    IReadOnlyList<string> Contracts,           // base types + interfaces (incl. resolved generic bases)
    IReadOnlyList<string> ReferencedApis,      // "Namespace.Type.Member" of referenced members
    IReadOnlyList<string> CapabilityStringHits,// capability needles found in the raw image (ASCII+UTF-16)
    bool ConventionMiddleware,                 // a type declares Invoke/InvokeAsync taking an HttpContext param (Core convention middleware — implements no interface)
    string? PublicKeyHex,                      // full public key blob as lowercase hex, or null if not strong-named
    bool StrongNameValid,                      // result of StrongName.Verify on the image
    IReadOnlyList<string> AttributeTypes       // full type-names of assembly- + type-level custom attributes (authenticates runtime-generated assemblies: e.g. RazorCompiledItem)
);

public static class Facts
{
    // Non-readonly: Configure() replaces this at startup when mem-contracts.json is present.
    private static string[] StringNeedles = { "cmd.exe", "powershell", "WScript.Shell", "/c ", "ProcessStartInfo" };

    public static void Configure(IReadOnlyList<string>? stringNeedles)
    {
        if (stringNeedles is { Count: > 0 }) StringNeedles = stringNeedles.ToArray();
    }

    public static ModuleFacts Parse(byte[] image)
    {
        MetadataReader mr = OpenMetadata(image, out PEReader _);
        string asmName; string? pkt = null; bool strong = false; string? pkHex = null;
        var attrTypes = new HashSet<string>(StringComparer.Ordinal);
        if (mr.IsAssembly)
        {
            AssemblyDefinition ad = mr.GetAssemblyDefinition();
            asmName = mr.GetString(ad.Name);
            byte[] pk = mr.GetBlobBytes(ad.PublicKey);
            if (pk.Length > 0) { strong = true; pkt = PublicKeyToken(pk); pkHex = Net462Compat.ToHex(pk); }
            CollectAttributeTypes(mr, ad.GetCustomAttributes(), attrTypes); // assembly-level (e.g. [assembly: RazorCompiledItem])
        }
        else
        {
            asmName = mr.GetString(mr.GetModuleDefinition().Name);
        }

        var types = new List<string>();
        var contracts = new HashSet<string>(StringComparer.Ordinal);
        bool conventionMw = false;
        foreach (TypeDefinitionHandle th in mr.TypeDefinitions)
        {
            TypeDefinition td = mr.GetTypeDefinition(th);
            types.Add(Join(mr.GetString(td.Namespace), mr.GetString(td.Name)));
            string? bt = TypeName(mr, td.BaseType);
            if (bt != null) contracts.Add(bt);
            foreach (InterfaceImplementationHandle iih in td.GetInterfaceImplementations())
            {
                string? n = TypeName(mr, mr.GetInterfaceImplementation(iih).Interface);
                if (n != null) contracts.Add(n);
            }
            CollectAttributeTypes(mr, td.GetCustomAttributes(), attrTypes); // type-level (e.g. [RazorSourceChecksum] on the view class)
            if (!conventionMw && DeclaresHttpContextInvoke(mr, td)) conventionMw = true;
        }

        var apis = new List<string>();
        foreach (MemberReferenceHandle mh in mr.MemberReferences)
        {
            MemberReference m = mr.GetMemberReference(mh);
            if (m.Parent.Kind == HandleKind.TypeReference)
            {
                TypeReference tr = mr.GetTypeReference((TypeReferenceHandle)m.Parent);
                apis.Add($"{Join(mr.GetString(tr.Namespace), mr.GetString(tr.Name))}.{mr.GetString(m.Name)}");
            }
        }

        var strHits = new List<string>();
        string ascii = Encoding.ASCII.GetString(image);
        string utf16 = Encoding.Unicode.GetString(image);
        foreach (string needle in StringNeedles)
            if (ascii.Contains(needle, StringComparison.OrdinalIgnoreCase) || utf16.Contains(needle, StringComparison.OrdinalIgnoreCase))
                strHits.Add(needle);

        bool snValid = StrongName.Verify(image) == SnResult.Valid;

        return new ModuleFacts(asmName, pkt, strong, types, contracts.ToList(), apis, strHits, conventionMw, pkHex, snValid, attrTypes.ToList());
    }

    // True if the type declares an Invoke/InvokeAsync method that takes an HttpContext (Core/classic) or
    // IOwinContext (Katana OWIN) parameter — the duck-typed convention-middleware contract (implements no
    // interface). Per-type + signature-precise: a delegate's Invoke (no matching param) and mere usage
    // elsewhere do NOT match, so this is a tight signal, not a name heuristic.
    private static bool DeclaresHttpContextInvoke(MetadataReader mr, TypeDefinition td)
    {
        foreach (MethodDefinitionHandle mh in td.GetMethods())
        {
            MethodDefinition md = mr.GetMethodDefinition(mh);
            string name = mr.GetString(md.Name);
            if (name != "Invoke" && name != "InvokeAsync") continue;
            try
            {
                MethodSignature<string> sig = md.DecodeSignature(new NameSigProvider(), null);
                foreach (string p in sig.ParameterTypes)
                    if (p == "Microsoft.AspNetCore.Http.HttpContext"
                        || p == "System.Web.HttpContext"
                        || p == "Microsoft.Owin.IOwinContext")
                        return true;
            }
            catch { /* unreadable signature — skip */ }
        }
        return false;
    }

    // Collect the full type-names of the custom attributes applied to an entity (assembly or type).
    // Used to AUTHENTICATE runtime-generated assemblies by a forgery-resistant marker rather than the
    // attacker-controlled assembly name: a real Razor view carries [RazorCompiledItem]/[RazorSourceChecksum].
    private static void CollectAttributeTypes(MetadataReader mr, CustomAttributeHandleCollection handles, HashSet<string> into)
    {
        foreach (CustomAttributeHandle h in handles)
        {
            try
            {
                CustomAttribute ca = mr.GetCustomAttribute(h);
                EntityHandle attrType = ca.Constructor.Kind switch
                {
                    HandleKind.MemberReference => mr.GetMemberReference((MemberReferenceHandle)ca.Constructor).Parent,
                    HandleKind.MethodDefinition => mr.GetMethodDefinition((MethodDefinitionHandle)ca.Constructor).GetDeclaringType(),
                    _ => default
                };
                string? n = TypeName(mr, attrType);
                if (n != null) into.Add(n);
            }
            catch { /* unreadable attribute ctor — skip */ }
        }
    }

    private static MetadataReader OpenMetadata(byte[] image, out PEReader pe)
    {
        Exception? last = null;
        foreach (var opts in new[] { PEStreamOptions.PrefetchEntireImage, PEStreamOptions.PrefetchEntireImage | PEStreamOptions.IsLoadedImage })
        {
            try { pe = new PEReader(new MemoryStream(image, writable: false), opts); return pe.GetMetadataReader(); }
            catch (Exception ex) { last = ex; }
        }
        throw new InvalidOperationException("no readable CLI metadata in image", last);
    }

    // ECMA-335 public key token = last 8 bytes of SHA1(publicKey), reversed.
    private static string PublicKeyToken(byte[] publicKey)
    {
        byte[] sha = Net462Compat.Sha1(publicKey);
        var tok = new byte[8];
        for (int i = 0; i < 8; i++) tok[i] = sha[sha.Length - 1 - i];
        return Net462Compat.ToHex(tok);
    }

    private static string Join(string ns, string name) => ns.Length > 0 ? ns + "." + name : name;

    private static string? TypeName(MetadataReader mr, EntityHandle h)
    {
        if (h.IsNil) return null;
        switch (h.Kind)
        {
            case HandleKind.TypeReference:
                TypeReference tr = mr.GetTypeReference((TypeReferenceHandle)h);
                return Join(mr.GetString(tr.Namespace), mr.GetString(tr.Name));
            case HandleKind.TypeDefinition:
                TypeDefinition td = mr.GetTypeDefinition((TypeDefinitionHandle)h);
                return Join(mr.GetString(td.Namespace), mr.GetString(td.Name));
            case HandleKind.TypeSpecification:
                return GenericTypeName(mr, (TypeSpecificationHandle)h);
            default:
                return null;
        }
    }

    // Resolve a generic instantiation (e.g. List<int>) to its generic type definition name, so a
    // generic pipeline base isn't silently dropped (TypeName returned null for these before).
    private static string? GenericTypeName(MetadataReader mr, TypeSpecificationHandle h)
    {
        try { return mr.GetTypeSpecification(h).DecodeSignature(new NameSigProvider(), null); }
        catch { return null; }
    }

    // Minimal ISignatureTypeProvider: we only need type NAMES (for contract matching), so a generic
    // instantiation collapses to the generic type's name and other shapes to their element.
    private sealed class NameSigProvider : System.Reflection.Metadata.ISignatureTypeProvider<string, object?>
    {
        public string GetGenericInstantiation(string genericType, System.Collections.Immutable.ImmutableArray<string> args) => genericType;
        public string GetTypeFromDefinition(MetadataReader r, TypeDefinitionHandle h, byte rawKind) { var td = r.GetTypeDefinition(h); return Join(r.GetString(td.Namespace), r.GetString(td.Name)); }
        public string GetTypeFromReference(MetadataReader r, TypeReferenceHandle h, byte rawKind) { var tr = r.GetTypeReference(h); return Join(r.GetString(tr.Namespace), r.GetString(tr.Name)); }
        public string GetTypeFromSpecification(MetadataReader r, object? gc, TypeSpecificationHandle h, byte rawKind) => "spec";
        public string GetSZArrayType(string e) => e;
        public string GetArrayType(string e, System.Reflection.Metadata.ArrayShape s) => e;
        public string GetByReferenceType(string e) => e;
        public string GetPointerType(string e) => e;
        public string GetGenericMethodParameter(object? gc, int i) => "T";
        public string GetGenericTypeParameter(object? gc, int i) => "T";
        public string GetModifiedType(string mod, string unmod, bool req) => unmod;
        public string GetPinnedType(string e) => e;
        public string GetPrimitiveType(System.Reflection.Metadata.PrimitiveTypeCode c) => c.ToString();
        public string GetFunctionPointerType(System.Reflection.Metadata.MethodSignature<string> si) => "fnptr";
    }
}
