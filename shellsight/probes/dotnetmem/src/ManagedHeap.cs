using Microsoft.Diagnostics.Runtime;

namespace ShellSight.DotnetMem;

// A handle to a managed object in the heap abstraction. Opaque to the pure walk; both FakeHeap and
// ClrMdHeap materialize it with the object's type name and the image base of its type's module
// (BackingImageBase == 0 means path-less / unresolved). Equality is by all fields (Address is unique
// per object, so this behaves as identity for seen-sets).
public readonly record struct ClrObjectRef(ulong Address, string TypeName, ulong BackingImageBase);

// The minimal heap surface the reachability walk needs. Implemented by ClrMdHeap (live) and FakeHeap
// (tests). Read operations return null on a missing/null edge — the walk treats null as "chain ends".
public interface IManagedHeap
{
    ClrObjectRef? ReadStaticObject(string typeName, string fieldName);
    ClrObjectRef? ReadInstanceObject(ClrObjectRef obj, string fieldName);
    // Objects whose type is typeName OR derives from it (subclass-aware; see ClrMdHeap / WalkModules).
    IEnumerable<ClrObjectRef> InstancesOf(string typeName);
    IEnumerable<ClrObjectRef> EnumerateItems(ClrObjectRef collection);
    bool HasField(ClrObjectRef obj, string fieldName);
}

// Live IManagedHeap over a ClrRuntime. Read-only: every operation reads the already-acquired heap;
// nothing is injected into the target. Resolution failures return null/empty (the walk falls open).
// NOTE (Win11 first-build): verify the ClrMD 4.x member names used here — GetTypeByName, StaticFields
// /ReadObject(domain), ReadObjectField, AsArray()/GetObjectValue. Adjust if the build flags them.
public sealed class ClrMdHeap : IManagedHeap
{
    private readonly ClrRuntime _runtime;
    private readonly ClrHeap _heap;
    public ClrMdHeap(ClrRuntime runtime) { _runtime = runtime; _heap = runtime.Heap; }

    private ClrType? FindType(string typeName)
    {
        foreach (ClrModule m in _runtime.EnumerateModules())
        {
            try { ClrType? t = m.GetTypeByName(typeName); if (t != null) return t; }
            catch { /* module without this type */ }
        }
        return null;
    }

    private static ClrObjectRef Ref(ClrObject o) =>
        new ClrObjectRef(o.Address, o.Type?.Name ?? "", o.Type?.Module?.ImageBase ?? 0);

    public ClrObjectRef? ReadStaticObject(string typeName, string fieldName)
    {
        ClrType? t = FindType(typeName);
        ClrStaticField? sf = t?.GetStaticFieldByName(fieldName);
        if (sf == null) return null;
        foreach (ClrAppDomain dom in _runtime.AppDomains)
        {
            try
            {
                ClrObject o = sf.ReadObject(dom);
                if (!o.IsNull && o.Type != null) return Ref(o);
            }
            catch { /* not initialized in this domain */ }
        }
        return null;
    }

    public ClrObjectRef? ReadInstanceObject(ClrObjectRef obj, string fieldName)
    {
        try
        {
            ClrObject o = _heap.GetObject(obj.Address).ReadObjectField(fieldName);
            return (!o.IsNull && o.Type != null) ? Ref(o) : (ClrObjectRef?)null;
        }
        catch { return null; }
    }

    // Instances whose type IS typeName OR derives from it. Real ASP.NET apps subclass HttpApplication
    // (the Global.asax-generated type), so the module walk must match subclasses — an exact-name match
    // finds zero HttpApplication instances in a real w3wp (live-IIS validated 2026-06-21).
    public IEnumerable<ClrObjectRef> InstancesOf(string typeName)
    {
        foreach (ClrObject o in _heap.EnumerateObjects())
            for (ClrType? t = o.Type; t != null; t = t.BaseType)
                if (t.Name == typeName) { yield return Ref(o); break; }
    }

    // Enumerate a managed collection's elements. A raw List<T> exposes _items/_size directly; wrapper
    // collections hold the backing list one hop in: Collection<T> -> "items"; GlobalFilterCollection ->
    // "_filters". Walk up to 3 hops to reach an object exposing _items, then read _items/_size.
    // (HttpModuleCollection : NameObjectCollectionBase has a different shape — handled in Tier 2.)
    // Field names are System.Web/BCL internals — verify live if a chain returns empty.
    public IEnumerable<ClrObjectRef> EnumerateItems(ClrObjectRef collection)
    {
        ClrObject listObj;
        try { listObj = _heap.GetObject(collection.Address); } catch { yield break; }
        for (int hop = 0; hop < 3 && !HasFieldOn(listObj, "_items"); hop++)
        {
            ClrObject inner = default;
            foreach (string f in new[] { "items", "_filters", "_list" })
            {
                if (!HasFieldOn(listObj, f)) continue;
                try { inner = listObj.ReadObjectField(f); } catch { }
                if (!inner.IsNull) break;
            }
            if (inner.IsNull)
            {
                // NameObjectCollectionBase shape (HttpModuleCollection): entries in _entriesArray (ArrayList);
                // each entry's Value is the module. Verify field names live if modules are not reached.
                ClrObject entries = default;
                try { entries = listObj.ReadObjectField("_entriesArray"); } catch { }
                if (entries.IsNull) yield break;
                ClrObject inner2 = default;
                try { inner2 = entries.ReadObjectField("_items"); } catch { } // ArrayList backing array
                if (inner2.IsNull) yield break;
                ClrArray ea;
                try { ea = inner2.AsArray(); } catch { yield break; }
                for (int i = 0; i < ea.Length; i++)
                {
                    ClrObjectRef? r = null;
                    try
                    {
                        ClrObject entry = ea.GetObjectValue(i);
                        if (!entry.IsNull) { ClrObject val = entry.ReadObjectField("Value"); if (!val.IsNull && val.Type != null) r = Ref(val); }
                    }
                    catch { }
                    if (r != null) yield return r.Value;
                }
                yield break;
            }
            listObj = inner;
        }
        ClrObject itemsObj;
        try { itemsObj = listObj.ReadObjectField("_items"); } catch { yield break; }
        if (itemsObj.IsNull) yield break;
        ClrArray arr;
        try { arr = itemsObj.AsArray(); } catch { yield break; }
        int size;
        try { size = listObj.ReadField<int>("_size"); } catch { size = arr.Length; }
        for (int i = 0; i < size && i < arr.Length; i++)
        {
            ClrObjectRef? r = null;
            try { ClrObject co = arr.GetObjectValue(i); if (!co.IsNull && co.Type != null) r = Ref(co); }
            catch { }
            if (r != null) yield return r.Value;
        }
    }

    private bool HasFieldOn(ClrObject o, string field)
    {
        try { return o.Type?.GetFieldByName(field) != null; } catch { return false; }
    }

    public bool HasField(ClrObjectRef obj, string fieldName)
    {
        try { return _heap.GetObjectType(obj.Address)?.GetFieldByName(fieldName) != null; }
        catch { return false; }
    }
}
