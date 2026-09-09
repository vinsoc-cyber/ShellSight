namespace ShellSight.DotnetMem;

using System.Collections.Concurrent;
using Microsoft.Diagnostics.NETCore.Client;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers.Clr;

/// <summary>
/// Listens to DotNETRuntimeRundown events for a target PID via EventPipe.
/// For each path-less CLR module (ModuleILPath empty = reflective/dynamic load),
/// invokes onEvent with the assembly name — supplementing ClrMD module enumeration.
/// </summary>
public sealed class ETWChannel : IDisposable
{
    private readonly CancellationTokenSource _cts = new();
    private Task? _task;

    public ETWChannel(int pid, Action<string> onEvent)
    {
        if (pid <= 0) return; // stub/test mode: no ETW session started

        _task = Task.Run(() =>
        {
            try { Run(pid, onEvent, _cts.Token); }
            catch (OperationCanceledException) { }
            catch (Exception ex) { Console.Error.WriteLine($"etw-channel: {ex.Message}"); }
        });
    }

    private static void Run(int pid, Action<string> onEvent, CancellationToken token)
    {
        // Loader keyword = 0x8: triggers LoaderAssemblyDCStop + LoaderModuleDCStop rundown events.
        const long LoaderKeyword = 0x8;
        var providers = new[]
        {
            new EventPipeProvider(
                "Microsoft-Windows-DotNETRuntimeRundown",
                System.Diagnostics.Tracing.EventLevel.Informational,
                LoaderKeyword)
        };
        try
        {
            var client = new DiagnosticsClient(pid); // does not implement IDisposable
            using var session = client.StartEventPipeSession(providers, requestRundown: true);
            using var source = new EventPipeEventSource(session.EventStream);

            var rundown = new ClrRundownTraceEventParser(source);

            // Collect assembly names by AssemblyID for correlation with module events.
            var asmNames = new ConcurrentDictionary<long, string>();
            rundown.LoaderAssemblyDCStop += evt =>
                asmNames.TryAdd(evt.AssemblyID, evt.FullyQualifiedAssemblyName ?? "");

            // Detect path-less modules: empty ModuleILPath = dynamic/reflective load.
            rundown.LoaderModuleDCStop += evt =>
            {
                if (token.IsCancellationRequested) { source.StopProcessing(); return; }
                if (string.IsNullOrEmpty(evt.ModuleILPath))
                {
                    string name = asmNames.TryGetValue(evt.AssemblyID, out var n) && !string.IsNullOrEmpty(n)
                        ? n
                        : $"dynamic-module-0x{evt.ModuleID:x}";
                    onEvent(name);
                }
            };

            // Cancel hook: stop the event source when the probe timeout fires.
            token.Register(() => { try { source.StopProcessing(); } catch { } });
            source.Process();
        }
        catch (Exception) when (!token.IsCancellationRequested)
        {
            // EventPipe unavailable (.NET Framework IIS, insufficient perms, etc.) — skip silently.
        }
    }

    public void Dispose()
    {
        _cts.Cancel();
        try { _task?.Wait(2000); } catch { }
        _cts.Dispose();
    }
}
