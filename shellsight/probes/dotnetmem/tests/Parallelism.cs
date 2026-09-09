using Xunit;

// The integration tests start/stop a real victim process in a shared lab directory (copying and
// deleting MemoryShell.dll, writing STOP). xUnit parallelizes across test classes by default, which
// makes those runs stomp on each other. Serialize the whole assembly — the suite is small and these
// tests spawn processes + attach a debugger, so deterministic serial execution is the right call.
[assembly: CollectionBehavior(DisableTestParallelization = true)]
