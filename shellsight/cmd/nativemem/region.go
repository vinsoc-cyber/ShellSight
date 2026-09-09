package main

// Region is a committed, EXECUTABLE memory region after classification — decoupled from the raw
// MEMORY_BASIC_INFORMATION so the discriminator is unit-testable without any syscall.
type Region struct {
	Base        uintptr // region base address
	Size        uintptr // region size in bytes
	Type        string  // "image" | "mapped" | "private"
	Protect     uint32  // raw PAGE_* protection
	Backed      bool    // executable bytes are backed by a known on-disk image module
	HasPEHeader bool    // first two bytes are "MZ" (a mapped PE)
	JITOwned    bool    // CLR-owned RX JIT code heap (set by filterJIT on managed processes)
	ThreadStart bool    // a thread's start address falls inside this region

	// Module-stomp / hollowing verdict (set by checkRegionStomp for backed executable regions).
	Stomped      bool     // in-memory code diverges wholesale from the on-disk module (hollowing)
	Patched      bool     // small/isolated in-memory code patch vs disk (inline hook)
	ModifiedFrac float64  // fraction of compared bytes that differ from disk (after rebasing)
	PatchRVAs    []uint32 // sample of differing RVAs (evidence)
}
