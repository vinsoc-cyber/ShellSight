package main

// filterJIT marks CLR JIT code heaps as JIT-owned on managed processes so the discriminator
// allowlists them, cutting RX-region noise. Heuristic (MVP): on a managed process, an unbacked
// region that is RX (not RWX), without a PE header, and without a thread starting inside it is a
// JIT code heap. RWX, mapped-PE, and thread-start regions are NEVER filtered (W^X-as-escalator),
// so real implants still escalate. Nothing is filtered on unmanaged processes. Must run AFTER
// scanRegions (sets HasPEHeader) and markThreadStarts (sets ThreadStart), BEFORE assess.
func filterJIT(regions []Region, managed bool) {
	if !managed {
		return
	}
	for i := range regions {
		r := &regions[i]
		if r.Backed || r.JITOwned {
			continue
		}
		if isWritableExecute(r.Protect) || r.HasPEHeader || r.ThreadStart {
			continue // an escalator is present — never suppress
		}
		r.JITOwned = true // RX, no PE, no thread, managed -> JIT code heap
	}
}
