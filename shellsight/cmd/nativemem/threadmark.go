package main

// markThreadStarts sets ThreadStart on every region that contains at least one thread's start
// address. A thread starting inside an unbacked region is strong corroboration of injected code.
func markThreadStarts(regions []Region, starts []uintptr) {
	for i := range regions {
		for _, s := range starts {
			if s >= regions[i].Base && s < regions[i].Base+regions[i].Size {
				regions[i].ThreadStart = true
				break
			}
		}
	}
}
