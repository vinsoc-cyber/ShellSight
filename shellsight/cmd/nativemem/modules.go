package main

// Module is a loaded module's identity + in-memory range.
type Module struct {
	Name string  // lowercased base name, e.g. "coreclr.dll"
	Path string  // full on-disk path
	Base uintptr // load address
	Size uintptr // image size in bytes
}

// isManaged reports whether the CLR is loaded (so the JIT filter should run).
func isManaged(mods []Module) bool {
	for _, m := range mods {
		switch m.Name {
		case "clr.dll", "coreclr.dll", "mscorwks.dll":
			return true
		}
	}
	return false
}

// backedBy reports whether addr falls within any loaded module's image range [Base, Base+Size).
func backedBy(addr uintptr, mods []Module) bool {
	for _, m := range mods {
		if m.Size > 0 && addr >= m.Base && addr < m.Base+m.Size {
			return true
		}
	}
	return false
}

// backingModule returns the loaded module whose image range [Base, Base+Size) contains addr, or
// nil. Sibling of backedBy, used to resolve a backed region to the module it must be diffed against.
func backingModule(addr uintptr, mods []Module) *Module {
	for i := range mods {
		m := &mods[i]
		if m.Size > 0 && addr >= m.Base && addr < m.Base+m.Size {
			return m
		}
	}
	return nil
}
