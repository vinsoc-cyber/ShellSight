package main

import "testing"

func TestIsManaged(t *testing.T) {
	managed := []Module{{Name: "kernel32.dll"}, {Name: "coreclr.dll"}}
	native := []Module{{Name: "kernel32.dll"}, {Name: "iisutil.dll"}}
	if !isManaged(managed) {
		t.Error("coreclr.dll present -> isManaged should be true")
	}
	if isManaged(native) {
		t.Error("no CLR module -> isManaged should be false")
	}
}

func TestBackedBy(t *testing.T) {
	mods := []Module{{Name: "a.dll", Base: 0x1000, Size: 0x1000}} // covers [0x1000,0x2000)
	if !backedBy(0x1500, mods) {
		t.Error("0x1500 is inside [0x1000,0x2000) -> backed")
	}
	if backedBy(0x2000, mods) {
		t.Error("0x2000 is the exclusive end -> not backed")
	}
	if backedBy(0x500, mods) {
		t.Error("0x500 is below the module -> not backed")
	}
	if backedBy(0x1500, nil) {
		t.Error("empty module list -> not backed")
	}
}

func TestBackingModule(t *testing.T) {
	mods := []Module{{Name: "a.dll", Base: 0x1000, Size: 0x1000}, {Name: "b.dll", Base: 0x5000, Size: 0x1000}}
	if m := backingModule(0x1500, mods); m == nil || m.Name != "a.dll" {
		t.Fatalf("0x1500 must resolve to a.dll, got %v", m)
	}
	if m := backingModule(0x9999, mods); m != nil {
		t.Errorf("unbacked addr must resolve to nil, got %v", m)
	}
}
