package main

import "testing"

func TestMarkThreadStarts(t *testing.T) {
	regions := []Region{
		{Base: 0x1000, Size: 0x1000}, // [0x1000,0x2000)
		{Base: 0x5000, Size: 0x1000}, // [0x5000,0x6000)
	}
	markThreadStarts(regions, []uintptr{0x1800, 0x9999}) // 0x1800 in region0; 0x9999 in neither
	if !regions[0].ThreadStart {
		t.Error("region0 contains a thread start (0x1800) -> ThreadStart should be true")
	}
	if regions[1].ThreadStart {
		t.Error("region1 contains no thread start -> ThreadStart should be false")
	}
}
