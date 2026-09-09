package main

import "testing"

func TestIsExecutable(t *testing.T) {
	cases := []struct {
		prot uint32
		want bool
	}{
		{0x10, true}, {0x20, true}, {0x40, true}, {0x80, true}, // EXECUTE, _READ, _READWRITE, _WRITECOPY
		{0x110, true},                                          // EXECUTE | PAGE_GUARD(0x100)
		{0x01, false}, {0x02, false}, {0x04, false},            // NOACCESS, READONLY, READWRITE
	}
	for _, c := range cases {
		if got := isExecutable(c.prot); got != c.want {
			t.Errorf("isExecutable(0x%x)=%v want %v", c.prot, got, c.want)
		}
	}
}

func TestIsWritableExecute(t *testing.T) {
	cases := []struct {
		prot uint32
		want bool
	}{
		{0x40, true}, {0x80, true}, // _READWRITE, _WRITECOPY = W^X violation
		{0x20, false}, {0x10, false}, {0x04, false}, // _READ, EXECUTE, READWRITE(non-exec)
	}
	for _, c := range cases {
		if got := isWritableExecute(c.prot); got != c.want {
			t.Errorf("isWritableExecute(0x%x)=%v want %v", c.prot, got, c.want)
		}
	}
}

func TestProtString(t *testing.T) {
	if protString(0x40) != "RWX" {
		t.Errorf("protString(0x40)=%q want RWX", protString(0x40))
	}
	if protString(0x20) != "RX" {
		t.Errorf("protString(0x20)=%q want RX", protString(0x20))
	}
}
