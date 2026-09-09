package main

import "testing"

func TestFilterJIT(t *testing.T) {
	mk := func(prot uint32, pe, thread bool) Region {
		return Region{Type: "private", Protect: prot, HasPEHeader: pe, ThreadStart: thread}
	}
	t.Run("unmanaged filters nothing", func(t *testing.T) {
		rs := []Region{mk(0x20, false, false)} // RX private
		filterJIT(rs, false)
		if rs[0].JITOwned {
			t.Error("unmanaged process: nothing should be JIT-filtered")
		}
	})
	t.Run("managed RX private is filtered", func(t *testing.T) {
		rs := []Region{mk(0x20, false, false)}
		filterJIT(rs, true)
		if !rs[0].JITOwned {
			t.Error("managed RX private (no PE/thread) should be JIT-filtered")
		}
	})
	t.Run("RWX never filtered", func(t *testing.T) {
		rs := []Region{mk(0x40, false, false)} // RWX
		filterJIT(rs, true)
		if rs[0].JITOwned {
			t.Error("RWX must never be JIT-filtered")
		}
	})
	t.Run("PE header never filtered", func(t *testing.T) {
		rs := []Region{mk(0x20, true, false)}
		filterJIT(rs, true)
		if rs[0].JITOwned {
			t.Error("mapped PE must never be JIT-filtered")
		}
	})
	t.Run("thread-start never filtered", func(t *testing.T) {
		rs := []Region{mk(0x20, false, true)}
		filterJIT(rs, true)
		if rs[0].JITOwned {
			t.Error("thread-start region must never be JIT-filtered")
		}
	})
}
