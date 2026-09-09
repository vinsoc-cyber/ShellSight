package main

// Windows PAGE_* memory protection constants (winnt.h). Defined here (not via x/sys) so this file
// stays portable and unit-testable on any OS.
const (
	pageExecute          = 0x10
	pageExecuteRead      = 0x20
	pageExecuteReadWrite = 0x40
	pageExecuteWriteCopy = 0x80
)

// isExecutable: any of the four execute protections, ignoring modifier bits (PAGE_GUARD 0x100,
// PAGE_NOCACHE 0x200, PAGE_WRITECOMBINE 0x400). The execute family occupies the 0xF0 nibble.
func isExecutable(prot uint32) bool {
	return prot&(pageExecute|pageExecuteRead|pageExecuteReadWrite|pageExecuteWriteCopy) != 0
}

// isWritableExecute: executable AND writable (W^X violation) — the primary escalation signal.
func isWritableExecute(prot uint32) bool {
	return prot&(pageExecuteReadWrite|pageExecuteWriteCopy) != 0
}

// protString renders a short protection label for evidence strings.
func protString(prot uint32) string {
	switch {
	case isWritableExecute(prot):
		return "RWX"
	case isExecutable(prot):
		return "RX"
	default:
		return "non-exec"
	}
}
