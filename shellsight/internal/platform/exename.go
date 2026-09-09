// Package platform holds the handful of facts about the host operating system that more than one
// command needs to agree on.
//
// It exists for exactly one reason: the executable-extension rule had been written out by hand at
// every site that resolved a bundled component, and every one of those sites hardcoded the WINDOWS
// answer. The result was a detector that cross-compiles cleanly, produces byte-identical findings on
// Linux (2026-08-20 parity: 0 differences across 29,962 files), and still could not start there,
// because its resolver was looking for `diskprobe.exe`. Three copies of a four-line rule is three
// chances for one of them to keep the old answer.
package platform

// ExeName applies the platform's executable extension to a base name.
//
// The base name must carry no extension of its own -- callers declare `diskprobe`, never
// `diskprobe.exe` -- so that the platform answer is produced in one place rather than assumed.
func ExeName(base, goos string) string {
	// A capability launched by an external runtime (java-mem, through a JVM) declares no bundled
	// binary. Appending the extension here would manufacture a resolvable-looking ".exe" path to a
	// file that cannot exist, and the caller's own emptiness guard would be the only thing standing
	// between that and a confusing "component missing" error.
	if base == "" {
		return ""
	}
	if goos == "windows" {
		return base + ".exe"
	}
	return base
}
