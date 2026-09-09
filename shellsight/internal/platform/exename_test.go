package platform

import (
	"runtime"
	"testing"
)

func TestExeNameAddsDotExeOnlyOnWindows(t *testing.T) {
	if got := ExeName("diskprobe", "windows"); got != "diskprobe.exe" {
		t.Errorf(`ExeName("diskprobe","windows") = %q, want "diskprobe.exe"`, got)
	}
	for _, goos := range []string{"linux", "darwin", "freebsd", "openbsd"} {
		if got := ExeName("diskprobe", goos); got != "diskprobe" {
			t.Errorf("ExeName(%q) = %q, want %q", goos, got, "diskprobe")
		}
	}
}

func TestExeNameIsIdempotentlyDerivedForTheHost(t *testing.T) {
	// A caller that passes runtime.GOOS must get the host's answer -- the property every resolver
	// depends on, and the one a hardcoded literal silently broke.
	want := "yr"
	if runtime.GOOS == "windows" {
		want = "yr.exe"
	}
	if got := ExeName("yr", runtime.GOOS); got != want {
		t.Errorf("ExeName(\"yr\", runtime.GOOS) = %q, want %q", got, want)
	}
}

func TestExeNameLeavesAnEmptyBaseAlone(t *testing.T) {
	// java-mem declares no bundled binary; appending ".exe" to "" would produce a resolvable-looking
	// path to a file that cannot exist.
	if got := ExeName("", "windows"); got != "" {
		t.Errorf(`ExeName("", "windows") = %q, want ""`, got)
	}
}
