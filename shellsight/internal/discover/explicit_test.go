package discover

// Spec 007 US1: the operator's own --path. Platform-neutral cases; the process-root-view cases that
// need a second mount namespace live in discovery_linux_test.go.

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAnAbsentExplicitPathKeepsItsRefusalReason(t *testing.T) {
	// FR-002: relaxing canonicalisation for explicit paths must not change what an absent path says.
	p := filepath.Join(t.TempDir(), "nope")
	res := assemble([]Root{{Path: p, Mechanism: MechExplicit}}, nil)
	if len(res.Roots) != 0 {
		t.Fatalf("an absent path must not be scanned, got %v", res.Roots)
	}
	if len(res.Rejected) != 1 || res.Rejected[0].Reason != reasonAbsent {
		t.Fatalf("want %q, got %+v", reasonAbsent, res.Rejected)
	}
}

func TestAnExplicitPathThatIsAFileIsRefusedAsNotADirectory(t *testing.T) {
	p := filepath.Join(t.TempDir(), "file.php")
	if err := os.WriteFile(p, []byte("<?php"), 0o644); err != nil {
		t.Fatal(err)
	}
	res := assemble([]Root{{Path: p, Mechanism: MechExplicit}}, nil)
	if len(res.Roots) != 0 || len(res.Rejected) != 1 || res.Rejected[0].Reason != "the path is not a directory" {
		t.Fatalf("want 'the path is not a directory', got roots=%v rejected=%+v", res.Roots, res.Rejected)
	}
}

func TestAnExplicitPathInsideRootIsReportedInBothNamespaces(t *testing.T) {
	// FR-004 / research R2: with --root, a discovered directory is shown both where it was scanned
	// and as the scanned host serves it. An explicit path inside the root earns the same second form.
	root := t.TempDir()
	www := filepath.Join(root, "srv", "www")
	if err := os.MkdirAll(www, 0o755); err != nil {
		t.Fatal(err)
	}
	res := Discover([]string{www}, Options{Root: root})
	if len(res.Roots) != 1 {
		t.Fatalf("want the explicit root, got roots=%v rejected=%+v", res.Roots, res.Rejected)
	}
	if res.Roots[0].Path != www {
		t.Fatalf("the scanned path must stay as typed, got %q", res.Roots[0].Path)
	}
	if res.Roots[0].InFilesystem != "/srv/www" {
		t.Fatalf("want served-as form /srv/www, got %q", res.Roots[0].InFilesystem)
	}
}

func TestAnExplicitPathOutsideRootHasNoServedAsForm(t *testing.T) {
	root := t.TempDir()
	other := t.TempDir()
	res := Discover([]string{other}, Options{Root: root})
	if len(res.Roots) != 1 || res.Roots[0].InFilesystem != "" {
		t.Fatalf("a path outside --root has no in-filesystem form, got %+v", res.Roots)
	}
}

func TestAnExplicitPathWithoutRootHasNoServedAsForm(t *testing.T) {
	// A live scan records one namespace, not the same one twice (offlineroot.go: rooted).
	dir := t.TempDir()
	res := Discover([]string{dir}, Options{})
	if len(res.Roots) != 1 || res.Roots[0].InFilesystem != "" {
		t.Fatalf("a live explicit path has no in-filesystem form, got %+v", res.Roots)
	}
}
