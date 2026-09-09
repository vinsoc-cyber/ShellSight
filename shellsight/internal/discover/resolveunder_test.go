package discover

// Spec 007 US1 / research R1: inside a filesystem mounted at --root, symbolic links are resolved as
// the SCANNED filesystem would resolve them. Before this, EvalSymlinks followed an absolute link
// inside an image into the scanning host's own filesystem, so whether an image's webroot was accepted
// depended on what the analyst's machine happened to have at the same path.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// symlinkOrSkip creates a symlink, skipping where the platform needs a privilege for it.
func symlinkOrSkip(t *testing.T, target, link string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("cannot create a symlink on this platform: %v", err)
	}
}

func TestAnAbsoluteSymlinkInsideAMountedImageIsResolvedInTheImage(t *testing.T) {
	// /var/www/html -> /srv/site, where /srv/site exists in the IMAGE and (almost certainly) not on
	// the scanning host. The root must be accepted on the image's evidence alone.
	root := t.TempDir()
	mustDir(t, filepath.Join(root, "srv", "site"))
	link := filepath.Join(root, "var", "www", "html")
	symlinkOrSkip(t, "/srv/site", link)

	res := assembleUnder(root, []Root{{Path: link, Mechanism: MechApacheConfig, Source: "/etc/apache2/apache2.conf"}}, nil)
	if len(res.Roots) != 1 || res.Roots[0].Path != link {
		t.Fatalf("a link resolvable inside the image must be accepted; got roots=%v rejected=%+v", res.Roots, res.Rejected)
	}
}

func TestAnAbsoluteSymlinkToTheImageRootIsRefusedByContainment(t *testing.T) {
	// The classic widening attack, written into the image: /var/www/html -> /. Judged against the
	// IMAGE's root, not ours.
	root := t.TempDir()
	link := filepath.Join(root, "var", "www", "html")
	symlinkOrSkip(t, "/", link)

	res := assembleUnder(root, []Root{{Path: link, Mechanism: MechNginxConfig, Source: "/etc/nginx/nginx.conf"}}, nil)
	if len(res.Roots) != 0 {
		t.Fatalf("a link to the image's root must not be scanned, got %v", res.Roots)
	}
	if len(res.Rejected) != 1 || !strings.Contains(res.Rejected[0].Reason, "the filesystem root is not a webroot") {
		t.Fatalf("want a containment rejection naming the filesystem root, got %+v", res.Rejected)
	}
}

func TestASymlinkToAnOSDirectoryInsideTheImageIsRefused(t *testing.T) {
	root := t.TempDir()
	mustDir(t, filepath.Join(root, "etc"))
	link := filepath.Join(root, "var", "www", "html")
	symlinkOrSkip(t, "/etc", link)

	res := assembleUnder(root, []Root{{Path: link, Mechanism: MechNginxConfig, Source: "/etc/nginx/nginx.conf"}}, nil)
	if len(res.Roots) != 0 || len(res.Rejected) != 1 || !strings.Contains(res.Rejected[0].Reason, "/etc is an operating-system directory") {
		t.Fatalf("want '/etc is an operating-system directory' inside the image, got roots=%v rejected=%+v", res.Roots, res.Rejected)
	}
}

func TestARelativeSymlinkEscapingTheImageIsRefused(t *testing.T) {
	root := t.TempDir()
	link := filepath.Join(root, "var", "www", "html")
	symlinkOrSkip(t, "../../../../..", link)

	res := assembleUnder(root, []Root{{Path: link, Mechanism: MechNginxConfig, Source: "/etc/nginx/nginx.conf"}}, nil)
	if len(res.Roots) != 0 || len(res.Rejected) != 1 || !strings.Contains(res.Rejected[0].Reason, "escapes the scanned filesystem root") {
		t.Fatalf("want an escape rejection, got roots=%v rejected=%+v", res.Roots, res.Rejected)
	}
}

func TestARelativeSymlinkInsideTheImageIsFollowedInPlace(t *testing.T) {
	root := t.TempDir()
	mustDir(t, filepath.Join(root, "srv", "site"))
	link := filepath.Join(root, "var", "www", "html")
	symlinkOrSkip(t, filepath.Join("..", "..", "srv", "site"), link)

	res := assembleUnder(root, []Root{{Path: link, Mechanism: MechApacheConfig, Source: "x"}}, nil)
	if len(res.Roots) != 1 {
		t.Fatalf("a relative link staying inside the image must be accepted; got roots=%v rejected=%+v", res.Roots, res.Rejected)
	}
}

func TestASymlinkLoopInsideTheImageTerminatesAndIsRefused(t *testing.T) {
	root := t.TempDir()
	a := filepath.Join(root, "a")
	b := filepath.Join(root, "b")
	symlinkOrSkip(t, "/b", a)
	symlinkOrSkip(t, "/a", b)

	res := assembleUnder(root, []Root{{Path: a, Mechanism: MechNginxConfig, Source: "x"}}, nil)
	if len(res.Roots) != 0 || len(res.Rejected) != 1 {
		t.Fatalf("a loop must be refused, got roots=%v rejected=%+v", res.Roots, res.Rejected)
	}
}

func TestOutsideTheRootResolutionIsUnchanged(t *testing.T) {
	// A proposal that does not lie under --root is judged as before, in this filesystem.
	root := t.TempDir()
	other := t.TempDir()
	res := assembleUnder(root, []Root{{Path: other, Mechanism: MechApacheConfig, Source: "x"}}, nil)
	if len(res.Roots) != 1 {
		t.Fatalf("a real directory outside the root is still a valid proposal; got %+v", res)
	}
}
