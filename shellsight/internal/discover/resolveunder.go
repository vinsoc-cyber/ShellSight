package discover

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Resolution and containment INSIDE a filesystem mounted at Options.Root, and the readability check
// that replaces canonicalisation for the operator's own path (spec 007 US1, research R1/R2).
//
// Two filesystems the scanner reads are not its own: an image or snapshot attached at a directory,
// and another container's root view at /proc/<pid>/root. In both, an absolute symlink target names
// the SCANNED host's `/`. filepath.EvalSymlinks does not know that -- it follows the link into the
// scanning host's filesystem, and for the /proc view it first collapses the magic link itself into
// `/`. Measured 2026-08-26: `--root /proc/616/root` discovered /var/www only because the WSL host
// happened to have /var/www as well; a conventional root that existed only inside the container
// would have been refused as "cannot be resolved", and the refusal would have depended on the
// scanning host's layout, not the target's.

// readableDir reports why a directory the operator named cannot be scanned, or "" when it can be
// opened and listed. Stat has already said it is a directory; this is the read permission Stat does
// not check -- a 0000 directory stats perfectly well and would otherwise reach the walk and report a
// clean scan of nothing.
func readableDir(abs string) string {
	f, err := os.Open(abs)
	if err != nil {
		return fmt.Sprintf("the directory cannot be read: %v", err)
	}
	defer f.Close()
	if _, err := f.Readdirnames(1); err != nil && !errors.Is(err, io.EOF) {
		return fmt.Sprintf("the directory cannot be read: %v", err)
	}
	return ""
}

// servedAs returns the path the scanned filesystem uses for abs when abs lies inside root: the form
// a discovered root already carries in InFilesystem, so an explicit --path inside --root reads the
// same way in the report.
func servedAs(root, abs string) (string, bool) {
	root = filepath.Clean(root)
	if !withinRoot(root, abs) {
		return "", false
	}
	rel, err := filepath.Rel(root, abs)
	if err != nil {
		return "", false
	}
	if rel == "." {
		return "/", true
	}
	return "/" + filepath.ToSlash(rel), true
}

// maxLinkHops bounds a symlink chain inside the scanned filesystem. Its configuration is
// attacker-writable, so a loop is a possibility, not a corner case; 40 is what the kernel allows.
const maxLinkHops = 40

// evalSymlinksUnder resolves abs the way the scanned filesystem would, treating root as its `/`:
// components below root are followed, a relative link target is joined to its directory, an absolute
// link target is re-rooted under root, and the root prefix itself -- on a process-root view the
// /proc/<pid>/root magic link -- is never resolved. Walking out of the root is an error (FR-037), and
// so is a chain deeper than maxLinkHops.
func evalSymlinksUnder(root, abs string) (string, error) {
	rel, err := filepath.Rel(root, abs)
	if err != nil {
		return "", err
	}
	work := splitPath(rel)
	cur := root
	hops := 0
	for len(work) > 0 {
		p := work[0]
		work = work[1:]
		switch p {
		case "", ".":
			continue
		case "..":
			if pathKey(cur) == pathKey(root) {
				return "", errors.New("the path escapes the scanned filesystem root")
			}
			cur = filepath.Dir(cur)
			continue
		}
		next := filepath.Join(cur, p)
		fi, err := os.Lstat(next)
		if err != nil {
			return "", err
		}
		if fi.Mode()&os.ModeSymlink == 0 {
			cur = next
			continue
		}
		hops++
		if hops > maxLinkHops {
			return "", errors.New("too many levels of symbolic links")
		}
		target, err := os.Readlink(next)
		if err != nil {
			return "", err
		}
		if filepath.IsAbs(target) || strings.HasPrefix(target, "/") || strings.HasPrefix(target, `\`) {
			// Absolute in the SCANNED filesystem: start over from its root, never from ours. A Windows
			// link created with target "/" reads back as `\`, which filepath.IsAbs does not consider
			// absolute (no volume) -- hence the explicit separator checks.
			target = strings.TrimPrefix(target, filepath.VolumeName(target))
			cur = root
		}
		work = append(splitPath(target), work...)
	}
	return cur, nil
}

// splitPath splits a path into components on either separator.
func splitPath(p string) []string {
	return strings.FieldsFunc(filepath.ToSlash(p), func(r rune) bool { return r == '/' })
}

// containmentReasonUnder is containmentReason with root standing for the scanned filesystem's `/`:
// the image's own root is not a webroot, and its /etc is an operating-system directory even though,
// from here, it is just a subdirectory of a mount point.
func containmentReasonUnder(root, resolved string) string {
	if pathKey(resolved) == pathKey(root) {
		return "rejected by containment: the filesystem root is not a webroot"
	}
	rel, err := filepath.Rel(root, resolved)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "rejected by containment: the path escapes the scanned filesystem root"
	}
	inFS := filepath.Clean(string(filepath.Separator) + rel)
	if osDirectories()[pathKey(inFS)] {
		return "rejected by containment: " + filepath.ToSlash(inFS) + " is an operating-system directory, not a webroot"
	}
	return ""
}
