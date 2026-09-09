package main

// The reader allowlist: which directory entries the probe is willing to open.
//
// WHY THIS EXISTS
//
// A webroot can contain entries that are not ordinary files, and anyone who can write to the
// webroot -- including the intruder being hunted -- can create them. Measured 2026-08-20 on ext4,
// against the shipped engine and this probe:
//
//   - a FIFO named `x.php` makes `os.Open` block forever, because opening a FIFO for reading waits
//     for a writer that never comes. No read bound helps: the block happens before the first read.
//   - a symlink to /dev/zero makes an unbounded `os.ReadFile` grow until the process dies (466 MB
//     RSS observed), and makes the engine itself reach 292 MB in 20 s and climb.
//
// In both cases the failure is loss of the WHOLE scan, not of the offending file: scanning a
// directory containing a known webshell plus a FIFO reported ZERO findings. A scanner an attacker
// can switch off by touching one file is not a control, so this is a security property rather than
// a robustness nicety (spec 002 US3, FR-013 to FR-018).
//
// WHY SYMLINKS ARE NOT FOLLOWED
//
// Measured, not assumed: `yr --recursive` scans a hard link and an ordinary file but skips a
// symlink to a regular file entirely, and does not descend a directory symlink. Go's
// `filepath.WalkDir` likewise never follows directory symlinks. So NOT following a symlink is both
// what the engine already does -- keeping detections identical (FR-019) -- and what FR-018
// requires, since a link inside the webroot may point outside it.
//
// It also closes a containment hole that exists today: the PHP and Perl/Python taint passes reach
// the file through `os.ReadFile`, which FOLLOWS symlinks, so a link in the webroot pointing at any
// file on the host would be read and reported under the in-webroot path. That is both an escape
// and a misattribution.
//
// A symlink whose target is a regular file inside the scanned roots is NOT a coverage gap -- the
// target is enumerated in its own right and its content is examined. Counting it as skipped would
// claim a hole that does not exist, so `classifyEntry` distinguishes the two cases.

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// maxScanFileBytes bounds how much of any single file the probe will read, independently of file
// kind (FR-016). The kind allowlist already excludes endless devices; this is the second bound, for
// an ordinary file that is merely enormous.
const maxScanFileBytes = 32 << 20

// entryVerdict is what the allowlist decided about one directory entry.
type entryVerdict int

const (
	// entryRead is an ordinary file: open it.
	entryRead entryVerdict = iota
	// entryCovered is an entry we do not read but whose content is examined anyway -- a symlink
	// resolving to a regular file inside the scanned roots. Not a coverage gap, so not counted.
	entryCovered
	// entryGap is an entry that is not read and whose content is therefore NOT examined: a FIFO,
	// socket, device, dangling link, or a link resolving outside the scanned roots.
	entryGap
)

// classifyEntry decides whether a walk may read p.
//
// `d.Type()` comes from the directory entry itself and costs no syscall, which matters because this
// runs once per file in a corpus of tens of thousands. Only a symlink -- rare -- needs `os.Stat`,
// which follows the link, to learn what it resolves to.
func classifyEntry(p string, d fs.DirEntry, roots []string) entryVerdict {
	t := d.Type()
	switch {
	case t.IsRegular():
		return entryRead
	case t.IsDir():
		// Directories are traversed, not read. Never a gap.
		return entryCovered
	case t&os.ModeSymlink != 0:
		return classifySymlink(p, roots)
	case t&os.ModeIrregular != 0:
		// The directory entry could not name the type (some filesystems return DT_UNKNOWN). Ask the
		// filesystem rather than guessing; guessing "regular" here would reopen the FIFO hang.
		fi, err := os.Stat(p)
		if err != nil || !fi.Mode().IsRegular() {
			return entryGap
		}
		return entryRead
	default:
		// FIFO, socket, block device, character device.
		return entryGap
	}
}

// classifySymlink resolves a link and reports whether skipping it leaves a coverage gap.
//
// DISCLOSED RESIDUAL (spec 007, research R1). Under a process-root view -- a root named as
// /proc/<pid>/root/... -- EvalSymlinks resolves the entry through the magic link into the SCANNER'S
// namespace, so a link whose target sits inside the same root is judged against a directory that may
// not exist here and lands in entryGap. That is counted (skipped.non_regular, coverage degraded),
// never silent, and the regular files beside it are unaffected; cmd/diskprobe/nsview_linux_test.go
// pins exactly that. Resolving in the scanned namespace here would mean threading --root through the
// walk; it is a follow-up, not part of that feature.
func classifySymlink(p string, roots []string) entryVerdict {
	fi, err := os.Stat(p) // follows the link
	if err != nil || !fi.Mode().IsRegular() {
		// Dangling, circular, or pointing at a device. Not examined, and nothing else examines it.
		return entryGap
	}
	target, err := filepath.EvalSymlinks(p)
	if err != nil {
		return entryGap
	}
	if pathWithinAny(target, roots) {
		// The target is enumerated in its own right, so its content IS examined. Reading the link
		// too would only duplicate the finding under a second path.
		return entryCovered
	}
	// Resolves outside the scanned roots. FR-018 forbids examining it.
	return entryGap
}

// pathWithinAny reports whether target lies inside one of roots. Both sides are resolved first so a
// root reached through a symlink still matches, and the comparison is on path SEGMENTS so that
// `/srv/www-backup` is not treated as inside `/srv/www`.
func pathWithinAny(target string, roots []string) bool {
	for _, root := range roots {
		realRoot, err := filepath.EvalSymlinks(root)
		if err != nil {
			realRoot = root
		}
		rel, err := filepath.Rel(realRoot, target)
		if err != nil {
			continue
		}
		if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			continue
		}
		if filepath.IsAbs(rel) {
			continue
		}
		return true
	}
	return false
}

// scanSkips counts what the scan declined to read, per data-model E3.
//
// Counting is by DISTINCT PATH rather than by occurrence: several passes walk the same tree, and a
// single FIFO seen by four of them is one file not examined, not four.
//
// Not safe for concurrent use; the passes that record into it run sequentially.
type scanSkips struct {
	nonRegular map[string]struct{}
	unreadable map[string]struct{}
	oversize   map[string]struct{}
	// noLangDetector is files no language-specific detector examined: the name claimed no language
	// and no language sign matched the content. They WERE scanned by the unscoped rule layer, so
	// this is a weaker statement than "not scanned" -- see finding.ScanSkips.NoLanguageDetector.
	noLangDetector map[string]struct{}
}

func (s *scanSkips) markNonRegular(p string)     { s.mark(&s.nonRegular, p) }
func (s *scanSkips) markUnreadable(p string)     { s.mark(&s.unreadable, p) }
func (s *scanSkips) markOversize(p string)       { s.mark(&s.oversize, p) }
func (s *scanSkips) markNoLangDetector(p string) { s.mark(&s.noLangDetector, p) }

func (s *scanSkips) mark(set *map[string]struct{}, p string) {
	if *set == nil {
		*set = map[string]struct{}{}
	}
	(*set)[p] = struct{}{}
}

func (s *scanSkips) NonRegular() int     { return len(s.nonRegular) }
func (s *scanSkips) Unreadable() int     { return len(s.unreadable) }
func (s *scanSkips) Oversize() int       { return len(s.oversize) }
func (s *scanSkips) NoLangDetector() int { return len(s.noLangDetector) }

func (s *scanSkips) Total() int {
	return s.NonRegular() + s.Unreadable() + s.Oversize() + s.NoLangDetector()
}

// rootPaths is one webroot and the vetted files found under it.
type rootPaths struct {
	Root  string
	Paths []string
}

// allPaths flattens the per-root lists for the passes that do not care which root a file came from.
//
// Deliberately NOT deduplicated across roots: every pass today walks each root independently, so a
// file reachable from two overlapping roots is already processed twice. Deduplicating here would
// change detections on overlapping roots, which is exactly what FR-019 and T052 forbid.
func allPaths(rs []rootPaths) []string {
	var out []string
	for _, r := range rs {
		out = append(out, r.Paths...)
	}
	return out
}

// enumerateScannable walks each root once and returns the paths the probe may read, in walk order,
// together with what it declined and why.
//
// This is the single authoritative pass. The engine is handed exactly this list rather than the
// directory -- handing it the directory is what let one FIFO hang the whole scan -- and every other
// pass consumes the same list, so the tree is walked once instead of four times and a skip is
// counted once instead of once per pass.
//
// A walk error on one entry is recorded and skipped rather than returned: FR-014 requires that a
// file the scanner cannot read must not prevent the others from being examined.
func enumerateScannable(roots []string) ([]rootPaths, scanSkips) {
	var out []rootPaths
	var skips scanSkips

	for _, root := range roots {
		var paths []string
		_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				// Includes a directory we cannot open. Count it and keep going.
				skips.markUnreadable(p)
				if d != nil && d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if d.IsDir() {
				return nil
			}
			switch classifyEntry(p, d, roots) {
			case entryRead:
			case entryCovered:
				return nil
			default:
				skips.markNonRegular(p)
				return nil
			}

			// Oversize is RECORDED but NOT excluded. The engine memory-maps its targets, so a huge
			// file costs it nothing and dropping one here would lose a detection yr makes today --
			// exactly the regression FR-019 and T052 forbid. The bound that matters is on the Go
			// passes, which read into memory; readBoundedFile enforces it there. So this counter
			// discloses "the deobfuscation and taint passes did not examine these", which has been
			// true and silent since readBoundedFile was introduced.
			//
			// Only web-source files count. The in-memory passes filter by extension before reading,
			// so a 200 MB git pack or zip was never going to be read at any size, and calling it a
			// gap would claim a hole that does not exist -- the same dishonesty the symlink case
			// avoids. Measured: all 13 files over the bound in the corpus are .git packs, LFS
			// objects, zips and one browscap.xml, several inside benign populations, so without
			// this gate an ordinary WordPress checkout would report degraded coverage forever.
			if info, err := d.Info(); err != nil {
				skips.markUnreadable(p)
				return nil
			} else if info.Size() > maxScanFileBytes && webshellLikeExt(p) {
				skips.markOversize(p)
			}

			// Readability is TESTED, not inferred. A file with mode 0000 stats perfectly well --
			// the permission that matters belongs to the file, while the walk only needed the
			// directory's -- so nothing learned so far distinguishes it from a readable one, and it
			// used to be dropped silently while the run reported success. Inspecting the mode bits
			// instead would still miss the ordinary IR case of a file readable only by another
			// user. The open is O_RDONLY and immediately closed; the kind allowlist above has
			// already excluded everything for which opening is not free.
			if f, err := os.Open(p); err != nil {
				skips.markUnreadable(p)
				return nil
			} else {
				_ = f.Close()
			}
			paths = append(paths, p)
			return nil
		})
		out = append(out, rootPaths{Root: root, Paths: paths})
	}
	return out, skips
}
