// Package release ingests a published scanner release: it verifies every file against the
// release's own hash manifest before anything is stored.
//
// Verification is two-directional on purpose. Checking only that manifested files match would
// let an extra, unmanifested file ride along into a release and from there into an agent, so a
// file on disk that the manifest does not name is a verification failure too.
package release

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ManifestName is the release's complete inventory, written by scripts/package.sh.
//
// NOT PROBE-HASHES.sha256, which is what this used to name and is a different document: that one is
// the PREBUILT-asset attribution record, and package.sh refuses any entry in it that is not an
// approved prebuilt path. Verification here is two-directional, so pointing at a deliberately
// partial list meant no real release could ever be ingested -- measured 2026-09-08 on
// shellsight-v1.0.1-20-g687b745-win.zip, which PROBE-HASHES described 144 of 164 files of:
//
//	release verification failed: file RUNBOOK.md is present but not named in PROBE-HASHES.sha256
//
// and that refusal blocked publish, and with it every agent build. The tests never saw it because
// mkRelease writes a manifest line for every file it creates, so the fixture is complete by
// construction and the real document's partialness was not expressible.
const ManifestName = "RELEASE-FILES.sha256"

type File struct {
	Path   string // slash-relative to the release root
	SHA256 string
	Body   []byte
}

func Sum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// Verify reads the manifest, checks every entry against disk and every file on disk against the
// manifest, and returns the verified files with their contents.
func Verify(root string) ([]File, error) {
	manifest, err := os.ReadFile(filepath.Join(root, ManifestName))
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", ManifestName, err)
	}

	want := map[string]string{}
	for n, line := range strings.Split(string(manifest), "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		hash, path, ok := strings.Cut(line, "  ")
		if !ok {
			return nil, fmt.Errorf("%s line %d: expected '<hash>  <path>', got %q", ManifestName, n+1, line)
		}
		path = strings.TrimSpace(path)
		if err := checkContained(path); err != nil {
			return nil, fmt.Errorf("%s line %d: %w", ManifestName, n+1, err)
		}
		want[path] = strings.ToLower(strings.TrimSpace(hash))
	}

	var out []File
	for path, wantHash := range want {
		body, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
		if err != nil {
			return nil, fmt.Errorf("manifested file %s: %w", path, err)
		}
		if got := Sum(body); got != wantHash {
			return nil, fmt.Errorf("hash mismatch for %s: manifest says %s, file is %s", path, wantHash, got)
		}
		out = append(out, File{Path: path, SHA256: wantHash, Body: body})
	}

	if err := checkNoExtraFiles(root, want); err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

// checkContained refuses any path that is absolute or climbs out of the release root. Manifest
// text is data from outside the console and must never be able to name a file elsewhere on disk.
func checkContained(path string) error {
	if path == "" {
		return fmt.Errorf("empty path")
	}
	if filepath.IsAbs(path) || strings.HasPrefix(path, "/") || strings.Contains(path, `\`) {
		return fmt.Errorf("path %q must be relative and slash-separated", path)
	}
	clean := filepath.ToSlash(filepath.Clean(path))
	if clean == ".." || strings.HasPrefix(clean, "../") {
		return fmt.Errorf("path %q escapes the release root", path)
	}
	return nil
}

func checkNoExtraFiles(root string, want map[string]string) error {
	return filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		rel, rerr := filepath.Rel(root, p)
		if rerr != nil {
			return rerr
		}
		rel = filepath.ToSlash(rel)
		if rel == ManifestName {
			return nil
		}
		if _, ok := want[rel]; !ok {
			return fmt.Errorf("file %s is present but not named in %s", rel, ManifestName)
		}
		return nil
	})
}
