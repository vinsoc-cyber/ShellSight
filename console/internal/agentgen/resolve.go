package agentgen

import (
	"fmt"
	"sort"
	"strings"
)

// Selection is the resolved answer to "what does this build carry".
type Selection struct {
	// Files are release-relative paths, sorted and deduplicated. Sorted because the zip's entry
	// order has to be fixed for G6, and doing it here means the writer cannot forget.
	Files []string
	// NeedsRules reports whether any selected view scans with YARA, so the caller knows whether a
	// rule set is required at all. A memory-only build takes none -- G8, and the form reads this to
	// say "not applicable" rather than hardcoding it.
	NeedsRules bool
	// Views is the selection, sorted, as it will be written into agent.json.
	Views []string
}

// Resolve turns a view selection into the file set a generated agent must carry.
func Resolve(doc Components, views []string) (Selection, error) {
	if len(views) == 0 {
		return Selection{}, fmt.Errorf(
			"a build must carry at least one view; one carrying none would examine nothing and report " +
				"a clean sweep of a host it never looked at")
	}
	files := map[string]bool{}
	for _, f := range doc.Always {
		files[f] = true
	}
	out := Selection{}
	for _, v := range views {
		vc, ok := doc.Views[v]
		if !ok {
			return Selection{}, fmt.Errorf(
				"target %s does not support the %q view: its declaration has no entry for it",
				doc.Target, v)
		}
		for _, b := range vc.Binaries {
			files[b] = true
		}
		if vc.Rules {
			// Data is deliberately NOT staged for a rules view. Those entries name the rule LAYERS
			// the compiled .yarc replaces (spec 6.4), so staging them would ship YARA source in a
			// customer-bound agent and contradict G8/D5. They are also directories, which
			// release_files has no row for.
			out.NeedsRules = true
			continue
		}
		for _, d := range vc.Data {
			files[d] = true
		}
	}
	for f := range files {
		out.Files = append(out.Files, f)
	}
	sort.Strings(out.Files)

	// Views is deduplicated as well as sorted, and that is not tidiness.
	//
	// It is written verbatim into agent.json's `views`, and the scanner joins that list with a comma
	// to build -views. The scanner rejects a blank view name and one containing a comma, and rejects
	// duplicate JSON keys -- but not a repeated ARRAY ELEMENT, so `["disk","disk"]` is accepted and
	// becomes `-views disk,disk`. Deduplicating here means the declaration says each view once,
	// which is what it means.
	seen := map[string]bool{}
	for _, v := range views {
		if seen[v] {
			continue
		}
		seen[v] = true
		out.Views = append(out.Views, v)
	}
	sort.Strings(out.Views)
	return out, nil
}

// StagedFile is one file on its way into the archive.
type StagedFile struct {
	// Path is the path inside the generated agent, always forward-slashed: it becomes a zip entry
	// name, and zip names are defined as forward-slashed regardless of the host.
	Path string
	Body []byte
}

// Stage fetches the bytes of every resolved component, refusing the build if the release does not
// hold one, or if a declared path is not the shape a release path may take.
//
// The shape check is not redundant with the membership check: a path like "../yr" or "/etc/passwd"
// is not in release_files either, so membership alone reports it as merely absent -- which reads as
// "this release is incomplete" when the truth is "this declaration is malformed". Resolve does not
// check shape either; the scanner enforces it at package time, and nothing carries that guarantee
// to a release published another way.
//
// package.sh already verifies a release's declaration against its own extracted archive, so a
// release built that way holds what it declares. This is the guard for one that was not: the
// declaration lists OPTIONAL views unconditionally, and a document promising a component the
// release lacks looks exactly like a correct one. Refusing here costs a lookup; not refusing hands
// out an agent that cannot run a view its own agent.json claims.
func Stage(files Files, sel Selection) ([]StagedFile, error) {
	staged := make([]StagedFile, 0, len(sel.Files))
	for _, p := range sel.Files {
		if err := checkReleasePath(p); err != nil {
			return nil, err
		}
		body, ok := files.File(p)
		if !ok {
			return nil, fmt.Errorf(
				"this release declares %q but does not hold it, so the build would ship an agent "+
					"missing a component its configuration claims", p)
		}
		staged = append(staged, StagedFile{Path: p, Body: body})
	}
	return staged, nil
}

// checkReleasePath rejects anything that is not a release-relative, slash-separated path.
//
// Deliberately not internal/release's checkContained, and it does not CALL that one, and the difference is not just that checkContained is unexported.
// checkContained leads with filepath.IsAbs, whose answer depends on the host: "C:/x" is absolute on
// Windows and an ordinary relative path on Linux. This console resolves paths for a TARGET, which
// need not be its own platform -- a Linux-hosted console generates windows-amd64 agents -- so a
// rule that changes meaning with the host would accept a drive-absolute Windows path on one
// deployment and refuse it on another from the same release. Hence the explicit colon rule and no
// filepath at all: the same document is judged the same way everywhere.
//
// The scanner's isRooted (cmd/shellsight/config.go) reached this conclusion independently, and its
// comment says so -- "deliberately wider than filepath.IsAbs, and wider on both platforms".
func checkReleasePath(p string) error {
	switch {
	case p == "":
		return fmt.Errorf("this release declares a component with an empty path")
	case strings.HasPrefix(p, "/"), strings.Contains(p, `\`), strings.Contains(p, ":"):
		return fmt.Errorf(
			"this release declares %q, which is not a release-relative slash-separated path", p)
	}
	for _, part := range strings.Split(p, "/") {
		if part == ".." {
			return fmt.Errorf(
				"this release declares %q, which climbs out of the release root", p)
		}
	}
	return nil
}
