package discover

import (
	"fmt"
	"path/filepath"
	"strings"
)

// Scanning a filesystem that is mounted somewhere else: an image, a snapshot, a recovered disk.
//
// FR-034 names this case explicitly -- "so that a mounted image, a snapshot, and a host whose web
// server is stopped are all still covered" -- and it was the one of the three that did not work. Every
// config path in this package was an absolute literal rooted at the live `/`, so discovery on a
// mounted image read the ANALYST'S configuration.
//
// MEASURED, and the outcome is worse than "unsupported". A responder mounted an image containing a
// webshell and ran the scan US6 exists to make possible -- no --path:
//
//	verdict=clean incomplete=false
//	    root /srv/hidden-apache  via apache-dump (/etc/apache2/extra-vhosts/hidden.conf)
//	    root /var/www            via convention
//
// A clean verdict about an image that was never opened, with the analyst's own config files cited as
// provenance. That is the silent-clean failure T075 fixed, reached by a different route.
//
// With Root set, every path is read in the SCANNED filesystem's namespace and then mapped into this
// one, and the mechanisms that can only describe the live host say so instead of answering about the
// wrong machine.

// resolveUnderRoot maps a path from the scanned filesystem's namespace into this one.
//
// Returns ok=false when the result escapes Root. An image's configuration is attacker-writable like
// any other, and `root /../../etc;` would otherwise resolve to the ANALYST'S /etc -- turning a request
// to scan an image into a scan of the machine doing the scanning. filepath.Join cleans the `..` away
// silently, so this has to be checked rather than assumed.
func (o Options) resolveUnderRoot(p string) (string, bool) {
	if o.Root == "" {
		return p, true
	}
	root := filepath.Clean(o.Root)
	joined := filepath.Join(root, p)
	if !withinRoot(root, joined) {
		return "", false
	}
	return joined, true
}

// rooted builds a Root for a path the scanned filesystem named, mapping it into this namespace.
//
// InFilesystem is set only when it differs from Path, so a live scan records one namespace rather than
// the same one twice -- redundancy in report.json for every ordinary scan, and the thing the live-path
// control test exists to catch.
func (o Options) rooted(p string, m Mechanism, source string) (Root, bool) {
	mapped, ok := o.resolveUnderRoot(p)
	if !ok {
		return Root{}, false
	}
	r := Root{Path: mapped, Mechanism: m, Source: source}
	if mapped != p {
		r.InFilesystem = p
	}
	return r, true
}

// withinRoot reports whether p is root or inside it.
func withinRoot(root, p string) bool {
	rk, pk := pathKey(root), pathKey(p)
	if rk == pk {
		return true
	}
	rel, err := filepath.Rel(rk, pk)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}

// offline reports whether a filesystem other than this host's is being scanned.
func (o Options) offline() bool { return strings.TrimSpace(o.Root) != "" }

// liveHostOnly is the outcome for a mechanism that can only describe the running host.
//
// Environment variables, the process table and a config-dump binary all answer about the machine doing
// the scanning. On a mounted image their answers are not merely useless, they are about the WRONG
// HOST -- so they must report unavailable rather than contribute roots. Being told "this cannot apply
// to an image" is the whole point of US4's distinction between n/a and a silent absence.
func liveHostOnly(m Mechanism, root string) Outcome {
	return Outcome{
		Mechanism: m, Status: StatusUnavailable,
		Detail: fmt.Sprintf("describes the running host, not the filesystem mounted at %s", root),
	}
}
