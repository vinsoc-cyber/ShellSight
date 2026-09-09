package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Integrity states. These describe what the console can and cannot vouch for.
const (
	// IntegrityVerified: report.json matches the hash in the run folder's own manifest.
	IntegrityVerified = "verified"
	// IntegrityUnverified: no manifest was present. Not a problem, not a guarantee.
	IntegrityUnverified = "unverified"
	// IntegrityAltered: a manifest was present and disagrees.
	IntegrityAltered = "altered"
)

// Loaded is a parsed run folder and what could be said about its integrity.
type Loaded struct {
	Report    Report
	Integrity string
	Source    string // the run folder path, for the audit trail
}

func Sum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// LoadRunFolder reads report.json and checks it against manifest.json when one is present.
//
// A report whose hash disagrees is STILL RETURNED, marked altered. Refusing it would discard
// evidence from a live engagement; what the analyst needs is to read it and to know it does not
// match its manifest.
//
// The check is self-consistency, NOT authenticity: anyone who can edit report.json can recompute
// manifest.json. That is why the states are verified/unverified/altered and not valid/invalid, and
// why nothing here should be presented as proof of origin.
func LoadRunFolder(dir string) (Loaded, error) {
	body, err := os.ReadFile(filepath.Join(dir, "report.json"))
	if err != nil {
		return Loaded{}, fmt.Errorf("reading report.json: %w", err)
	}
	// An absent manifest is nil bytes, which Load reads as "unverified" -- the same answer this
	// function gave when it did its own file reading.
	manifest, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		manifest = nil
	}
	return Load(body, manifest, dir)
}

// Load is LoadRunFolder without a filesystem: the same parse and the same integrity check over
// bytes that arrived some other way -- an HTTP upload, say.
//
// It exists so there is exactly ONE implementation of what verified/unverified/altered mean. A
// second copy behind the upload endpoint is how the CLI and the browser would come to disagree
// about whether a given report matches its manifest, and that disagreement would be invisible
// until an engagement depended on it.
//
// manifest may be nil, which is "no manifest was supplied": unverified, not an error.
func Load(body, manifest []byte, source string) (Loaded, error) {
	rep, err := Parse(body)
	if err != nil {
		return Loaded{}, err
	}
	out := Loaded{Report: rep, Integrity: IntegrityUnverified, Source: source}
	if len(manifest) == 0 {
		return out, nil
	}
	var named map[string]string
	if err := json.Unmarshal(manifest, &named); err != nil {
		return out, nil // an unreadable manifest is no worse than an absent one
	}
	want, ok := named["report.json"]
	if !ok {
		return out, nil
	}
	if want == Sum(body) {
		out.Integrity = IntegrityVerified
	} else {
		out.Integrity = IntegrityAltered
	}
	return out, nil
}
