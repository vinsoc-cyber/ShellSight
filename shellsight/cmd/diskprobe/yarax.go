package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

// Bounds on how much of a pattern hit is carried into a finding. Matched bytes are
// attacker-controlled, so both the count and the length are capped: evidence and NDJSON are
// one-line-per-finding formats, and a rule with dozens of patterns (or one 4 KB match) would
// otherwise make a report unreadable.
const (
	maxNamedPatterns = 6  // distinct pattern identifiers named in evidence
	maxMatchTextLen  = 48 // characters of matched text kept per hit
	maxContextHits   = 6  // pattern hits detailed in Context
)

// patternSummary renders the matched patterns two ways: a STABLE list of identifiers for
// Detection.Evidence, and the volatile offset/text detail for Context.
//
// The split matters. fusion.fingerprint hashes Evidence and the RUNBOOK presents that fingerprint
// as the SIEM's dedup/suppression key, so anything in Evidence must be stable across cosmetic edits
// to the scanned file. Pattern identifiers are part of the rule and satisfy that; byte offsets and
// matched bytes do not, and would move the fingerprint whenever a benign file shifted by a byte.
func patternSummary(hits []yaraxPatternMatch) (names string, detail string) {
	if len(hits) == 0 {
		return "", ""
	}
	seen := map[string]bool{}
	var ids []string
	for _, h := range hits {
		if h.Identifier == "" || seen[h.Identifier] {
			continue
		}
		seen[h.Identifier] = true
		ids = append(ids, h.Identifier)
	}
	sort.Strings(ids) // deterministic: yr's order is not guaranteed, and this feeds a hashed field
	if len(ids) > maxNamedPatterns {
		extra := len(ids) - maxNamedPatterns
		ids = append(ids[:maxNamedPatterns:maxNamedPatterns], fmt.Sprintf("+%d more", extra))
	}
	names = strings.Join(ids, ", ")

	var parts []string
	for i, h := range hits {
		if i == maxContextHits {
			parts = append(parts, fmt.Sprintf("+%d more hit(s)", len(hits)-maxContextHits))
			break
		}
		parts = append(parts, fmt.Sprintf("%s@%d: %s", h.Identifier, h.Offset, oneLine(h.Match)))
	}
	return names, strings.Join(parts, "; ")
}

// oneLine collapses matched bytes to a single bounded, printable line. Control characters are
// replaced rather than dropped so the analyst can still see that they were present.
func oneLine(s string) string {
	var b strings.Builder
	lastSpace := false
	for _, r := range s {
		switch {
		case r == '\n' || r == '\r' || r == '\t' || unicode.IsSpace(r):
			if !lastSpace {
				b.WriteByte(' ')
				lastSpace = true
			}
		case !unicode.IsPrint(r):
			b.WriteByte('.')
			lastSpace = false
		default:
			b.WriteRune(r)
			lastSpace = false
		}
		if b.Len() >= maxMatchTextLen {
			return strings.TrimSpace(b.String()) + "..."
		}
	}
	return strings.TrimSpace(b.String())
}

// yaraMetaMap unmarshals both yr's array-of-pairs format ([["k","v"]] from --print-meta)
// and the object format ({"k":"v"}) used in tests and older yr versions.
type yaraMetaMap map[string]string

func (m *yaraMetaMap) UnmarshalJSON(b []byte) error {
	out := map[string]string{}
	// yr emits meta as an array of [key, value] pairs where value may be a string, a NUMBER
	// (THOR/signature-base uses `score = 75`, `id = 12302`), or a bool. Decode values as
	// RawMessage and stringify so a single non-string meta value cannot fail the whole record —
	// which previously dropped EVERY rule match on that file (incl. our own string-meta rules),
	// silently suppressing the entire signature-base pack on any matched file.
	var pairs [][]json.RawMessage
	if err := json.Unmarshal(b, &pairs); err == nil {
		for _, pair := range pairs {
			if len(pair) != 2 {
				continue
			}
			var k string
			if json.Unmarshal(pair[0], &k) != nil {
				continue
			}
			out[k] = rawMetaToString(pair[1])
		}
		*m = out
		return nil
	}
	// Fall back to object form: {"key": value} (value may also be non-string).
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(b, &obj); err != nil {
		return err
	}
	for k, v := range obj {
		out[k] = rawMetaToString(v)
	}
	*m = out
	return nil
}

// rawMetaToString renders a JSON scalar meta value (string, number, or bool) as a plain string:
// a JSON string yields its unquoted text, anything else yields its literal JSON token.
func rawMetaToString(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	return strings.TrimSpace(string(raw))
}

// yaraxPatternMatch is one pattern hit inside a rule, from `yr --print-strings`. yr emits these
// under the "strings" key as {"identifier": "$a", "offset": N, "match": "..."}.
type yaraxPatternMatch struct {
	Identifier string `json:"identifier"`
	Offset     int64  `json:"offset"`
	Match      string `json:"match"`
}

type yaraxRuleMatch struct {
	Identifier string              `json:"identifier"`
	Namespace  string              `json:"namespace,omitempty"`
	Meta       yaraMetaMap         `json:"meta,omitempty"`
	Strings    []yaraxPatternMatch `json:"strings,omitempty"`
}
type yaraxFileMatch struct {
	Path  string           `json:"path"`
	Rules []yaraxRuleMatch `json:"rules"`
}

// yaraXArgs builds the `yr scan` argument list.
//
// Extracted from runYaraX so the invocation is assertable without executing yr: the flags here are
// not cosmetic. --print-meta carries shellsight_lang, which drives rule admission in rulegate.go,
// and --print-strings carries the matched text that becomes Detection.Evidence and feeds the
// content fingerprint. Dropping either on one path would change findings while every test about
// scanning still passed.
//
// compiled selects `-C`, which yr's help defines as "Indicate that <RULES_PATH> is a file
// containing compiled rules". rulesPath is then a single .yarc file rather than a directory.
func yaraXArgs(rulesPath string, compiled bool, listPath string) []string {
	args := []string{"scan",
		"--output-format", "ndjson",
		"--print-namespace",
		"--print-meta",
		// Which pattern fired is the difference between "DodgyPhp matched" and an actionable
		// finding. Bounded here rather than only at render time so an attacker-controlled match
		// cannot make yr emit megabytes per hit.
		"--print-strings=" + strconv.Itoa(maxMatchTextLen),
		// `--recursive` is rejected outright when TARGET_PATH is a file, and would be redundant:
		// the list is already the full recursive enumeration.
		"--scan-list",
	}
	if compiled {
		args = append(args, "-C")
	}
	// yr's usage is `<RULES_PATH>... <TARGET_PATH>`: the list must be last, or yr reads it as
	// another rules path.
	return append(args, rulesPath, listPath)
}

// runYaraX scans targetDir with the rules at rulesPath via the bundled `yr` CLI,
// returning raw NDJSON stdout.
//
// yr's failure modes are subtle (verified empirically): it exits 0 on a normal
// scan AND exits 0 when it cannot open the target — logging only `error: ...` to
// stderr. So exit code alone is not enough to stay coverage-honest. We capture
// stderr and treat a fatal `error:` line as a scan failure even on exit 0. A
// non-zero exit WITH usable stdout is tolerated (parse what we got); a non-zero
// exit with empty stdout is a real failure.
//
// TARGETS, NOT A DIRECTORY. This used to pass the webroot with `--recursive` and let yr walk it,
// which made the engine a second, independent copy of the reader defect the Go passes had.
// Measured 2026-08-20 on ext4: `yr --recursive` over a directory holding a known webshell plus a
// FIFO produced ZERO findings and never terminated, and on a symlink to /dev/zero it reached
// 292 MB RSS in 20 s and was still climbing. Handing it a list built by enumerateScannable puts the
// file-kind decision in one place that the engine and the Go passes both obey.
//
// The list is what yr would have walked itself, minus the entries that break it: measured, yr does
// not descend directory symlinks and does not scan symlinks to regular files, which is exactly what
// classifyEntry decides -- so ordinary trees produce identical detections (FR-019).
func runYaraX(ctx context.Context, yrPath, rulesPath string, compiled bool, targets []string) ([]byte, error) {
	if len(targets) == 0 {
		return nil, nil // nothing readable under this root; not a scan failure
	}
	listPath, cleanup, err := writeScanList(targets)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	// CommandContext so an interrupt kills the engine instead of orphaning it. Deliberately no
	// timeout constant: the hang this replaced came from the target list, not from a slow scan, and
	// an arbitrary deadline would abort legitimate long runs -- one population of the emulated
	// arm64 parity collect takes ~5 hours.
	cmd := exec.CommandContext(ctx, yrPath, yaraXArgs(rulesPath, compiled, listPath)...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	// An explicit empty stdin rather than nil: os/exec opens os.DevNull for a nil stream, and a
	// minimal root filesystem may not have one. Measured in an Alpine chroot, where the engine failed
	// with "open /dev/null: no such file or directory" while every file it needed was present.
	cmd.Stdin = bytes.NewReader(nil)
	out, err := cmd.Output()
	if err != nil {
		if len(out) == 0 {
			return nil, fmt.Errorf("%v: %s", err, strings.TrimSpace(stderr.String()))
		}
		return out, nil // non-zero exit but usable output — parse what we got
	}
	// Exit 0: the scan succeeded for the files yr could read. Treat a stderr "error:" line as fatal
	// ONLY when NO scan output was produced — the genuine can't-open-rules/target case (yr exits 0
	// but logs only an error: line). When output IS present, stderr "error:"/warnings are non-fatal:
	// large packs (YARA-Forge) emit warnings whose help text QUOTES rule strings that themselves
	// contain the substring "error:", and per-file module errors (pe/dotnet rules on text files) are
	// expected and harmless. A naive substring check fails the whole directory on those. (Surfaced
	// wiring in the 5k-rule YARA-Forge core pack.)
	if len(bytes.TrimSpace(out)) == 0 && bytes.Contains(stderr.Bytes(), []byte("error:")) {
		return nil, fmt.Errorf("yr reported (no scan output): %s", strings.TrimSpace(stderr.String()))
	}
	return out, nil
}

// writeScanList materialises the target list for `yr --scan-list`, which reads one path per line.
//
// A path containing a newline would inject a bogus entry, so such paths are dropped rather than
// written: on Linux a filename may legally contain one and the webroot is attacker-writable. They
// are rare enough that losing one beats corrupting the whole list.
func writeScanList(targets []string) (string, func(), error) {
	f, err := tempFile("ss-scanlist-*.txt")
	if err != nil {
		return "", func() {}, fmt.Errorf("scan list: %w", err)
	}
	cleanup := func() { _ = os.Remove(f.Name()) }
	w := bufio.NewWriter(f)
	for _, t := range targets {
		if strings.ContainsAny(t, "\n\r") {
			continue
		}
		if _, err := w.WriteString(filepath.Clean(t) + "\n"); err != nil {
			f.Close()
			cleanup()
			return "", func() {}, fmt.Errorf("scan list: %w", err)
		}
	}
	if err := w.Flush(); err != nil {
		f.Close()
		cleanup()
		return "", func() {}, fmt.Errorf("scan list: %w", err)
	}
	if err := f.Close(); err != nil {
		cleanup()
		return "", func() {}, fmt.Errorf("scan list: %w", err)
	}
	return f.Name(), cleanup, nil
}

// parseNDJSON turns yr's NDJSON into per-file matches, skipping blank/unparseable
// lines and files with zero matched rules.
func parseNDJSON(ndjson []byte) []yaraxFileMatch {
	var matches []yaraxFileMatch
	sc := bufio.NewScanner(bytes.NewReader(ndjson))
	sc.Buffer(make([]byte, 0, 1<<20), 16<<20) // tolerate long lines (many rules)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var m yaraxFileMatch
		if err := json.Unmarshal(line, &m); err != nil {
			continue
		}
		if len(m.Rules) > 0 {
			matches = append(matches, m)
		}
	}
	return matches
}
