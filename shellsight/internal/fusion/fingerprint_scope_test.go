package fusion

import (
	"testing"

	"shellsight/internal/finding"
)

// The fingerprint must ignore Context.
//
// It is the key the runbook presents for SIEM suppression, so it has to be stable across additions
// that carry no identity. Spec 008 adds `context.rule_scope` to findings admitted because a file's
// CONTENT was plausibly the language while its NAME claimed nothing; if that moved the fingerprint,
// every suppression written before the feature would stop matching, and a renamed-file finding could
// not be suppressed by a rule written against the same rule on a normally-named file.
//
// This is structural today -- fingerprint() reads Host, View, target, Detection and family -- and the
// test exists so a later change cannot fold Context in without noticing.
func TestFingerprintIgnoresContext(t *testing.T) {
	base := finding.Finding{
		SchemaVersion: finding.SchemaVersion,
		Host:          "WEB01",
		View:          "disk",
		Target:        finding.Target{Kind: "file", File: &finding.File{Path: `C:\web\shell.txt`}},
		Artifact:      finding.Artifact{Kind: "file-webshell", Identity: "shell.txt"},
		Detection: finding.Detection{
			Basis:        "signature",
			KnowledgeRef: "kb:yara/php_eval_request_webshell",
			Evidence:     "YARA rule php_eval_request_webshell matched: $eval_req",
		},
		Score: 70,
		Tier:  finding.TierLikely,
	}

	withContext := base
	withContext.Context = map[string]string{
		"rule_author": "ShellSight",
		"rule_scope":  "unknown-language",
	}

	a, b := fingerprint(base), fingerprint(withContext)
	if a == "" {
		t.Fatal("fingerprint returned empty; this test would assert nothing")
	}
	if a != b {
		t.Errorf("Context changed the fingerprint: %q -> %q -- every existing SIEM suppression "+
			"would stop matching", a, b)
	}

	// A sanity anchor in the other direction: something that IS identity must change it, or the
	// test above would pass for a fingerprint that ignores everything.
	moved := base
	moved.Detection.Evidence += " (decoded layer)"
	if fingerprint(moved) == a {
		t.Error("changing Detection.Evidence did not change the fingerprint; the function is not " +
			"hashing what this test assumes it hashes")
	}
}
