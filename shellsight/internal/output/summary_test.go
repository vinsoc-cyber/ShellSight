package output

import (
	"strings"
	"testing"

	"shellsight/internal/finding"
)

// summary.txt is the first thing an analyst reads, and it used to print
//
//	[likely-malicious] disk — openid.php (signature, score=70) [T1505.003]
//
// which names neither the rule nor which openid.php. phpMyAdmin ships examples/openid.php, so on a
// real tree the analyst could not identify the file, let alone the rule that fired. Everything
// needed was already in report.json, so this was a rendering gap, not a data gap.
func diskFinding() finding.Finding {
	fam := "GenericEval"
	return finding.Finding{
		Host: "WEB01", View: "disk",
		Target:   finding.Target{Kind: "file", File: &finding.File{Path: `C:\inetpub\wwwroot\examples\openid.php`}},
		Artifact: finding.Artifact{Kind: "file-webshell", Identity: "openid.php"},
		Detection: finding.Detection{
			Basis:        "signature",
			KnowledgeRef: "kb:yara/DodgyPhp",
			Evidence:     "YARA rule DodgyPhp matched: $execution",
		},
		Context:        map[string]string{"yara_matches": "$execution@11: base64_decode($_POST"},
		Classification: finding.Classification{Family: &fam},
		Score:          70, Tier: finding.TierLikely,
		Mitre: []string{"T1505.003"},
	}
}

func summaryOf(f finding.Finding) string {
	return summary(finding.Report{
		SchemaVersion: finding.SchemaVersion,
		Scan:          finding.Scan{Host: "WEB01", RunID: "run-1", ToolVersion: "test"},
		Verdict:       finding.Verdict{Tier: f.Tier, Score: f.Score},
		Coverage:      []finding.Coverage{{View: "disk", Status: finding.CovRan}},
		Findings:      []finding.Finding{f},
	})
}

func TestSummaryNamesTheRuleThatFired(t *testing.T) {
	out := summaryOf(diskFinding())
	if !strings.Contains(out, "kb:yara/DodgyPhp") {
		t.Fatalf("summary must name the rule so an FP can be looked up and tuned:\n%s", out)
	}
}

func TestSummaryGivesTheFullPathNotJustTheBasename(t *testing.T) {
	out := summaryOf(diskFinding())
	if !strings.Contains(out, `C:\inetpub\wwwroot\examples\openid.php`) {
		t.Fatalf("summary must give the full path (a tree can hold several openid.php):\n%s", out)
	}
}

// The evidence line is what turns "DodgyPhp fired" into something an analyst can judge.
func TestSummaryShowsEvidenceAndMatchedText(t *testing.T) {
	out := summaryOf(diskFinding())
	if !strings.Contains(out, "$execution") {
		t.Errorf("summary must show which pattern matched:\n%s", out)
	}
	if !strings.Contains(out, "base64_decode($_POST") {
		t.Errorf("summary must show the matched text when captured:\n%s", out)
	}
}

func TestSummaryStillShowsTierScoreFamilyAndMitre(t *testing.T) {
	out := summaryOf(diskFinding())
	for _, want := range []string{"likely-malicious", "70", "GenericEval", "T1505.003"} {
		if !strings.Contains(out, want) {
			t.Errorf("summary lost %q:\n%s", want, out)
		}
	}
}

// Memory findings have no file path — the artifact identity is the class or module name. The
// renderer must not emit a blank target for them.
func TestSummaryUsesArtifactIdentityWhenThereIsNoFile(t *testing.T) {
	f := finding.Finding{
		Host: "WEB01", View: "dotnet-mem",
		Artifact:  finding.Artifact{Kind: "memory-module", Identity: "DynamicModule.EvilHandler"},
		Detection: finding.Detection{Basis: "structural-heuristic", KnowledgeRef: "kb:mem/pipeline", Evidence: "path-less CLR module implements IHttpModule"},
		Score:     85, Tier: finding.TierConfirmed,
	}
	out := summaryOf(f)
	if !strings.Contains(out, "DynamicModule.EvilHandler") {
		t.Fatalf("a memory finding must still name its artifact:\n%s", out)
	}
	if strings.Contains(out, "—  ") || strings.Contains(out, "— \n") {
		t.Errorf("no blank target should be rendered:\n%s", out)
	}
}

// A finding with no family or ATT&CK tags must not render empty decorations.
func TestSummaryOmitsEmptyFields(t *testing.T) {
	f := diskFinding()
	f.Classification.Family = nil
	f.Mitre = nil
	f.Context = nil
	out := summaryOf(f)
	if strings.Contains(out, "family=") {
		t.Errorf("no family should mean no family= label:\n%s", out)
	}
	if strings.Contains(out, "[]") {
		t.Errorf("no mitre tags should mean no empty brackets:\n%s", out)
	}
	// Match the rendered line, not the substring: the evidence text legitimately reads
	// "YARA rule DodgyPhp matched: $execution".
	if strings.Contains(out, "\n      matched: ") {
		t.Errorf("no captured match text should mean no matched: line:\n%s", out)
	}
}
