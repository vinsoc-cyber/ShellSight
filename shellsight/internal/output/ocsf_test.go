package output

import (
	"encoding/json"
	"strings"
	"testing"

	"shellsight/internal/finding"
)

func TestOCSFLineMapsDetectionFinding(t *testing.T) {
	fam := "Godzilla"
	f := finding.Finding{
		SchemaVersion: "1.0", Fingerprint: "abc123", Host: "WEB01", View: "dotnet-mem",
		Target:         finding.Target{Kind: "process", Process: &finding.Process{PID: 4321, Name: "w3wp.exe"}},
		Artifact:       finding.Artifact{Kind: "dotnet-memory-module", Identity: "MemoryShell"},
		Detection:      finding.Detection{Basis: "structural-heuristic", Evidence: "implements System.Web.IHttpModule"},
		Score:          95, Tier: finding.TierConfirmed,
		Classification: finding.Classification{Family: &fam},
		Mitre:          []string{"T1505.003", "T1505.004"},
	}
	rep := finding.Report{Scan: finding.Scan{Host: "WEB01", Started: "2026-06-13T10:00:00Z", ToolVersion: "0.5.0-dev"}, Findings: []finding.Finding{f}}

	line := ocsfLines(rep)
	if len(line) != 1 {
		t.Fatalf("want 1 ocsf line, got %d", len(line))
	}
	var o map[string]any
	if err := json.Unmarshal([]byte(line[0]), &o); err != nil {
		t.Fatalf("ocsf line not valid json: %v", err)
	}
	if o["class_uid"].(float64) != 2004 || o["category_uid"].(float64) != 2 || o["type_uid"].(float64) != 200401 {
		t.Fatalf("wrong OCSF class/category/type: %v", o)
	}
	if o["severity_id"].(float64) != 5 || o["confidence_id"].(float64) != 3 {
		t.Fatalf("confirmed must map to severity 5 / confidence 3, got sev=%v conf=%v", o["severity_id"], o["confidence_id"])
	}
	atk, _ := json.Marshal(o["attacks"])
	if !strings.Contains(string(atk), "T1505.004") {
		t.Fatalf("attacks must carry the technique IDs: %s", atk)
	}
}

func TestOCSFMetadataVersionIs18(t *testing.T) {
	f := finding.Finding{Host: "WEB01", View: "disk", Tier: finding.TierLikely,
		Detection: finding.Detection{Basis: "signature", Evidence: "rule x matched"}}
	rep := finding.Report{Scan: finding.Scan{Host: "WEB01", Started: "2026-06-15T10:00:00Z", ToolVersion: "0.6.0-dev"}, Findings: []finding.Finding{f}}
	o := ocsfFrom(rep, f)
	if o.Metadata.Version != "1.8.0" {
		t.Fatalf("OCSF metadata.version must be 1.8.0, got %q", o.Metadata.Version)
	}
}

func TestT1620MapsToDefenseEvasionTactic(t *testing.T) {
	f := finding.Finding{Host: "H", View: "dotnet-mem", Tier: finding.TierLikely,
		Detection: finding.Detection{Basis: "structural-heuristic", Evidence: "path-less CLR module"},
		Mitre:     []string{"T1505.003", "T1620"}}
	rep := finding.Report{Scan: finding.Scan{Host: "H", Started: "2026-06-15T10:00:00Z", ToolVersion: "0.6.0-dev"}, Findings: []finding.Finding{f}}
	o := ocsfFrom(rep, f)
	var foundDE bool
	for _, a := range o.Attacks {
		if a.Technique.UID == "T1620" && a.Tactic.UID == "TA0005" {
			foundDE = true
		}
	}
	if !foundDE {
		t.Fatalf("T1620 must map to tactic TA0005 (Defense Evasion); attacks=%+v", o.Attacks)
	}
}

func TestSevConfMapping(t *testing.T) {
	cases := []struct {
		tier     finding.Tier
		sev, con int
	}{
		{finding.TierClean, 1, 1},
		{finding.TierSuspicious, 3, 2},
		{finding.TierLikely, 4, 3},
		{finding.TierConfirmed, 5, 3},
	}
	for _, c := range cases {
		s, n := sevConf(c.tier)
		if s != c.sev || n != c.con {
			t.Fatalf("%s → want sev %d conf %d, got %d/%d", c.tier, c.sev, c.con, s, n)
		}
	}
}
