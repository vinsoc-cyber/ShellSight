package agentcfg

import (
	"os"
	"path/filepath"
	"testing"
)

// The scanner half of the cross-module contract. The console writes contracts/agent.json's format
// and cannot import this package -- console/go.mod records why -- so the golden is what keeps the
// two honest. See contracts/README.md.
//
// This asserts every field ARRIVES, not merely that the file parses. A parse test would pass
// against a document whose keys the console had renamed: encoding/json ignores an unknown field, so
// "buildid" instead of "build_id" loads clean and lands as "". Every assertion below is therefore
// on a VALUE from the golden, not on the absence of an error.
//
// Line endings are not normalised here and do not need to be: core.autocrlf gives this tracked file
// CRLF on a Windows checkout, and JSON treats CR as whitespace between tokens. The console's side
// compares bytes, so it normalises; this side compares parsed values, so it does not have to.
func TestTheScannerReadsTheContractGolden(t *testing.T) {
	path := filepath.Join("..", "..", "..", "contracts", "agent.json")
	// Checked before Load, and not for tidiness. Load reports a MISSING file as absence rather than
	// as an error -- Config{} with Present false and err nil, deliberately, because a scanner run by
	// hand has no config and must fall back to defaults. So a golden that has been deleted or moved
	// reaches the Present check below and fails it with "Present is false for a config that exists",
	// which asserts the opposite of what happened. Measured 2026-09-04 by moving the file aside.
	//
	// It matters more here than in an ordinary test because this file lives OUTSIDE this module, so
	// the way it goes missing is someone reorganising the repo rather than someone editing this
	// package -- and they need to be told which path they broke.
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("the cross-module contract is missing at %s: %v", path, err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatalf("the scanner cannot read the contract the console writes: %v", err)
	}
	if !got.Present {
		t.Fatal("Present is false for a config that exists")
	}
	if got.SchemaVersion != SchemaVersion {
		t.Errorf("SchemaVersion = %q, want %q", got.SchemaVersion, SchemaVersion)
	}
	if got.BuildID != "b-7f3a91" {
		// Named rather than left as a bare value dump, because an EMPTY value here is exactly what
		// a renamed key looks like from this side: encoding/json ignores a field it does not know,
		// so contracts/agent.json saying "buildid" loads clean and lands as "".
		t.Errorf("BuildID = %q, want %q; an empty value means contracts/agent.json no longer "+
			"carries the key this scanner reads", got.BuildID, "b-7f3a91")
	}
	if len(got.Views) != 1 || got.Views[0] != "disk" {
		t.Errorf("Views = %v", got.Views)
	}
	// The baked scan scope. Asserted here or the contract does not cover it: the console can add a
	// field to the golden and this test would stay green while the scanner ignored it.
	if len(got.ScanScope) != 2 || got.ScanScope[0] != "/var/www" || got.ScanScope[1] != "/srv/http" {
		t.Errorf("ScanScope = %v, want the golden's two paths", got.ScanScope)
	}
	if got.RuleSet.Name != "sweep-acme" || got.RuleSet.Version != 3 {
		t.Errorf("RuleSet = %+v", got.RuleSet)
	}
	if got.RuleSet.Yarc != "rules/set.yarc" {
		t.Errorf("RuleSet.Yarc = %q", got.RuleSet.Yarc)
	}
	if len(got.RuleSet.YarcSHA256) != 64 {
		t.Errorf("RuleSet.YarcSHA256 = %q, want 64 hex characters", got.RuleSet.YarcSHA256)
	}
	if !got.OutputFormat.Specified || got.OutputFormat.Value != OutputFormatJSON {
		t.Errorf("OutputFormat = %+v", got.OutputFormat)
	}
	if !got.ProcessPriority.Specified || got.ProcessPriority.Value != ProcessPriorityLow {
		t.Errorf("ProcessPriority = %+v", got.ProcessPriority)
	}
	if got.GeneratedBy == "" || got.GeneratedAt == "" || got.Release == "" {
		t.Errorf("provenance fields are empty: at=%q by=%q release=%q",
			got.GeneratedAt, got.GeneratedBy, got.Release)
	}
	// The golden exercises the two settings' CHOSEN state. Their unchosen state -- null, which is
	// what the console writes when the analyst picked nothing -- is covered by
	// TestANullBakedSettingIsTheSameAsAnAbsentOne, so a second golden would only duplicate it.
	if got.GeneratedAt != "2026-09-04T12:00:00Z" {
		t.Errorf("GeneratedAt = %q; the golden's exact value is what makes this a contract rather "+
			"than a smoke test", got.GeneratedAt)
	}
	if got.GeneratedBy != "v.quannh67" {
		t.Errorf("GeneratedBy = %q", got.GeneratedBy)
	}
	if got.Release != "v1.0.0-488-gdd02888" {
		t.Errorf("Release = %q", got.Release)
	}
}
