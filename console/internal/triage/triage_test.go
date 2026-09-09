package triage

import (
	"reflect"
	"testing"

	"shellsightconsole/internal/store"
)

func TestGroupCollapsesManyRulesOnOneFileIntoOneItem(t *testing.T) {
	// The real shape: five rules fired on one file. An analyst decides once, not five times.
	in := []store.FindingRecord{
		{Ref: "aa-ObfuscatedPhp", ContentKey: "sha256:aa", Host: "web-01",
			FilePath: `C:\www\shell.php`, Score: 70, Tier: "likely-malicious"},
		{Ref: "aa-DodgyPhp", ContentKey: "sha256:aa", Host: "web-01",
			FilePath: `C:\www\shell.php`, Score: 70, Tier: "likely-malicious"},
		{Ref: "aa-phptaint", ContentKey: "sha256:aa", Host: "web-01",
			FilePath: `C:\www\shell.php`, Score: 90, Tier: "confirmed"},
	}
	got := Groups(in)
	if len(got) != 1 {
		t.Fatalf("got %d groups, want 1", len(got))
	}
	if len(got[0].Findings) != 3 {
		t.Fatalf("group holds %d findings, want 3", len(got[0].Findings))
	}
}

func TestAGroupTakesTheHighestTierAndScoreOfItsFindings(t *testing.T) {
	// Triage order must follow the worst thing said about the content, not the first thing.
	in := []store.FindingRecord{
		{Ref: "a", ContentKey: "sha256:aa", Score: 70, Tier: "likely-malicious"},
		{Ref: "b", ContentKey: "sha256:aa", Score: 90, Tier: "confirmed"},
	}
	got := Groups(in)
	if got[0].Tier != "confirmed" || got[0].Score != 90 {
		t.Fatalf("group is %s/%d, want confirmed/90", got[0].Tier, got[0].Score)
	}
}

func TestOneWebshellInManyPlacesOnManyHostsIsOneItem(t *testing.T) {
	// The property that makes content the unit. Keying on fingerprint would give four items.
	in := []store.FindingRecord{
		{Ref: "aa-r", ContentKey: "sha256:aa", Host: "web-01", FilePath: `C:\a\s.php`, Fingerprint: "f1"},
		{Ref: "aa-r", ContentKey: "sha256:aa", Host: "web-01", FilePath: `C:\b\s.php`, Fingerprint: "f2"},
		{Ref: "aa-r", ContentKey: "sha256:aa", Host: "web-02", FilePath: `C:\a\s.php`, Fingerprint: "f3"},
		{Ref: "aa-r", ContentKey: "sha256:aa", Host: "web-02", FilePath: `D:\c\s.php`, Fingerprint: "f4"},
	}
	got := Groups(in)
	if len(got) != 1 {
		t.Fatalf("got %d groups, want 1 -- content is the unit, not location", len(got))
	}
	if got[0].Locations != 4 {
		t.Fatalf("Locations = %d, want 4", got[0].Locations)
	}
	if len(got[0].Hosts) != 2 {
		t.Fatalf("Hosts = %v, want 2 distinct", got[0].Hosts)
	}
}

func TestGroupsAreOrderedBySeverityThenLocationCount(t *testing.T) {
	in := []store.FindingRecord{
		{Ref: "a", ContentKey: "sha256:low", Score: 45, Tier: "suspicious"},
		{Ref: "b", ContentKey: "sha256:high", Score: 95, Tier: "confirmed"},
		{Ref: "c", ContentKey: "sha256:mid", Score: 70, Tier: "likely-malicious"},
	}
	got := Groups(in)
	want := []string{"sha256:high", "sha256:mid", "sha256:low"}
	var order []string
	for _, g := range got {
		order = append(order, g.ContentKey)
	}
	if !reflect.DeepEqual(order, want) {
		t.Fatalf("order = %v, want %v", order, want)
	}
}

func TestDistinctRulesAreListedOncePerGroup(t *testing.T) {
	in := []store.FindingRecord{
		{Ref: "a", ContentKey: "sha256:aa", KnowledgeRef: "kb:yara/DodgyPhp"},
		{Ref: "b", ContentKey: "sha256:aa", KnowledgeRef: "kb:yara/DodgyPhp"},
		{Ref: "c", ContentKey: "sha256:aa", KnowledgeRef: "phptaint:sink-on-request"},
	}
	got := Groups(in)
	if len(got[0].Rules) != 2 {
		t.Fatalf("Rules = %v, want 2 distinct", got[0].Rules)
	}
}
