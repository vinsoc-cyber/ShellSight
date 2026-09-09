package rules

import (
	"slices"
	"sort"
	"testing"
)

func TestValidLangsAreTheElevenTheGateUnderstands(t *testing.T) {
	// These mirror declaredWeblangs in cmd/diskprobe/rulegate.go. A value outside this set is a
	// typo that silently changes which files a rule may fire on, and yr cannot see it.
	for _, ok := range []string{
		"php", "jsp", "java", "asp", "aspx", "dotnet", "asp-family", "web-generic", "perl", "python", "shtml",
	} {
		if !ValidLang(ok) {
			t.Errorf("%q should be a valid shellsight_lang", ok)
		}
	}
	for _, bad := range []string{"PHP", "phpp", "ruby", "", " php"} {
		if ValidLang(bad) {
			t.Errorf("%q should not be a valid shellsight_lang", bad)
		}
	}
}

func TestIdentifierIsExtractedFromRuleText(t *testing.T) {
	got, err := Identifier(`rule my_shell_rule {
  condition:
    true
}`)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if got != "my_shell_rule" {
		t.Fatalf("got %q, want my_shell_rule", got)
	}
}

func TestIdentifierHandlesLeadingCommentsAndPrivateGlobal(t *testing.T) {
	got, err := Identifier(`// a comment
private global rule spaced_out : tag1 tag2 {
  condition: true
}`)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if got != "spaced_out" {
		t.Fatalf("got %q, want spaced_out", got)
	}
}

func TestIdentifierRejectsTextWithNoRule(t *testing.T) {
	if _, err := Identifier("this is not a rule"); err == nil {
		t.Fatal("expected an error when no rule declaration is present")
	}
}

func TestIdentifierRejectsTwoRulesInOneText(t *testing.T) {
	// One editor pane is one rule. Two would make revisions and exclusions ambiguous.
	_, err := Identifier(`rule a { condition: true }
rule b { condition: true }`)
	if err == nil {
		t.Fatal("expected an error when the text declares more than one rule")
	}
}

func TestLangsIsSortedAndStable(t *testing.T) {
	// Langs() ranges over a map, and Go randomises map iteration order per call. The API serves
	// this list straight to a <select>, so an unsorted result reorders the dropdown on every page
	// load -- and an analyst reaching for the same entry twice picks a different one.
	first := Langs()
	if len(first) == 0 {
		t.Fatal("Langs() is empty")
	}
	if !sort.StringsAreSorted(first) {
		t.Errorf("Langs() = %v, want sorted", first)
	}
	for i := 0; i < 20; i++ {
		if got := Langs(); !slices.Equal(got, first) {
			t.Fatalf("call %d gave %v, first call gave %v -- order is not stable", i, got, first)
		}
	}
}

func TestLangsIsNotAliasedToCallerMutation(t *testing.T) {
	// A caller sorting or truncating the returned slice must not corrupt the next caller's list.
	got := Langs()
	if len(got) < 2 {
		t.Skip("needs at least two languages to detect aliasing")
	}
	got[0] = "clobbered"
	if Langs()[0] == "clobbered" {
		t.Error("Langs() hands out a slice backed by shared state")
	}
}
