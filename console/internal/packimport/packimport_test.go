package packimport

import (
	"strings"
	"testing"
)

const pack = `// A pack header, with the imports every extracted rule may need.
import "pe"
import "hash"

private rule Helper_PRIVATE {
  strings: $h = "helper"
  condition: $h
}

rule First_Rule : tag1 tag2 {
  meta:
    author = "someone"
  strings:
    $a = "aaa"
  condition:
    Helper_PRIVATE and $a
}

/* a comment between rules, with a } brace inside it */

global rule Second_Rule {
  condition:
    pe.number_of_sections > 2
}
`

func TestSplitFindsEveryRuleIncludingPrivateAndGlobal(t *testing.T) {
	got, err := Split(pack)
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d rules, want 3", len(got))
	}
	names := []string{got[0].Identifier, got[1].Identifier, got[2].Identifier}
	want := []string{"Helper_PRIVATE", "First_Rule", "Second_Rule"}
	for i := range want {
		if names[i] != want[i] {
			t.Fatalf("rule %d is %q, want %q", i, names[i], want[i])
		}
	}
}

func TestEveryExtractedRuleCarriesThePacksImports(t *testing.T) {
	// 267 rules in the real pack reference a module namespace. A rule that lost its import
	// does not compile, so the import lines must ride along with each record.
	got, _ := Split(pack)
	for _, r := range got {
		if !strings.Contains(r.Text, `import "pe"`) || !strings.Contains(r.Text, `import "hash"`) {
			t.Fatalf("rule %s lost the pack imports:\n%s", r.Identifier, r.Text)
		}
	}
}

func TestABraceInsideACommentDoesNotSplitARule(t *testing.T) {
	// Splitting at rule STARTS rather than by brace matching is what makes this safe: the
	// splitter never has to find where a rule ends.
	got, _ := Split(pack)
	var second string
	for _, r := range got {
		if r.Identifier == "Second_Rule" {
			second = r.Text
		}
	}
	if !strings.Contains(second, "pe.number_of_sections") {
		t.Fatalf("Second_Rule was truncated:\n%s", second)
	}
}

func TestPrivateIsRecorded(t *testing.T) {
	got, _ := Split(pack)
	for _, r := range got {
		wantPrivate := r.Identifier == "Helper_PRIVATE"
		if r.Private != wantPrivate {
			t.Errorf("%s: Private=%v, want %v", r.Identifier, r.Private, wantPrivate)
		}
	}
}

func TestSplitRejectsAPackWithDuplicateIdentifiers(t *testing.T) {
	// The rules table has a UNIQUE constraint on identifier; a duplicate must be reported here
	// with both names rather than surfacing as a database error halfway through an import.
	_, err := Split(`rule Dup { condition: true }
rule Dup { condition: false }`)
	if err == nil {
		t.Fatal("expected a duplicate identifier to be rejected")
	}
	if !strings.Contains(err.Error(), "Dup") {
		t.Fatalf("error must name the duplicate, got: %v", err)
	}
}

func TestSplitOfTextWithNoRulesIsAnError(t *testing.T) {
	if _, err := Split(`import "pe"`); err == nil {
		t.Fatal("expected a pack with no rules to be rejected")
	}
}
