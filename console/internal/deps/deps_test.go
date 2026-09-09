package deps

import (
	"reflect"
	"sort"
	"testing"
)

// A miniature of the real shape: a private helper, two rules that need it, one that needs nothing,
// and one that depends on a dependent (so transitivity is exercised).
var fixture = map[string]string{
	"IsPhp": `private rule IsPhp {
  strings: $php = "<?php"
  condition: $php
}`,
	"DodgyPhp": `rule DodgyPhp {
  strings: $a = "eval("
  condition: IsPhp and $a
}`,
	"ObfuscatedPhp": `rule ObfuscatedPhp {
  strings: $b = "gzinflate"
  condition: IsPhp and $b
}`,
	"Standalone": `rule Standalone {
  strings: $c = "nothing"
  condition: $c
}`,
	"BuiltOnDodgy": `rule BuiltOnDodgy {
  condition: DodgyPhp and filesize < 100KB
}`,
}

func sorted(s []string) []string { out := append([]string(nil), s...); sort.Strings(out); return out }

func TestDirectReferencesAreFound(t *testing.T) {
	g := New(fixture)
	got := sorted(g.DependenciesOf("DodgyPhp"))
	if !reflect.DeepEqual(got, []string{"IsPhp"}) {
		t.Fatalf("DependenciesOf(DodgyPhp) = %v, want [IsPhp]", got)
	}
}

func TestKeywordsAndModulesAreNotTreatedAsReferences(t *testing.T) {
	// BuiltOnDodgy's condition is `DodgyPhp and filesize < 100KB`. Three of those tokens --
	// `and`, `filesize`, `KB` -- parse as identifiers and are not rules. Every dependency
	// reported must be an actual rule.
	//
	// Assert membership, NOT equality with a single name: DependenciesOf is transitive, so
	// IsPhp legitimately appears here via DodgyPhp. An earlier version of this test demanded
	// that every dependency equal "DodgyPhp", which contradicted
	// TestDependenciesAreTransitive below -- no implementation could satisfy both.
	g := New(fixture)
	deps := g.DependenciesOf("BuiltOnDodgy")
	if len(deps) == 0 {
		t.Fatal("expected BuiltOnDodgy to have dependencies")
	}
	for _, d := range deps {
		if _, isRule := fixture[d]; !isRule {
			t.Errorf("BuiltOnDodgy picked up a non-rule identifier: %q", d)
		}
	}
	for _, noise := range []string{"and", "filesize", "KB"} {
		for _, d := range deps {
			if d == noise {
				t.Errorf("YARA keyword %q was treated as a rule reference", noise)
			}
		}
	}
}

func TestDependenciesAreTransitive(t *testing.T) {
	// Compiling BuiltOnDodgy needs DodgyPhp, which itself needs IsPhp.
	g := New(fixture)
	got := sorted(g.DependenciesOf("BuiltOnDodgy"))
	want := []string{"DodgyPhp", "IsPhp"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("DependenciesOf(BuiltOnDodgy) = %v, want %v", got, want)
	}
}

func TestDependentsAreTransitive(t *testing.T) {
	// This is the blast radius of an exclusion: excluding IsPhp breaks three rules, not two,
	// because BuiltOnDodgy needs DodgyPhp which needs IsPhp.
	g := New(fixture)
	got := sorted(g.DependentsOf("IsPhp"))
	want := []string{"BuiltOnDodgy", "DodgyPhp", "ObfuscatedPhp"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("DependentsOf(IsPhp) = %v, want %v", got, want)
	}
}

func TestARuleNothingReferencesHasNoDependents(t *testing.T) {
	g := New(fixture)
	if got := g.DependentsOf("Standalone"); len(got) != 0 {
		t.Fatalf("DependentsOf(Standalone) = %v, want none", got)
	}
}

func TestOnlyTheConditionSectionIsScanned(t *testing.T) {
	// A rule NAME appearing in a string literal or a meta field is not a reference.
	g := New(map[string]string{
		"Target": `rule Target { condition: true }`,
		"Decoy": `rule Decoy {
  meta:
    description = "supersedes Target"
  strings:
    $s = "Target"
  condition:
    $s
}`,
	})
	if got := g.DependenciesOf("Decoy"); len(got) != 0 {
		t.Fatalf("Decoy picked up a reference from meta or strings: %v", got)
	}
}

func TestAnUnknownRuleHasNoDependenciesRatherThanPanicking(t *testing.T) {
	g := New(fixture)
	if got := g.DependenciesOf("NoSuchRule"); len(got) != 0 {
		t.Fatalf("got %v, want none", got)
	}
}
