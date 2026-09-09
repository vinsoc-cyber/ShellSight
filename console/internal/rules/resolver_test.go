package rules

import (
	"context"
	"testing"
)

type fakeLibrary struct{ texts map[string]string }

func (f *fakeLibrary) AllRuleTexts(context.Context) (map[string]string, error) {
	out := map[string]string{}
	for k, v := range f.texts {
		out[k] = v
	}
	return out, nil
}

const libHelper = `private rule Helper_PRIVATE {
  strings:
    $h = "helper"
  condition:
    $h
}`

func TestResolverSuppliesADependency(t *testing.T) {
	r := NewLibraryResolver(&fakeLibrary{texts: map[string]string{
		"Helper_PRIVATE": libHelper,
		"unrelated":      `rule unrelated { condition: true }`,
	}})
	got, err := r.ContextFor(context.Background(), dependentRule)
	if err != nil {
		t.Fatalf("ContextFor: %v", err)
	}
	if _, ok := got["Helper_PRIVATE"]; !ok {
		t.Fatalf("dependency not supplied: %v", keysOf(got))
	}
	if _, ok := got["unrelated"]; ok {
		t.Fatalf("an unreferenced rule was supplied as context: %v", keysOf(got))
	}
}

func TestResolverExcludesTheEditedRulesOwnOldText(t *testing.T) {
	// Editing a rule that is already in the library. Supplying its OLD text as context would put
	// the same identifier in the compile twice, and yr fails on a duplicate identifier -- so an
	// ordinary edit would be rejected for a reason that has nothing to do with the analyst's change.
	const oldText = `rule needs_helper { condition: false }`
	r := NewLibraryResolver(&fakeLibrary{texts: map[string]string{
		"Helper_PRIVATE": libHelper,
		"needs_helper":   oldText,
	}})
	got, err := r.ContextFor(context.Background(), dependentRule)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := got["needs_helper"]; ok {
		t.Fatal("the edited rule's own previous text was supplied as its own context")
	}
	if _, ok := got["Helper_PRIVATE"]; !ok {
		t.Fatal("the real dependency was lost")
	}
}

func TestResolverReturnsNothingForARuleThatReferencesNothing(t *testing.T) {
	r := NewLibraryResolver(&fakeLibrary{texts: map[string]string{"Helper_PRIVATE": libHelper}})
	got, err := r.ContextFor(context.Background(), validRule)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("got %v, want no context", keysOf(got))
	}
}

func TestResolverToleratesUnparseableText(t *testing.T) {
	// A half-typed rule must not make the resolver error; the compile check is what reports
	// malformedness, and it needs to run to do that.
	r := NewLibraryResolver(&fakeLibrary{texts: map[string]string{"Helper_PRIVATE": libHelper}})
	if _, err := r.ContextFor(context.Background(), "rule broken {"); err != nil {
		t.Fatalf("resolver should tolerate unparseable text, got: %v", err)
	}
}

func keysOf(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
