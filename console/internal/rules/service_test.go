package rules

import (
	"context"
	"strings"
	"testing"

	"shellsightconsole/internal/store"
)

// fakeStore records what the service asked it to do. Only the methods the service uses exist.
type fakeStore struct {
	rules   map[int64]store.Rule
	revs    map[int64]store.RuleRevision
	nextID  int64
	created int
	revised int
	deleted int
	audits  int
}

func newFake() *fakeStore {
	return &fakeStore{rules: map[int64]store.Rule{}, revs: map[int64]store.RuleRevision{}, nextID: 1}
}

func (f *fakeStore) CreateRule(_ context.Context, r store.Rule, rev store.RuleRevision) (int64, error) {
	id := f.nextID
	f.nextID++
	r.ID = id
	rev.Revision = 1
	f.rules[id], f.revs[id] = r, rev
	f.created++
	return id, nil
}
func (f *fakeStore) GetRule(_ context.Context, id int64) (store.Rule, store.RuleRevision, error) {
	return f.rules[id], f.revs[id], nil
}
func (f *fakeStore) AddRevision(_ context.Context, id int64, rev store.RuleRevision) (int, error) {
	n := f.revs[id].Revision + 1
	rev.Revision = n
	f.revs[id] = rev
	f.revised++
	return n, nil
}
func (f *fakeStore) SoftDeleteRule(_ context.Context, id int64) error     { f.deleted++; return nil }
func (f *fakeStore) Audit(_ context.Context, _, _, _ string, _ any) error { f.audits++; return nil }

// fakeDeps supplies whatever dependency context a test wants. Empty by default, because most
// rules reference nothing.
type fakeDeps struct{ ctx map[string]string }

func (f *fakeDeps) ContextFor(context.Context, string) (map[string]string, error) {
	return f.ctx, nil
}

func newService(t *testing.T) (*Service, *fakeStore) {
	t.Helper()
	f := newFake()
	return NewService(f, NewCompiler(yrPath(t)), &fakeDeps{}), f
}

func TestARuleWithADependencyIsAcceptedWhenTheResolverSuppliesIt(t *testing.T) {
	// Guards the defect this design was corrected for: the service must compile the rule with
	// its dependencies, not alone. Without the resolver this save would be refused.
	f := newFake()
	svc := NewService(f, NewCompiler(yrPath(t)),
		&fakeDeps{ctx: map[string]string{"Helper_PRIVATE": helperRule}})

	if _, err := svc.Create(context.Background(), "custom", dependentRule, "php", "v.quannh67"); err != nil {
		t.Fatalf("a rule with a supplied dependency was rejected: %v", err)
	}
	if f.created != 1 {
		t.Fatalf("expected the rule to be stored, created=%d", f.created)
	}
}

func TestCreateRejectsARuleThatDoesNotCompile(t *testing.T) {
	svc, f := newService(t)
	_, err := svc.Create(context.Background(), "custom", brokenRule, "php", "v.quannh67")
	if err == nil {
		t.Fatal("expected a non-compiling rule to be rejected")
	}
	if !strings.Contains(err.Error(), "syntax error") {
		t.Fatalf("error must carry yr's message, got: %v", err)
	}
	if f.created != 0 {
		t.Fatal("a rule that does not compile must never reach the store")
	}
}

func TestCreateStoresAValidRuleAndAudits(t *testing.T) {
	svc, f := newService(t)
	id, err := svc.Create(context.Background(), "custom", validRule, "php", "v.quannh67")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if id == 0 || f.created != 1 {
		t.Fatalf("expected one stored rule, got id=%d created=%d", id, f.created)
	}
	if f.audits != 1 {
		t.Fatalf("expected one audit entry, got %d", f.audits)
	}
	if f.rules[id].Identifier != "ok_rule" {
		t.Fatalf("identifier was not extracted from the text: %q", f.rules[id].Identifier)
	}
}

func TestCreateRejectsAnInvalidLanguage(t *testing.T) {
	svc, _ := newService(t)
	if _, err := svc.Create(context.Background(), "custom", validRule, "ruby", "a"); err == nil {
		t.Fatal("expected an invalid shellsight_lang to be rejected")
	}
}

func TestCreateRejectsAnUnknownLayer(t *testing.T) {
	svc, _ := newService(t)
	if _, err := svc.Create(context.Background(), "made-up", validRule, "php", "a"); err == nil {
		t.Fatal("expected an unknown layer to be rejected")
	}
}

func TestFoundationRulesCannotBeCreatedEditedOrDeleted(t *testing.T) {
	// Design D7: foundation is exclude-only. Editing upstream text forfeits the next pack refresh.
	svc, f := newService(t)
	ctx := context.Background()

	if _, err := svc.Create(ctx, "foundation", validRule, "php", "a"); err == nil {
		t.Fatal("expected creating a foundation rule through the API to be refused")
	}

	// Seed one as the import path would, bypassing the service.
	f.rules[9] = store.Rule{ID: 9, Identifier: "DodgyPhp", Layer: "foundation"}
	f.revs[9] = store.RuleRevision{Revision: 1, Text: validRule}

	if _, err := svc.Edit(ctx, 9, validRule, "php", "a"); err == nil {
		t.Fatal("expected editing a foundation rule to be refused")
	}
	if err := svc.Delete(ctx, 9, "a"); err == nil {
		t.Fatal("expected deleting a foundation rule to be refused")
	}
	if f.revised != 0 || f.deleted != 0 {
		t.Fatal("a foundation rule must not be modified in the store")
	}
}

func TestEditAppendsARevisionForOwnAndCustomLayers(t *testing.T) {
	svc, f := newService(t)
	ctx := context.Background()
	id, err := svc.Create(ctx, "own", validRule, "php", "a")
	if err != nil {
		t.Fatal(err)
	}
	n, err := svc.Edit(ctx, id, validRule, "jsp", "b")
	if err != nil {
		t.Fatalf("edit: %v", err)
	}
	if n != 2 {
		t.Fatalf("edit produced revision %d, want 2", n)
	}
	if f.revised != 1 {
		t.Fatalf("expected one revision appended, got %d", f.revised)
	}
}
