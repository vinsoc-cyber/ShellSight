package ruleset

import (
	"shellsightconsole/internal/consoletest"
	"context"
	"strings"
	"testing"
	"time"

	"shellsightconsole/internal/blob"
	"shellsightconsole/internal/rules"
	"shellsightconsole/internal/store"
)

func yrPath(t *testing.T) string {
	t.Helper()
	if p := consoletest.FindYr(); p != "" {
		return p
	}
	t.Skip("no yr binary found; set CONSOLE_TEST_YR")
	return ""
}

// fakeSetStore serves a fixed selection and records the freeze it was asked to perform.
type fakeSetStore struct {
	revs        []store.RuleRevision
	frozenVer   int
	frozenHash  string
	frozenRevs  []int64
	freezeCalls int
	set         store.RuleSet
}

func (f *fakeSetStore) ResolveSelection(context.Context, int64) ([]store.RuleRevision, error) {
	return f.revs, nil
}
func (f *fakeSetStore) Freeze(_ context.Context, _ int64, version int, _, hash string, ids []int64) error {
	f.freezeCalls++
	f.frozenVer, f.frozenHash, f.frozenRevs = version, hash, ids
	now := time.Now()
	f.set = store.RuleSet{ID: 1, Name: "s", Version: &version, FrozenAt: &now, YarcSHA256: hash}
	return nil
}
func (f *fakeSetStore) GetRuleSet(context.Context, int64) (store.RuleSet, error) { return f.set, nil }
func (f *fakeSetStore) Audit(context.Context, string, string, string, any) error { return nil }

const ruleA = `rule alpha_rule { strings: $a = "aaa" condition: $a }`
const ruleB = `rule beta_rule  { strings: $b = "bbb" condition: $b }`
const ruleBad = `rule bad_rule { condition: $nope and }`

func TestFreezeCompilesTheSelectionAndStoresTheBlob(t *testing.T) {
	f := &fakeSetStore{revs: []store.RuleRevision{
		{ID: 11, RuleID: 1, Text: ruleA},
		{ID: 22, RuleID: 2, Text: ruleB},
	}}
	bs := blob.New(t.TempDir())
	svc := NewService(f, bs, rules.NewCompiler(yrPath(t)))

	hash, err := svc.Freeze(context.Background(), 1, 1, "v.quannh67")
	if err != nil {
		t.Fatalf("freeze: %v", err)
	}
	if len(hash) != 64 {
		t.Fatalf("hash %q is not a sha256", hash)
	}
	body, err := bs.Get(hash)
	if err != nil {
		t.Fatalf("blob not stored: %v", err)
	}
	if len(body) == 0 {
		t.Fatal("stored an empty blob")
	}
	if f.freezeCalls != 1 || f.frozenHash != hash {
		t.Fatalf("store was not told about the blob: %+v", f)
	}
	if len(f.frozenRevs) != 2 {
		t.Fatalf("pinned %d revisions, want 2", len(f.frozenRevs))
	}
}

func TestFreezeIsRefusedWhenTheSelectionDoesNotCompile(t *testing.T) {
	f := &fakeSetStore{revs: []store.RuleRevision{
		{ID: 11, RuleID: 1, Text: ruleA},
		{ID: 33, RuleID: 3, Text: ruleBad},
	}}
	svc := NewService(f, blob.New(t.TempDir()), rules.NewCompiler(yrPath(t)))

	_, err := svc.Freeze(context.Background(), 1, 1, "a")
	if err == nil {
		t.Fatal("expected freeze to be refused when the set does not compile")
	}
	if !strings.Contains(err.Error(), "syntax error") {
		t.Fatalf("error must carry yr's message, got: %v", err)
	}
	if f.freezeCalls != 0 {
		t.Fatal("a set that does not compile must never be recorded as frozen")
	}
}

func TestFreezeIsRefusedWhenTheSelectionIsEmpty(t *testing.T) {
	// An agent built from an empty set would silently detect nothing.
	f := &fakeSetStore{revs: nil}
	svc := NewService(f, blob.New(t.TempDir()), rules.NewCompiler(yrPath(t)))
	if _, err := svc.Freeze(context.Background(), 1, 1, "a"); err == nil {
		t.Fatal("expected freezing an empty selection to be refused")
	}
}

func TestFreezeIsDeterministic(t *testing.T) {
	// The same revisions must produce the same blob hash, or byte-identical rebuilds are impossible.
	mk := func() *Service {
		return NewService(&fakeSetStore{revs: []store.RuleRevision{
			{ID: 11, RuleID: 1, Text: ruleA},
			{ID: 22, RuleID: 2, Text: ruleB},
		}}, blob.New(t.TempDir()), rules.NewCompiler(yrPath(t)))
	}
	a, err := mk().Freeze(context.Background(), 1, 1, "a")
	if err != nil {
		t.Fatal(err)
	}
	b, err := mk().Freeze(context.Background(), 1, 1, "a")
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatalf("same selection produced different blobs: %s vs %s", a, b)
	}
}

// fakeGraph reports a fixed blast radius, so the gate's behaviour is testable without a library.
type fakeGraph struct{ dependents map[string][]string }

func (f *fakeGraph) DependentsOf(name string) []string { return f.dependents[name] }

func TestExcludingAnUnreferencedRuleIsAllowed(t *testing.T) {
	g := &fakeGraph{dependents: map[string][]string{}}
	svc := NewService(&fakeSetStore{}, blob.New(t.TempDir()), rules.NewCompiler(yrPath(t)))
	svc.SetGraph(g)

	if err := svc.CheckExclusion("Standalone"); err != nil {
		t.Fatalf("excluding a rule nothing references was refused: %v", err)
	}
}

func TestExcludingAReferencedRuleIsRefusedAndNamesWhatBreaks(t *testing.T) {
	// Measured on the shipped packs: excluding IsWhitelisted breaks 9 rules, b64 breaks 10.
	// Because there is no partial-success mode, that blocks EVERY analyst's builds -- so the
	// gate refuses rather than warns.
	g := &fakeGraph{dependents: map[string][]string{
		"IsPhp": {"DodgyPhp", "ObfuscatedPhp"},
	}}
	svc := NewService(&fakeSetStore{}, blob.New(t.TempDir()), rules.NewCompiler(yrPath(t)))
	svc.SetGraph(g)

	err := svc.CheckExclusion("IsPhp")
	if err == nil {
		t.Fatal("expected excluding a referenced rule to be refused")
	}
	for _, want := range []string{"DodgyPhp", "ObfuscatedPhp"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error must name what would break; %q missing from: %v", want, err)
		}
	}
}

func TestExcludingARuleAndAllItsDependentsTogetherIsAllowed(t *testing.T) {
	// The escape hatch: exclude the whole dependent cluster and the set still compiles.
	g := &fakeGraph{dependents: map[string][]string{
		"IsPhp": {"DodgyPhp", "ObfuscatedPhp"},
	}}
	svc := NewService(&fakeSetStore{}, blob.New(t.TempDir()), rules.NewCompiler(yrPath(t)))
	svc.SetGraph(g)

	if err := svc.CheckExclusionSet([]string{"IsPhp", "DodgyPhp", "ObfuscatedPhp"}); err != nil {
		t.Fatalf("excluding a rule together with all its dependents was refused: %v", err)
	}
}
