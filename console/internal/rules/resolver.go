package rules

import (
	"context"

	"shellsightconsole/internal/deps"
)

// Library is the slice of the store the resolver needs.
type Library interface {
	AllRuleTexts(ctx context.Context) (map[string]string, error)
}

// LibraryResolver supplies a rule's transitive dependencies from the current rule library, so the
// compile check can compile it in context.
//
// It exists because compiling a rule alone rejects any rule whose condition names another rule --
// 50 of the 5,872 shipped rules, and 16 of the first 400 in the YARA-Forge pack.
type LibraryResolver struct{ lib Library }

func NewLibraryResolver(l Library) *LibraryResolver { return &LibraryResolver{lib: l} }

// editingKey indexes the text being checked while the graph is built. It contains a NUL, so it
// cannot collide with a real YARA identifier.
const editingKey = "\x00editing"

func (r *LibraryResolver) ContextFor(ctx context.Context, text string) (map[string]string, error) {
	all, err := r.lib.AllRuleTexts(ctx)
	if err != nil {
		return nil, err
	}

	// THE EDITED RULE'S OWN PREVIOUS TEXT MUST NOT BECOME ITS CONTEXT. When an existing rule is
	// edited, the library still holds the old version under the same identifier; compiling both
	// together fails on a duplicate identifier, and the analyst would see their ordinary edit
	// rejected for a reason unrelated to what they changed.
	//
	// An unparseable identifier is ignored rather than raised: a half-typed rule must still reach
	// the compile check, which is what reports malformedness.
	if own, idErr := Identifier(text); idErr == nil {
		delete(all, own)
	}

	all[editingKey] = text
	g := deps.New(all)

	out := map[string]string{}
	for _, name := range g.DependenciesOf(editingKey) {
		if body, ok := all[name]; ok {
			out[name] = body
		}
	}
	return out, nil
}
