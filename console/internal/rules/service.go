package rules

import (
	"context"
	"fmt"

	"shellsightconsole/internal/store"
)

// RuleStore is the slice of store.Store this service needs. Depending on the narrow interface
// rather than the whole Store keeps the service testable without a database.
type RuleStore interface {
	CreateRule(ctx context.Context, r store.Rule, rev store.RuleRevision) (int64, error)
	GetRule(ctx context.Context, id int64) (store.Rule, store.RuleRevision, error)
	AddRevision(ctx context.Context, ruleID int64, rev store.RuleRevision) (int, error)
	SoftDeleteRule(ctx context.Context, ruleID int64) error
	Audit(ctx context.Context, actor, action, subject string, detail any) error
}

// DepResolver supplies the transitive dependencies of a rule as identifier -> text, so the compile
// check can compile it in context. Backed by internal/console/deps over the current library; a
// stub returning nil is correct for a library in which nothing references anything.
type DepResolver interface {
	ContextFor(ctx context.Context, text string) (map[string]string, error)
}

type Service struct {
	store    RuleStore
	compiler *Compiler
	deps     DepResolver
}

func NewService(s RuleStore, c *Compiler, d DepResolver) *Service {
	return &Service{store: s, compiler: c, deps: d}
}

// checkInContext resolves the rule's dependencies and compiles it alongside them.
//
// Compiling in isolation is wrong for 50 of the 5,872 shipped rules -- see CheckRule. A resolver
// failure is fatal rather than ignored: falling back to an isolated compile would reject exactly
// the rules this exists to accept.
func (s *Service) checkInContext(ctx context.Context, text string) error {
	deps, err := s.deps.ContextFor(ctx, text)
	if err != nil {
		return fmt.Errorf("resolving rule dependencies: %w", err)
	}
	return s.compiler.CheckRule(text, deps)
}

// editableLayers are the layers the console will write to. `foundation` is absent by design (D7):
// its text is a mirror of an upstream pack, and editing it means the next signature-base or
// YARA-Forge refresh either overwrites the change or conflicts with it across thousands of rules.
// A foundation rule you disagree with is excluded from a rule set, never rewritten.
var editableLayers = map[string]bool{"own": true, "custom": true}

func (s *Service) Create(ctx context.Context, layer, text, lang, author string) (int64, error) {
	if !editableLayers[layer] {
		return 0, fmt.Errorf("layer %q is not writable; foundation rules are exclude-only", layer)
	}
	if lang != "" && !ValidLang(lang) {
		return 0, fmt.Errorf("shellsight_lang %q is not one of the values the rule gate understands", lang)
	}
	ident, err := Identifier(text)
	if err != nil {
		return 0, err
	}
	if err := s.checkInContext(ctx, text); err != nil {
		return 0, err
	}
	id, err := s.store.CreateRule(ctx,
		store.Rule{Identifier: ident, Layer: layer},
		store.RuleRevision{Text: text, Lang: lang, Author: author})
	if err != nil {
		return 0, err
	}
	_ = s.store.Audit(ctx, author, "rule.create", ident, map[string]any{"layer": layer, "lang": lang})
	return id, nil
}

func (s *Service) Edit(ctx context.Context, id int64, text, lang, author string) (int, error) {
	rule, _, err := s.store.GetRule(ctx, id)
	if err != nil {
		return 0, err
	}
	if !editableLayers[rule.Layer] {
		return 0, fmt.Errorf("rule %s is in the %s layer and cannot be edited; exclude it from a rule set instead",
			rule.Identifier, rule.Layer)
	}
	if lang != "" && !ValidLang(lang) {
		return 0, fmt.Errorf("shellsight_lang %q is not one of the values the rule gate understands", lang)
	}
	if _, err := Identifier(text); err != nil {
		return 0, err
	}
	if err := s.checkInContext(ctx, text); err != nil {
		return 0, err
	}
	n, err := s.store.AddRevision(ctx, id, store.RuleRevision{Text: text, Lang: lang, Author: author})
	if err != nil {
		return 0, err
	}
	_ = s.store.Audit(ctx, author, "rule.edit", rule.Identifier, map[string]any{"revision": n})
	return n, nil
}

func (s *Service) Delete(ctx context.Context, id int64, actor string) error {
	rule, _, err := s.store.GetRule(ctx, id)
	if err != nil {
		return err
	}
	if !editableLayers[rule.Layer] {
		return fmt.Errorf("rule %s is in the %s layer and cannot be deleted", rule.Identifier, rule.Layer)
	}
	if err := s.store.SoftDeleteRule(ctx, id); err != nil {
		return err
	}
	_ = s.store.Audit(ctx, actor, "rule.delete", rule.Identifier, nil)
	return nil
}
