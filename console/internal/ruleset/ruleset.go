// Package ruleset composes rules into named sets and freezes them.
//
// Freezing is where the console's central design decision lives: the selection is compiled HERE,
// once, into a YARA-X `.yarc` blob, and that blob is what a generated agent embeds. Measured
// 2026-08-30, this is detection-identical to shipping rule source (0 differences over 37,578 files,
// and over 5,382 more on linux/arm64), and it buys three things beyond removing the compile from
// every scan: a frozen set becomes one hashable artefact, an exclusion needs no runtime mechanism
// because an excluded rule is simply not compiled in, and rule source never reaches a host that is
// assumed to be compromised.
package ruleset

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"shellsightconsole/internal/blob"
	"shellsightconsole/internal/rules"
	"shellsightconsole/internal/store"
)

// SetStore is the slice of store.Store this service needs.
type SetStore interface {
	ResolveSelection(ctx context.Context, ruleSetID int64) ([]store.RuleRevision, error)
	Freeze(ctx context.Context, ruleSetID int64, version int, frozenBy, yarcSHA256 string, revisionIDs []int64) error
	GetRuleSet(ctx context.Context, id int64) (store.RuleSet, error)
	Audit(ctx context.Context, actor, action, subject string, detail any) error
}

type Service struct {
	store    SetStore
	blobs    *blob.Store
	compiler *rules.Compiler
	graph    Graph
}

func NewService(s SetStore, b *blob.Store, c *rules.Compiler) *Service {
	return &Service{store: s, blobs: b, compiler: c}
}

// Freeze compiles the set's current selection, stores the blob, and records the freeze.
//
// Order matters: compile, store the blob, THEN record. Recording a freeze whose blob does not
// exist would leave a rule set that claims to be buildable and is not.
func (s *Service) Freeze(ctx context.Context, ruleSetID int64, version int, actor string) (string, error) {
	revs, err := s.store.ResolveSelection(ctx, ruleSetID)
	if err != nil {
		return "", err
	}
	if len(revs) == 0 {
		return "", fmt.Errorf("this selection contains no rules; an agent built from it would detect nothing")
	}

	dir, err := os.MkdirTemp("", "console-set-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(dir)

	// Deterministic file names and ordering: byte-identical regeneration of a recorded build
	// depends on the same selection producing the same blob every time.
	sorted := make([]store.RuleRevision, len(revs))
	copy(sorted, revs)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].RuleID < sorted[j].RuleID })

	ids := make([]int64, 0, len(sorted))
	for _, r := range sorted {
		name := fmt.Sprintf("%012d.yar", r.RuleID)
		if err := os.WriteFile(filepath.Join(dir, name), []byte(r.Text), 0o644); err != nil {
			return "", err
		}
		ids = append(ids, r.ID)
	}

	compiled, err := s.compiler.CompileDir(dir)
	if err != nil {
		return "", err
	}
	hash, err := s.blobs.Put(compiled)
	if err != nil {
		return "", err
	}
	if err := s.store.Freeze(ctx, ruleSetID, version, actor, hash, ids); err != nil {
		return "", err
	}
	_ = s.store.Audit(ctx, actor, "ruleset.freeze", fmt.Sprintf("%d", ruleSetID),
		map[string]any{"version": version, "rules": len(ids), "yarc_sha256": hash})
	return hash, nil
}

// Graph reports which rules would fail to compile if a given rule were removed.
// Satisfied by *deps.Graph.
type Graph interface {
	DependentsOf(name string) []string
}

// SetGraph installs the reference graph the exclusion gate consults. It is set separately from
// the constructor because the graph is rebuilt whenever the library changes, while the service
// is long-lived.
func (s *Service) SetGraph(g Graph) { s.graph = g }

// CheckExclusion reports whether excluding one rule would orphan another.
//
// This refuses rather than warns, and the asymmetry is deliberate: a warning is dismissed by the
// analyst who caused the problem, while the consequence lands on everybody else. Excluding a
// referenced rule leaves an unresolved identifier, and a compile with an unresolved identifier
// produces NO blob at all -- so one dismissed warning stops the whole team building agents until
// somebody traces it.
func (s *Service) CheckExclusion(identifier string) error {
	return s.CheckExclusionSet([]string{identifier})
}

// CheckExclusionSet is the same question for several exclusions at once, and is what makes the
// escape hatch work: excluding a rule TOGETHER WITH everything that depends on it is safe, because
// nothing is left referencing it.
func (s *Service) CheckExclusionSet(identifiers []string) error {
	if s.graph == nil {
		return fmt.Errorf("no rule reference graph is loaded; refusing to judge an exclusion blind")
	}
	excluded := make(map[string]bool, len(identifiers))
	for _, id := range identifiers {
		excluded[id] = true
	}
	for _, id := range identifiers {
		var orphaned []string
		for _, dep := range s.graph.DependentsOf(id) {
			if !excluded[dep] {
				orphaned = append(orphaned, dep)
			}
		}
		if len(orphaned) > 0 {
			sort.Strings(orphaned)
			return fmt.Errorf(
				"excluding %s would break %d rule(s) that reference it: %s. "+
					"Exclude those as well, or leave %s in the set",
				id, len(orphaned), strings.Join(orphaned, ", "), id)
		}
	}
	return nil
}
