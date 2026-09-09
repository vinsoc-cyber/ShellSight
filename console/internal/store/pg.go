package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"shellsightconsole/internal/rulemeta"
)

type PG struct{ pool *pgxpool.Pool }

func NewPG(pool *pgxpool.Pool) *PG { return &PG{pool: pool} }

// PublishRelease inserts the release and all its files in one transaction. A partially inserted
// release would be a release whose manifest does not describe it, which is exactly the state
// verification exists to prevent.
func (p *PG) PublishRelease(ctx context.Context, r Release, files []ReleaseFile) (int64, error) {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var id int64
	err = tx.QueryRow(ctx,
		`INSERT INTO releases (version, target, published_by) VALUES ($1,$2,$3) RETURNING id`,
		r.Version, r.Target, r.PublishedBy).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("insert release: %w", err)
	}
	for _, f := range files {
		if _, err := tx.Exec(ctx,
			`INSERT INTO release_files (release_id, path, sha256) VALUES ($1,$2,$3)`,
			id, f.Path, f.SHA256); err != nil {
			return 0, fmt.Errorf("insert release file %s: %w", f.Path, err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return id, nil
}

func (p *PG) ListReleases(ctx context.Context) ([]Release, error) {
	rows, err := p.pool.Query(ctx,
		`SELECT id, version, target, published_at, published_by
		   FROM releases ORDER BY published_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Release
	for rows.Next() {
		var r Release
		if err := rows.Scan(&r.ID, &r.Version, &r.Target, &r.PublishedAt, &r.PublishedBy); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// GetRelease reads one release by id.
//
// By id, not by version: (version, target) is the natural key in `releases`, so a version string
// alone names as many rows as there are targets. Agent generation needs the TARGET to know which
// declaration it is assembling from, and a lookup that could not distinguish linux-amd64 from
// linux-arm64 would assemble an agent for the wrong processor.
func (p *PG) GetRelease(ctx context.Context, id int64) (Release, error) {
	var r Release
	err := p.pool.QueryRow(ctx,
		`SELECT id, version, target, published_at, published_by FROM releases WHERE id=$1`, id).
		Scan(&r.ID, &r.Version, &r.Target, &r.PublishedAt, &r.PublishedBy)
	return r, err
}

func (p *PG) ReleaseFiles(ctx context.Context, releaseID int64) ([]ReleaseFile, error) {
	rows, err := p.pool.Query(ctx,
		`SELECT path, sha256 FROM release_files WHERE release_id=$1 ORDER BY path`, releaseID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ReleaseFile
	for rows.Next() {
		var f ReleaseFile
		if err := rows.Scan(&f.Path, &f.SHA256); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

func (p *PG) Audit(ctx context.Context, actor, action, subject string, detail any) error {
	var raw []byte
	if detail != nil {
		b, err := json.Marshal(detail)
		if err != nil {
			return err
		}
		raw = b
	}
	_, err := p.pool.Exec(ctx,
		`INSERT INTO audit_log (actor, action, subject, detail) VALUES ($1,$2,$3,$4)`,
		actor, action, subject, raw)
	return err
}

// errNoRows is re-exported so domain packages can test for absence without importing pgx.
var ErrNotFound = pgx.ErrNoRows

func (p *PG) CreateRule(ctx context.Context, r Rule, rev RuleRevision) (int64, error) {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var id int64
	err = tx.QueryRow(ctx,
		`INSERT INTO rules (identifier, layer, source_pack) VALUES ($1,$2,NULLIF($3,''))
		 RETURNING id`, r.Identifier, r.Layer, r.SourcePack).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("insert rule: %w", err)
	}
	md := rulemeta.Parse(rev.Text)
	if _, err := tx.Exec(ctx,
		`INSERT INTO rule_revisions (rule_id, revision, text, lang, author, description, score, meta)
		 VALUES ($1,1,$2,NULLIF($3,''),$4,NULLIF($5,''),$6,$7)`,
		id, rev.Text, rev.Lang, rev.Author, md.Description, md.Score, md.Keys); err != nil {
		return 0, fmt.Errorf("insert revision: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return id, nil
}

// GetRule returns the rule and its LATEST revision.
func (p *PG) GetRule(ctx context.Context, id int64) (Rule, RuleRevision, error) {
	var r Rule
	var rev RuleRevision
	var pack, lang *string
	err := p.pool.QueryRow(ctx,
		`SELECT ru.id, ru.identifier, ru.layer, ru.source_pack,
		        rv.id, rv.revision, rv.text, rv.lang, rv.author, rv.created_at,
		        COALESCE(rv.description,''), rv.score, COALESCE(rv.meta,'{}'::jsonb)
		   FROM rules ru
		   JOIN rule_revisions rv ON rv.rule_id = ru.id
		  WHERE ru.id = $1
		  ORDER BY rv.revision DESC
		  LIMIT 1`, id).
		Scan(&r.ID, &r.Identifier, &r.Layer, &pack,
			&rev.ID, &rev.Revision, &rev.Text, &lang, &rev.Author, &rev.CreatedAt,
			&rev.Description, &rev.Score, &rev.Meta)
	if err != nil {
		return Rule{}, RuleRevision{}, err
	}
	if pack != nil {
		r.SourcePack = *pack
	}
	if lang != nil {
		rev.Lang = *lang
	}
	rev.RuleID = r.ID
	return r, rev, nil
}

// RuleIndex is the whole library as the rule browser needs it, one row per non-deleted rule at its
// latest revision, ordered by identifier.
//
// DISTINCT ON requires its own expression to lead the ORDER BY, so the alphabetical ordering the
// browser wants is applied by the outer query.
func (p *PG) RuleIndex(ctx context.Context) ([]RuleIndexRow, error) {
	rows, err := p.pool.Query(ctx,
		`SELECT id, identifier, layer, source_pack, score, description FROM (
		   SELECT DISTINCT ON (ru.id)
		          ru.id, ru.identifier, ru.layer,
		          COALESCE(ru.source_pack,'') AS source_pack,
		          rv.score, COALESCE(rv.description,'') AS description
		     FROM rules ru
		     JOIN rule_revisions rv ON rv.rule_id = ru.id
		    WHERE ru.deleted_at IS NULL
		    ORDER BY ru.id, rv.revision DESC
		 ) latest
		 ORDER BY identifier`)
	if err != nil {
		return nil, fmt.Errorf("building the rule index: %w", err)
	}
	defer rows.Close()

	out := []RuleIndexRow{}
	for rows.Next() {
		var r RuleIndexRow
		if err := rows.Scan(&r.ID, &r.Identifier, &r.Layer, &r.SourcePack,
			&r.Score, &r.Description); err != nil {
			return nil, fmt.Errorf("scanning an index row: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// AddRevision appends a revision and returns its number.
//
// THE LOCK IS ON THE PARENT ROW, NOT ON THE REVISIONS, and that is not a stylistic choice.
// PostgreSQL rejects a locking clause on any query containing an aggregate --
// `SELECT MAX(...) ... FOR UPDATE` raises SQLSTATE 0A000, "FOR UPDATE is not allowed with
// aggregate functions". An earlier draft of this plan did exactly that, so AddRevision failed on
// every call, not merely under contention. Locking `rules.id` serialises concurrent writers for
// this rule, after which MAX is computed safely inside the same transaction.
//
// Selecting the parent also makes AddRevision reject an unknown rule id, instead of inserting a
// revision that belongs to nothing.
func (p *PG) AddRevision(ctx context.Context, ruleID int64, rev RuleRevision) (int, error) {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var locked int64
	if err := tx.QueryRow(ctx,
		`SELECT id FROM rules WHERE id=$1 FOR UPDATE`, ruleID).Scan(&locked); err != nil {
		return 0, fmt.Errorf("locking rule %d: %w", ruleID, err)
	}

	var next int
	if err := tx.QueryRow(ctx,
		`SELECT COALESCE(MAX(revision),0)+1 FROM rule_revisions WHERE rule_id=$1`,
		ruleID).Scan(&next); err != nil {
		return 0, err
	}
	md := rulemeta.Parse(rev.Text)
	if _, err := tx.Exec(ctx,
		`INSERT INTO rule_revisions (rule_id, revision, text, lang, author, description, score, meta)
		 VALUES ($1,$2,$3,NULLIF($4,''),$5,NULLIF($6,''),$7,$8)`,
		ruleID, next, rev.Text, rev.Lang, rev.Author, md.Description, md.Score, md.Keys); err != nil {
		return 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return next, nil
}

// ListRules returns undeleted rules; layer=="" means every layer.
func (p *PG) ListRules(ctx context.Context, layer string) ([]Rule, error) {
	rows, err := p.pool.Query(ctx,
		`SELECT id, identifier, layer, COALESCE(source_pack,'')
		   FROM rules
		  WHERE deleted_at IS NULL AND ($1 = '' OR layer = $1)
		  ORDER BY identifier`, layer)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Rule
	for rows.Next() {
		var r Rule
		if err := rows.Scan(&r.ID, &r.Identifier, &r.Layer, &r.SourcePack); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// SoftDeleteRule hides a rule from the library without removing its revisions: a frozen rule set
// that contains one of those revisions must stay reconstructible.
func (p *PG) SoftDeleteRule(ctx context.Context, ruleID int64) error {
	_, err := p.pool.Exec(ctx, `UPDATE rules SET deleted_at = now() WHERE id = $1`, ruleID)
	return err
}

// BackfillMeta re-parses every stored revision and writes the metadata columns.
//
// It reads the rule text already in the database, so it needs no pack files and no re-import. It is
// idempotent: parsing is a pure function of the text, so a second run writes the same values.
func (p *PG) BackfillMeta(ctx context.Context) (MetaCoverage, error) {
	cov := MetaCoverage{Keys: map[string]int{}}

	rows, err := p.pool.Query(ctx, `SELECT id, text FROM rule_revisions ORDER BY id`)
	if err != nil {
		return cov, fmt.Errorf("reading revisions: %w", err)
	}
	type parsed struct {
		id int64
		md rulemeta.Meta
	}
	var all []parsed
	for rows.Next() {
		var id int64
		var text string
		if err := rows.Scan(&id, &text); err != nil {
			rows.Close()
			return cov, fmt.Errorf("scanning a revision: %w", err)
		}
		all = append(all, parsed{id, rulemeta.Parse(text)})
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return cov, err
	}

	// Counted from the parse, before any write, so the report describes what the parser found
	// rather than what the database happened to accept.
	for _, e := range all {
		cov.Revisions++
		if !e.md.HasBlock {
			cov.NoMetaBlock++
		}
		if e.md.Description != "" {
			cov.Description++
		}
		if e.md.Score != nil {
			cov.Score++
		}
		for k := range e.md.Keys {
			cov.Keys[k]++
		}
	}

	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return cov, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	for _, e := range all {
		if _, err := tx.Exec(ctx,
			`UPDATE rule_revisions SET description=NULLIF($2,''), score=$3, meta=$4 WHERE id=$1`,
			e.id, e.md.Description, e.md.Score, e.md.Keys); err != nil {
			return cov, fmt.Errorf("updating revision %d: %w", e.id, err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return cov, err
	}
	return cov, nil
}

func (p *PG) CreateRuleSet(ctx context.Context, name, createdBy string) (int64, error) {
	var id int64
	err := p.pool.QueryRow(ctx,
		`INSERT INTO rule_sets (name, created_by) VALUES ($1,$2) RETURNING id`,
		name, createdBy).Scan(&id)
	return id, err
}

func (p *PG) SetSelection(ctx context.Context, ruleSetID int64, sel Selection) error {
	raw, err := json.Marshal(sel)
	if err != nil {
		return err
	}
	ct, err := p.pool.Exec(ctx,
		`UPDATE rule_sets SET selection=$2 WHERE id=$1 AND frozen_at IS NULL`, ruleSetID, raw)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return fmt.Errorf("rule set %d is frozen or does not exist; frozen sets are immutable", ruleSetID)
	}
	return nil
}

func (p *PG) GetSelection(ctx context.Context, ruleSetID int64) (Selection, error) {
	var raw []byte
	if err := p.pool.QueryRow(ctx,
		`SELECT selection FROM rule_sets WHERE id=$1`, ruleSetID).Scan(&raw); err != nil {
		return Selection{}, err
	}
	var sel Selection
	err := json.Unmarshal(raw, &sel)
	return sel, err
}

func (p *PG) AddExclusion(ctx context.Context, ruleSetID, ruleID int64, reason, author string) error {
	if reason == "" {
		return fmt.Errorf("an exclusion must carry a reason")
	}
	_, err := p.pool.Exec(ctx,
		`INSERT INTO rule_set_exclusions (rule_set_id, rule_id, reason, author)
		 VALUES ($1,$2,$3,$4)
		 ON CONFLICT (rule_set_id, rule_id) DO UPDATE SET reason=$3, author=$4, created_at=now()`,
		ruleSetID, ruleID, reason, author)
	return err
}

func (p *PG) ListExclusions(ctx context.Context, ruleSetID int64) ([]Exclusion, error) {
	rows, err := p.pool.Query(ctx,
		`SELECT e.rule_id, r.identifier, e.reason, e.author, e.created_at
		   FROM rule_set_exclusions e JOIN rules r ON r.id = e.rule_id
		  WHERE e.rule_set_id = $1 ORDER BY r.identifier`, ruleSetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Exclusion
	for rows.Next() {
		var e Exclusion
		if err := rows.Scan(&e.RuleID, &e.Identifier, &e.Reason, &e.Author, &e.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ResolveSelection returns the LATEST revision of every rule the draft selection includes, minus
// this set's exclusions. It is what freeze compiles; a frozen set reads FrozenMembers instead.
func (p *PG) ResolveSelection(ctx context.Context, ruleSetID int64) ([]RuleRevision, error) {
	sel, err := p.GetSelection(ctx, ruleSetID)
	if err != nil {
		return nil, err
	}
	layers := sel.Layers
	if layers == nil {
		layers = []string{}
	}
	ids := sel.Rules
	if ids == nil {
		ids = []int64{}
	}
	rows, err := p.pool.Query(ctx,
		`SELECT DISTINCT ON (ru.id) rv.id, rv.rule_id, rv.revision, rv.text,
		        COALESCE(rv.lang,''), rv.author, rv.created_at
		   FROM rules ru
		   JOIN rule_revisions rv ON rv.rule_id = ru.id
		  WHERE ru.deleted_at IS NULL
		    AND (ru.layer = ANY($2::text[]) OR ru.id = ANY($3::bigint[]))
		    AND ru.id NOT IN (SELECT rule_id FROM rule_set_exclusions WHERE rule_set_id = $1)
		  ORDER BY ru.id, rv.revision DESC`, ruleSetID, layers, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RuleRevision
	for rows.Next() {
		var r RuleRevision
		if err := rows.Scan(&r.ID, &r.RuleID, &r.Revision, &r.Text, &r.Lang, &r.Author, &r.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ResolvedCount reports how many rules a set would actually apply.
//
// It delegates to ResolveSelection rather than running its own COUNT, and that is the point: layers
// and named rules are a union, exclusions subtract, and a soft-deleted rule drops out. A second
// SQL statement encoding those same three rules is a second definition of "resolved" that can
// drift from the first, and the number this returns is what refuses a build -- so it has to be the
// same number the analyst was shown while editing.
//
// The cost is that the rule TEXT is fetched to be counted and thrown away. That is real at 5,872
// rules and it is accepted here: a wrong count refuses a legitimate sweep or lets an empty set
// through, and neither is worth saving a few megabytes on an operation an analyst runs once.
func (p *PG) ResolvedCount(ctx context.Context, ruleSetID int64) (int, error) {
	revs, err := p.ResolveSelection(ctx, ruleSetID)
	if err != nil {
		return 0, err
	}
	return len(revs), nil
}

// Freeze makes a rule set immutable: it pins each resolved revision as a member, records the
// compiled blob's hash, and stamps the version. It refuses a set that is already frozen.
func (p *PG) Freeze(ctx context.Context, ruleSetID int64, version int, frozenBy, yarcSHA256 string, revisionIDs []int64) error {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	ct, err := tx.Exec(ctx,
		`UPDATE rule_sets
		    SET version=$2, frozen_at=now(), frozen_by=$3, yarc_sha256=$4
		  WHERE id=$1 AND frozen_at IS NULL`,
		ruleSetID, version, frozenBy, yarcSHA256)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return fmt.Errorf("rule set %d is already frozen or does not exist", ruleSetID)
	}
	for _, rid := range revisionIDs {
		if _, err := tx.Exec(ctx,
			`INSERT INTO rule_set_members (rule_set_id, rule_revision_id) VALUES ($1,$2)`,
			ruleSetID, rid); err != nil {
			return fmt.Errorf("pin revision %d: %w", rid, err)
		}
	}
	return tx.Commit(ctx)
}

// ListRuleSets returns every rule set, newest first. It never returns nil: the API encodes this
// directly, and `null` would crash a client that maps over the response instead of showing it an
// empty console.
func (p *PG) ListRuleSets(ctx context.Context) ([]RuleSet, error) {
	rows, err := p.pool.Query(ctx,
		`SELECT id, name, version, created_by, frozen_at, COALESCE(frozen_by,''),
		        COALESCE(yarc_sha256,'')
		   FROM rule_sets
		  ORDER BY id DESC`)
	if err != nil {
		return nil, fmt.Errorf("listing rule sets: %w", err)
	}
	defer rows.Close()

	out := []RuleSet{}
	for rows.Next() {
		var s RuleSet
		if err := rows.Scan(&s.ID, &s.Name, &s.Version, &s.CreatedBy, &s.FrozenAt,
			&s.FrozenBy, &s.YarcSHA256); err != nil {
			return nil, fmt.Errorf("scanning a rule set: %w", err)
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (p *PG) GetRuleSet(ctx context.Context, id int64) (RuleSet, error) {
	var s RuleSet
	var frozenBy, yarc *string
	err := p.pool.QueryRow(ctx,
		`SELECT id, name, version, created_by, frozen_at, frozen_by, yarc_sha256
		   FROM rule_sets WHERE id=$1`, id).
		Scan(&s.ID, &s.Name, &s.Version, &s.CreatedBy, &s.FrozenAt, &frozenBy, &yarc)
	if err != nil {
		return RuleSet{}, err
	}
	if frozenBy != nil {
		s.FrozenBy = *frozenBy
	}
	if yarc != nil {
		s.YarcSHA256 = *yarc
	}
	return s, nil
}

// FrozenMemberList names what a frozen set contains, without any rule text. It is what a screen
// needs; FrozenMembers is what the compile path needs.
//
// Like FrozenMembers it deliberately does NOT filter deleted rules. A frozen set pins a REVISION,
// so deleting the rule afterwards changes nothing about the blob an agent is already carrying --
// and a set that appeared to shrink would misreport what is deployed.
func (p *PG) FrozenMemberList(ctx context.Context, ruleSetID int64) ([]FrozenMember, error) {
	rows, err := p.pool.Query(ctx,
		`SELECT r.id, r.identifier, r.layer, rv.revision
		   FROM rule_set_members m
		   JOIN rule_revisions rv ON rv.id = m.rule_revision_id
		   JOIN rules r          ON r.id  = rv.rule_id
		  WHERE m.rule_set_id = $1
		  ORDER BY r.identifier`, ruleSetID)
	if err != nil {
		return nil, fmt.Errorf("listing members of rule set %d: %w", ruleSetID, err)
	}
	defer rows.Close()

	out := []FrozenMember{}
	for rows.Next() {
		var m FrozenMember
		if err := rows.Scan(&m.RuleID, &m.Identifier, &m.Layer, &m.Revision); err != nil {
			return nil, fmt.Errorf("scanning a member: %w", err)
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// FrozenMembers returns the pinned revisions. It deliberately does NOT filter deleted rules: a
// frozen set must stay reconstructible after the rules inside it are edited or deleted.
func (p *PG) FrozenMembers(ctx context.Context, ruleSetID int64) ([]RuleRevision, error) {
	rows, err := p.pool.Query(ctx,
		`SELECT rv.id, rv.rule_id, rv.revision, rv.text, COALESCE(rv.lang,''), rv.author, rv.created_at
		   FROM rule_set_members m
		   JOIN rule_revisions rv ON rv.id = m.rule_revision_id
		  WHERE m.rule_set_id = $1
		  ORDER BY rv.rule_id`, ruleSetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RuleRevision
	for rows.Next() {
		var r RuleRevision
		if err := rows.Scan(&r.ID, &r.RuleID, &r.Revision, &r.Text, &r.Lang, &r.Author, &r.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// AllRuleTexts returns identifier -> latest revision text for every undeleted rule.
//
// One query, not one per rule: this feeds the compile check's dependency context, and the library
// holds nearly 6,000 rules. DISTINCT ON with an ORDER BY is PostgreSQL's idiom for "latest row per
// group" and is why the store is PostgreSQL rather than something portable.
func (p *PG) AllRuleTexts(ctx context.Context) (map[string]string, error) {
	rows, err := p.pool.Query(ctx,
		`SELECT DISTINCT ON (ru.id) ru.identifier, rv.text
		   FROM rules ru
		   JOIN rule_revisions rv ON rv.rule_id = ru.id
		  WHERE ru.deleted_at IS NULL
		  ORDER BY ru.id, rv.revision DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var ident, text string
		if err := rows.Scan(&ident, &text); err != nil {
			return nil, err
		}
		out[ident] = text
	}
	return out, rows.Err()
}

func (p *PG) CreateCase(ctx context.Context, name, createdBy string) (int64, error) {
	var id int64
	err := p.pool.QueryRow(ctx,
		`INSERT INTO cases (name, created_by) VALUES ($1,$2) RETURNING id`,
		name, createdBy).Scan(&id)
	return id, err
}

func (p *PG) ListCases(ctx context.Context) ([]Case, error) {
	rows, err := p.pool.Query(ctx,
		`SELECT id, name, created_by, created_at FROM cases ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Case
	for rows.Next() {
		var c Case
		if err := rows.Scan(&c.ID, &c.Name, &c.CreatedBy, &c.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// SaveScan stores a scan with its coverage and findings in ONE transaction, and is idempotent on
// run_id.
//
// Idempotence matters because bulk import is the primary import: an analyst dragging the same run
// folder in twice is ordinary, not an error. The second call returns the existing scan id and
// created=false, having written nothing.
//
// The transaction matters for the opposite reason: a scan row with only some of its findings would
// read as a completed scan that found less than it did, which is the quietest possible way for this
// console to lie.
// scanIDForRun looks up a scan by its run id. It reports absence as found=false and returns every
// other failure as an error: a dropped connection or a cancelled context is not "no such run", and
// treating it as one turns a transport failure into a duplicate-key error further down.
func (p *PG) scanIDForRun(ctx context.Context, runID string) (int64, bool, error) {
	var id int64
	err := p.pool.QueryRow(ctx, `SELECT id FROM scans WHERE run_id=$1`, runID).Scan(&id)
	switch {
	case err == nil:
		return id, true, nil
	case errors.Is(err, pgx.ErrNoRows):
		return 0, false, nil
	default:
		return 0, false, fmt.Errorf("look up run %s: %w", runID, err)
	}
}

func (p *PG) SaveScan(ctx context.Context, caseID int64, s ScanRecord) (int64, bool, error) {
	// Idempotency is the UNIQUE constraint on scans.run_id, not this lookup. The lookup is only a
	// fast path that avoids opening a transaction for the common re-import; the INSERT below is
	// what actually decides, so two concurrent imports of one run folder cannot both win.
	existing, found, err := p.scanIDForRun(ctx, s.RunID)
	if err != nil {
		return 0, false, err
	}
	if found {
		return existing, false, nil
	}

	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return 0, false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var id int64
	err = tx.QueryRow(ctx,
		`INSERT INTO scans (case_id, run_id, host, started, finished, tool_version, operator,
		                    invocation, build_id, rule_set, tier, score, incomplete, integrity, source)
		 VALUES ($1,$2,$3,$4,$5,NULLIF($6,''),NULLIF($7,''),NULLIF($8,''),NULLIF($9,''),
		         NULLIF($10,''),$11,$12,$13,$14,NULLIF($15,''))
		 ON CONFLICT (run_id) DO NOTHING
		 RETURNING id`,
		caseID, s.RunID, s.Host, s.Started, s.Finished, s.ToolVersion, s.Operator,
		s.Invocation, s.BuildID, s.RuleSet, s.Tier, s.Score, s.Incomplete, s.Integrity, s.Source).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		// Another import claimed this run_id between our lookup and this INSERT. ON CONFLICT waits
		// for that transaction, so by now its scan is committed and ours is a duplicate by
		// definition -- return theirs rather than an error the caller cannot act on.
		if err := tx.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			return 0, false, fmt.Errorf("roll back losing import of run %s: %w", s.RunID, err)
		}
		existing, found, err := p.scanIDForRun(ctx, s.RunID)
		if err != nil {
			return 0, false, err
		}
		if !found {
			return 0, false, fmt.Errorf("run %s conflicted on insert but is not present", s.RunID)
		}
		return existing, false, nil
	}
	if err != nil {
		return 0, false, fmt.Errorf("insert scan: %w", err)
	}

	for _, c := range s.Coverage {
		if _, err := tx.Exec(ctx,
			`INSERT INTO scan_coverage (scan_id, view, status, reason, targets_scanned,
			                            non_regular, unreadable, oversize_skipped, no_language_detector)
			 VALUES ($1,$2,$3,NULLIF($4,''),$5,$6,$7,$8,$9)`,
			id, c.View, c.Status, c.Reason, c.TargetsScanned,
			c.NonRegular, c.Unreadable, c.OversizeSkipped, c.NoLanguageDetector); err != nil {
			return 0, false, fmt.Errorf("insert coverage %s: %w", c.View, err)
		}
	}

	for _, f := range s.Findings {
		if _, err := tx.Exec(ctx,
			`INSERT INTO findings (scan_id, finding_ref, content_key, host, view, file_path,
			                       file_sha256, artifact_kind, artifact_id, basis, knowledge_ref,
			                       evidence, score, tier, mitre, fingerprint)
			 VALUES ($1,$2,$3,$4,$5,NULLIF($6,''),NULLIF($7,''),NULLIF($8,''),NULLIF($9,''),
			         $10,NULLIF($11,''),NULLIF($12,''),$13,$14,$15,NULLIF($16,''))`,
			id, f.Ref, f.ContentKey, f.Host, f.View, f.FilePath, f.FileSHA256,
			f.ArtifactKind, f.ArtifactID, f.Basis, f.KnowledgeRef, f.Evidence,
			f.Score, f.Tier, f.Mitre, f.Fingerprint); err != nil {
			return 0, false, fmt.Errorf("insert finding %s: %w", f.Ref, err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return 0, false, err
	}
	return id, true, nil
}

func (p *PG) FindingsForScan(ctx context.Context, scanID int64) ([]FindingRecord, error) {
	rows, err := p.pool.Query(ctx,
		`SELECT id, finding_ref, content_key, host, view, COALESCE(file_path,''),
		        COALESCE(file_sha256,''), COALESCE(artifact_kind,''), COALESCE(artifact_id,''),
		        basis, COALESCE(knowledge_ref,''), COALESCE(evidence,''), score, tier,
		        COALESCE(mitre,'{}'), COALESCE(fingerprint,'')
		   FROM findings WHERE scan_id=$1 ORDER BY score DESC, finding_ref`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []FindingRecord
	for rows.Next() {
		var f FindingRecord
		if err := rows.Scan(&f.ID, &f.Ref, &f.ContentKey, &f.Host, &f.View, &f.FilePath,
			&f.FileSHA256, &f.ArtifactKind, &f.ArtifactID, &f.Basis, &f.KnowledgeRef,
			&f.Evidence, &f.Score, &f.Tier, &f.Mitre, &f.Fingerprint); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

func (p *PG) CoverageForScan(ctx context.Context, scanID int64) ([]CoverageRecord, error) {
	rows, err := p.pool.Query(ctx,
		`SELECT view, status, COALESCE(reason,''), targets_scanned, non_regular, unreadable,
		        oversize_skipped, no_language_detector
		   FROM scan_coverage WHERE scan_id=$1 ORDER BY view`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CoverageRecord
	for rows.Next() {
		var c CoverageRecord
		if err := rows.Scan(&c.View, &c.Status, &c.Reason, &c.TargetsScanned, &c.NonRegular,
			&c.Unreadable, &c.OversizeSkipped, &c.NoLanguageDetector); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// GetScan fetches one scan by id. Separate from ListScans because a scan view is reached by scan
// id, not by walking a case -- and filtering ListScans by a case the caller does not know is how a
// lookup silently returns nothing.
func (p *PG) GetScan(ctx context.Context, scanID int64) (ScanRecord, error) {
	var s ScanRecord
	err := p.pool.QueryRow(ctx,
		`SELECT id, run_id, host, COALESCE(tool_version,''), COALESCE(operator,''),
		        COALESCE(build_id,''), COALESCE(rule_set,''), tier, score, incomplete,
		        integrity, imported_at
		   FROM scans WHERE id=$1`, scanID).
		Scan(&s.ID, &s.RunID, &s.Host, &s.ToolVersion, &s.Operator, &s.BuildID, &s.RuleSet,
			&s.Tier, &s.Score, &s.Incomplete, &s.Integrity, &s.ImportedAt)
	return s, err
}

func (p *PG) ListScans(ctx context.Context, caseID int64) ([]ScanRecord, error) {
	rows, err := p.pool.Query(ctx,
		`SELECT id, run_id, host, COALESCE(tool_version,''), COALESCE(operator,''),
		        COALESCE(build_id,''), COALESCE(rule_set,''), tier, score, incomplete,
		        integrity, imported_at
		   FROM scans WHERE case_id=$1 ORDER BY imported_at DESC`, caseID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ScanRecord
	for rows.Next() {
		var s ScanRecord
		if err := rows.Scan(&s.ID, &s.RunID, &s.Host, &s.ToolVersion, &s.Operator,
			&s.BuildID, &s.RuleSet, &s.Tier, &s.Score, &s.Incomplete,
			&s.Integrity, &s.ImportedAt); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// Decision is a person's judgement about content.
type Decision struct {
	ID         int64     `json:"id"`
	ContentKey string    `json:"content_key"`
	Verdict    string    `json:"verdict"`
	Note       string    `json:"note,omitempty"`
	Author     string    `json:"author"`
	CaseID     *int64    `json:"case_id,omitempty"`
	CaseName   string    `json:"case_name,omitempty"`
	DecidedAt  time.Time `json:"decided_at"`
}

// RecordDecision appends a judgement. Decisions are append-only: a changed mind is a new row, so
// the history of what the team believed and when survives.
func (p *PG) RecordDecision(ctx context.Context, d Decision) (int64, error) {
	var id int64
	err := p.pool.QueryRow(ctx,
		`INSERT INTO decisions (content_key, verdict, note, author, case_id)
		 VALUES ($1,$2,NULLIF($3,''),$4,$5) RETURNING id`,
		d.ContentKey, d.Verdict, d.Note, d.Author, d.CaseID).Scan(&id)
	return id, err
}

// DecisionsFor returns every prior judgement about these content keys, newest first, with the case
// each was made on.
//
// This is the cross-engagement memory a command-line tool cannot have: a file judged on one
// customer surfaces that judgement on the next customer containing the same bytes, BEFORE the
// analyst is asked to decide again.
func (p *PG) DecisionsFor(ctx context.Context, contentKeys []string) (map[string][]Decision, error) {
	if len(contentKeys) == 0 {
		return map[string][]Decision{}, nil
	}
	rows, err := p.pool.Query(ctx,
		`SELECT d.id, d.content_key, d.verdict, COALESCE(d.note,''), d.author,
		        d.case_id, COALESCE(c.name,''), d.decided_at
		   FROM decisions d
		   LEFT JOIN cases c ON c.id = d.case_id
		  WHERE d.content_key = ANY($1::text[])
		  -- id DESC breaks ties: decisions recorded in the same transaction share
		  -- transaction_timestamp(), so decided_at alone leaves their order to chance.
		  ORDER BY d.decided_at DESC, d.id DESC`, contentKeys)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][]Decision{}
	for rows.Next() {
		var d Decision
		if err := rows.Scan(&d.ID, &d.ContentKey, &d.Verdict, &d.Note, &d.Author,
			&d.CaseID, &d.CaseName, &d.DecidedAt); err != nil {
			return nil, err
		}
		out[d.ContentKey] = append(out[d.ContentKey], d)
	}
	return out, rows.Err()
}

// RecordBuild inserts a generated agent, or returns the existing row when the same build id is
// recorded again -- but only after confirming it is the same artefact.
//
// ON CONFLICT rather than an error, because build_id is DERIVED from the build's inputs: recording
// it twice normally means the same request produced the same artefact, which is SC-003 working
// rather than a collision to report. A read-then-write would race two analysts generating the same
// build; this repo already fixed exactly that shape in the scan-import path.
//
// "Normally" is doing work in that sentence, which is why the sha256 is checked. The id is a
// TRUNCATED hash -- 48 bits after the widening in 0e9d75a -- so two genuinely different builds can
// collide, and returning the existing row then hands the caller a DIFFERENT agent's record. The
// download route serves by that record's hash, so the analyst would receive an archive the record
// does not describe. Rare is not the same as impossible, and the failure is silent, which is the
// combination this project keeps closing.
func (p *PG) RecordBuild(ctx context.Context, b Build) (Build, error) {
	row := p.pool.QueryRow(ctx, `
		INSERT INTO builds (build_id, release_id, rule_set_id, views, sha256, size_bytes,
		                    agent_json, generated_at, generated_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,COALESCE($8, now()),$9)
		ON CONFLICT (build_id) DO NOTHING
		RETURNING id, generated_at`,
		b.BuildID, b.ReleaseID, b.RuleSetID, b.Views, b.SHA256, b.SizeBytes, b.AgentJSON,
		nullTime(b.GeneratedAt), b.GeneratedBy)
	var id int64
	var at time.Time
	switch err := row.Scan(&id, &at); {
	case err == nil:
		b.ID, b.GeneratedAt = id, at
		return b, nil
	case errors.Is(err, ErrNotFound):
		// DO NOTHING returned no row: this build id is already recorded. Read it back so the caller
		// gets the same answer it would have got the first time -- after checking it really is the
		// same artefact, because the id is a truncated hash and a collision would otherwise return
		// someone else's build.
		existing, err := p.buildByBuildID(ctx, b.BuildID)
		if err != nil {
			return Build{}, err
		}
		if existing.SHA256 != b.SHA256 {
			return Build{}, fmt.Errorf(
				"build id %s already names an archive with sha256 %s, and this build's archive is "+
					"%s: two different builds have collided on a truncated id, and returning the "+
					"recorded one would describe an artefact nobody generated",
				b.BuildID, existing.SHA256, b.SHA256)
		}
		return existing, nil
	default:
		return Build{}, err
	}
}

func (p *PG) buildByBuildID(ctx context.Context, buildID string) (Build, error) {
	var b Build
	err := p.pool.QueryRow(ctx, `
		SELECT id, build_id, release_id, rule_set_id, views, sha256, size_bytes, agent_json,
		       generated_at, generated_by
		  FROM builds WHERE build_id=$1`, buildID).
		Scan(&b.ID, &b.BuildID, &b.ReleaseID, &b.RuleSetID, &b.Views, &b.SHA256, &b.SizeBytes,
			&b.AgentJSON, &b.GeneratedAt, &b.GeneratedBy)
	return b, err
}

// BuildByID reads one recorded build by its row id.
//
// By row id, not by build_id, because that is what a URL carries and what the download route is
// given. build_id is the shorter, quotable identifier and it is UNIQUE, but it is also a truncated
// hash: buildByBuildID exists for the conflict check in RecordBuild, where a collision is the very
// thing being detected, and this is the lookup for serving.
func (p *PG) BuildByID(ctx context.Context, id int64) (Build, error) {
	var b Build
	err := p.pool.QueryRow(ctx, `
		SELECT id, build_id, release_id, rule_set_id, views, sha256, size_bytes, agent_json,
		       generated_at, generated_by
		  FROM builds WHERE id=$1`, id).
		Scan(&b.ID, &b.BuildID, &b.ReleaseID, &b.RuleSetID, &b.Views, &b.SHA256, &b.SizeBytes,
			&b.AgentJSON, &b.GeneratedAt, &b.GeneratedBy)
	return b, err
}

// ListBuilds returns every recorded build, newest first.
func (p *PG) ListBuilds(ctx context.Context) ([]Build, error) {
	rows, err := p.pool.Query(ctx, `
		SELECT id, build_id, release_id, rule_set_id, views, sha256, size_bytes, agent_json,
		       generated_at, generated_by
		  FROM builds ORDER BY generated_at DESC, id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	// Non-nil so a client never receives null, matching the convention the other list methods use.
	out := []Build{}
	for rows.Next() {
		var b Build
		if err := rows.Scan(&b.ID, &b.BuildID, &b.ReleaseID, &b.RuleSetID, &b.Views, &b.SHA256,
			&b.SizeBytes, &b.AgentJSON, &b.GeneratedAt, &b.GeneratedBy); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// nullTime maps the zero time to NULL so the INSERT's COALESCE($8, now()) supplies the time. A
// generated agent's recorded time should be the moment it was generated, and a caller that did not
// set one is saying "now" rather than "the year zero".
//
// The COALESCE is where that happens, not a column DEFAULT: builds.generated_at is NOT NULL with no
// default, deliberately, so a row can never acquire a time nobody chose by omitting the column.
func nullTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t
}
