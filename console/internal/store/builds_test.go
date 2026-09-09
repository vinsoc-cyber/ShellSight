package store

import (
	"context"
	"strings"
	"testing"
)

func TestMigrateCreatesTheBuildsTable(t *testing.T) {
	pool := testPool(t)
	if err := Migrate(context.Background(), pool); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM information_schema.tables WHERE table_name='builds'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("builds table not created by 0004")
	}
}

func seedRelease(t *testing.T, pg *PG) int64 {
	t.Helper()
	id, err := pg.PublishRelease(context.Background(),
		Release{Version: "v1.0.0-test", Target: "linux-amd64", PublishedBy: "tester"},
		[]ReleaseFile{{Path: "shellsight", SHA256: Sum64("orchestrator")}})
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestRecordBuildRoundTrips(t *testing.T) {
	pool := testPool(t)
	if err := Migrate(context.Background(), pool); err != nil {
		t.Fatal(err)
	}
	pg := NewPG(pool)
	releaseID := seedRelease(t, pg)

	want := Build{
		BuildID:     "b-7f3a91",
		ReleaseID:   releaseID,
		Views:       []string{"disk"},
		SHA256:      Sum64("archive"),
		SizeBytes:   4096,
		AgentJSON:   []byte(`{"schema_version":"1"}`),
		GeneratedBy: "tester",
	}
	got, err := pg.RecordBuild(context.Background(), want)
	if err != nil {
		t.Fatalf("record: %v", err)
	}
	if got.ID == 0 {
		t.Error("RecordBuild returned no row id")
	}
	if got.GeneratedAt.IsZero() {
		t.Error("GeneratedAt was not returned")
	}

	list, err := pg.ListBuilds(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Fatalf("ListBuilds returned %d rows, want 1", len(list))
	}
	if list[0].BuildID != want.BuildID || list[0].SHA256 != want.SHA256 {
		t.Errorf("round trip lost data: %+v", list[0])
	}
	if len(list[0].Views) != 1 || list[0].Views[0] != "disk" {
		t.Errorf("Views = %v", list[0].Views)
	}
}

// A memory-only build has no rule set, and the column is nullable for exactly that reason. A NULL
// that came back as a zero id would tie the build to whatever row happens to have id 0.
//
// Read back through ListBuilds, NOT from RecordBuild's return value. RecordBuild's insert path
// returns the struct it was GIVEN, with only ID and GeneratedAt replaced, so asserting on its
// RuleSetID asserts on the nil the caller passed in -- it would pass with the column dropped from
// both statements. The non-nil case is here as the control: without it, a RuleSetID that was always
// nil would satisfy the null assertion too.
func TestABuildWithNoRuleSetRoundTripsAsNull(t *testing.T) {
	pool := testPool(t)
	if err := Migrate(context.Background(), pool); err != nil {
		t.Fatal(err)
	}
	pg := NewPG(pool)
	releaseID := seedRelease(t, pg)
	setID, err := pg.CreateRuleSet(context.Background(), "sweep-acme", "tester")
	if err != nil {
		t.Fatal(err)
	}

	if _, err := pg.RecordBuild(context.Background(), Build{
		BuildID: "b-memonly", ReleaseID: releaseID, Views: []string{"java-mem"},
		SHA256: Sum64("a"), SizeBytes: 1, AgentJSON: []byte(`{}`), GeneratedBy: "tester",
	}); err != nil {
		t.Fatalf("record the memory-only build: %v", err)
	}
	if _, err := pg.RecordBuild(context.Background(), Build{
		BuildID: "b-disk", ReleaseID: releaseID, RuleSetID: &setID, Views: []string{"disk"},
		SHA256: Sum64("b"), SizeBytes: 2, AgentJSON: []byte(`{}`), GeneratedBy: "tester",
	}); err != nil {
		t.Fatalf("record the disk build: %v", err)
	}

	list, err := pg.ListBuilds(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]Build{}
	for _, b := range list {
		byID[b.BuildID] = b
	}
	if got := byID["b-memonly"]; got.RuleSetID != nil {
		t.Errorf("RuleSetID = %v, want nil for a memory-only build", *got.RuleSetID)
	}
	got := byID["b-disk"]
	if got.RuleSetID == nil {
		t.Fatal("RuleSetID came back nil for a build that named a rule set")
	}
	if *got.RuleSetID != setID {
		t.Errorf("RuleSetID = %d, want %d", *got.RuleSetID, setID)
	}
}

// An empty table must list as an empty slice, not nil: the API hands this straight to a client and
// the convention everywhere in this store is that a list is never null.
func TestListBuildsOnAnEmptyTableIsEmptyNotNil(t *testing.T) {
	pool := testPool(t)
	if err := Migrate(context.Background(), pool); err != nil {
		t.Fatal(err)
	}
	list, err := NewPG(pool).ListBuilds(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if list == nil {
		t.Error("ListBuilds returned nil for an empty table; a list is never null here")
	}
	if len(list) != 0 {
		t.Errorf("ListBuilds returned %d rows from an empty table", len(list))
	}
}

// Two different builds colliding on a truncated id must NOT quietly return the recorded one.
//
// The id is 48 bits of a hash, so this is rare rather than impossible -- and the download route
// serves by the record's sha256, so a silent swap hands an analyst an archive the record does not
// describe.
func TestACollidingBuildIDWithADifferentArchiveIsRefused(t *testing.T) {
	pool := testPool(t)
	if err := Migrate(context.Background(), pool); err != nil {
		t.Fatal(err)
	}
	pg := NewPG(pool)
	releaseID := seedRelease(t, pg)
	first := Build{
		BuildID: "b-collide", ReleaseID: releaseID, Views: []string{"disk"},
		SHA256: Sum64("archive one"), SizeBytes: 1, AgentJSON: []byte(`{}`), GeneratedBy: "tester",
	}
	if _, err := pg.RecordBuild(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	second := first
	second.SHA256 = Sum64("archive two")
	got, err := pg.RecordBuild(context.Background(), second)
	if err == nil {
		t.Fatalf("a colliding build id with a different archive must be refused, not answered with "+
			"the recorded row (got %+v)", got)
	}
	// The refusal must name both hashes, because the whole point is that the caller can tell this
	// apart from "the same build, recorded twice" -- which is not an error at all.
	for _, want := range []string{first.SHA256, second.SHA256, "b-collide"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not name %s: %v", want, err)
		}
	}
	// And it must not have recorded a second row: a refused build is not a build.
	list, err := pg.ListBuilds(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].SHA256 != first.SHA256 {
		t.Errorf("the refused build changed the table: %+v", list)
	}
}

// The build id is derived from the inputs, so regenerating an identical build is not an error --
// it is the same artefact. Returning the existing row is what makes SC-003 usable rather than a
// unique-violation the analyst has to interpret.
func TestRegeneratingAnIdenticalBuildReturnsTheExistingRow(t *testing.T) {
	pool := testPool(t)
	if err := Migrate(context.Background(), pool); err != nil {
		t.Fatal(err)
	}
	pg := NewPG(pool)
	b := Build{
		BuildID: "b-same", ReleaseID: seedRelease(t, pg), Views: []string{"disk"},
		SHA256: Sum64("same"), SizeBytes: 10, AgentJSON: []byte(`{}`), GeneratedBy: "tester",
	}
	first, err := pg.RecordBuild(context.Background(), b)
	if err != nil {
		t.Fatal(err)
	}
	second, err := pg.RecordBuild(context.Background(), b)
	if err != nil {
		t.Fatalf("recording an identical build must not fail: %v", err)
	}
	if first.ID != second.ID {
		t.Errorf("a second identical build made a new row: %d then %d", first.ID, second.ID)
	}
	list, err := pg.ListBuilds(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Errorf("ListBuilds returned %d rows after two identical builds", len(list))
	}
}

// ResolvedCount must be the SAME number as ResolveSelection's length, not a second count that
// happens to agree today.
//
// It is what refuses a build, and the API reports it to the analyst while they edit -- so the two
// have to be one definition of "resolved". Layers and named rules are a union, exclusions subtract,
// and a soft-deleted rule drops out; a separate COUNT statement re-encodes all three and can drift.
// Asserted against the resolved list itself, and across an exclusion, so a count over `rules`
// rather than over the selection fails here.
func TestResolvedCountIsExactlyWhatResolveSelectionReturns(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	_, custom := seedRules(t, s)

	id, err := s.CreateRuleSet(ctx, "set", "a")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetSelection(ctx, id, Selection{Layers: []string{"own", "custom"}}); err != nil {
		t.Fatal(err)
	}

	agree := func(when string) int {
		t.Helper()
		revs, err := s.ResolveSelection(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		n, err := s.ResolvedCount(ctx, id)
		if err != nil {
			t.Fatalf("count %s: %v", when, err)
		}
		if n != len(revs) {
			t.Errorf("%s: ResolvedCount = %d but ResolveSelection returned %d", when, n, len(revs))
		}
		return n
	}
	if got := agree("with both layers selected"); got != 2 {
		t.Errorf("count with both layers = %d, want 2", got)
	}

	if err := s.AddExclusion(ctx, id, custom, "noisy on Acme CMS", "v.quannh67"); err != nil {
		t.Fatal(err)
	}
	if got := agree("after an exclusion"); got != 1 {
		t.Errorf("count after excluding one of two rules = %d, want 1", got)
	}

	// An empty selection resolves to nothing, which is the state the generate refusal exists for.
	empty, err := s.CreateRuleSet(ctx, "empty", "a")
	if err != nil {
		t.Fatal(err)
	}
	n, err := s.ResolvedCount(ctx, empty)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("ResolvedCount on an empty selection = %d, want 0", n)
	}
}

// GetRelease reads by id, because (version, target) is the natural key and a version string alone
// names one row per target. An agent assembled against the wrong row is machine code for the wrong
// processor.
func TestGetReleaseReadsTheRowByIDIncludingItsTarget(t *testing.T) {
	pool := testPool(t)
	if err := Migrate(context.Background(), pool); err != nil {
		t.Fatal(err)
	}
	pg := NewPG(pool)
	amd64, err := pg.PublishRelease(context.Background(),
		Release{Version: "v1.0.0-test", Target: "linux-amd64", PublishedBy: "tester"},
		[]ReleaseFile{{Path: "shellsight", SHA256: Sum64("a")}})
	if err != nil {
		t.Fatal(err)
	}
	arm64, err := pg.PublishRelease(context.Background(),
		Release{Version: "v1.0.0-test", Target: "linux-arm64", PublishedBy: "tester"},
		[]ReleaseFile{{Path: "shellsight", SHA256: Sum64("b")}})
	if err != nil {
		t.Fatal(err)
	}

	got, err := pg.GetRelease(context.Background(), arm64)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.ID != arm64 || got.Target != "linux-arm64" || got.Version != "v1.0.0-test" {
		t.Errorf("got %+v, want the linux-arm64 row (id %d)", got, arm64)
	}
	if got.PublishedBy != "tester" || got.PublishedAt.IsZero() {
		t.Errorf("provenance was not read back: %+v", got)
	}
	other, err := pg.GetRelease(context.Background(), amd64)
	if err != nil {
		t.Fatal(err)
	}
	if other.Target != "linux-amd64" {
		t.Errorf("the two targets are not distinguished: %+v", other)
	}
	if _, err := pg.GetRelease(context.Background(), arm64+1000); err == nil {
		t.Error("an unknown release id must be an error, not a zero Release")
	}
}

// BuildByID must read the row it was asked for. The download route serves whatever this returns,
// so a lookup that ignored the id would hand every caller one arbitrary build's archive under
// their own build's name -- and the archive would still hash correctly against the row it came
// from, which is what makes it quiet.
func TestBuildByIDReadsTheRowItWasAsked(t *testing.T) {
	pool := testPool(t)
	if err := Migrate(context.Background(), pool); err != nil {
		t.Fatal(err)
	}
	pg := NewPG(pool)
	releaseID := seedRelease(t, pg)

	var ids []int64
	for _, b := range []Build{
		{BuildID: "b-first", ReleaseID: releaseID, Views: []string{"disk"},
			SHA256: Sum64("one"), SizeBytes: 11, AgentJSON: []byte(`{"n":1}`), GeneratedBy: "tester"},
		{BuildID: "b-second", ReleaseID: releaseID, Views: []string{"java-mem"},
			SHA256: Sum64("two"), SizeBytes: 22, AgentJSON: []byte(`{"n":2}`), GeneratedBy: "tester"},
	} {
		saved, err := pg.RecordBuild(context.Background(), b)
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, saved.ID)
	}
	if ids[0] == ids[1] {
		t.Fatal("the two builds share a row id, so this test proves nothing")
	}

	second, err := pg.BuildByID(context.Background(), ids[1])
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if second.ID != ids[1] || second.BuildID != "b-second" {
		t.Errorf("got %+v, want the b-second row (id %d)", second, ids[1])
	}
	if second.SHA256 != Sum64("two") || second.SizeBytes != 22 {
		t.Errorf("the archive facts came from the wrong row: %+v", second)
	}
	if string(second.AgentJSON) != `{"n": 2}` && string(second.AgentJSON) != `{"n":2}` {
		t.Errorf("AgentJSON = %s, want the second build's", second.AgentJSON)
	}
	if len(second.Views) != 1 || second.Views[0] != "java-mem" {
		t.Errorf("Views = %v", second.Views)
	}

	first, err := pg.BuildByID(context.Background(), ids[0])
	if err != nil {
		t.Fatal(err)
	}
	if first.BuildID != "b-first" {
		t.Errorf("the two rows are not distinguished: got %+v", first)
	}

	if _, err := pg.BuildByID(context.Background(), ids[1]+1000); err == nil {
		t.Error("an unknown row id must be an error, not a zero Build the route would serve by")
	}
}
