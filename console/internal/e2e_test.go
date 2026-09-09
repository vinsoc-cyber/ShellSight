package console_test

import (
	"shellsightconsole/internal/consoletest"
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"shellsightconsole/internal/blob"
	"shellsightconsole/internal/rules"
	"shellsightconsole/internal/ruleset"
	"shellsightconsole/internal/store"
)

func TestPublishAuthorFreezeDownload(t *testing.T) {
	dsn := os.Getenv("CONSOLE_TEST_DSN")
	if dsn == "" {
		t.Skip("CONSOLE_TEST_DSN not set")
	}
	yr := consoletest.FindYr()
	if yr == "" {
		t.Skip("no yr binary found; set CONSOLE_TEST_YR")
	}

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if _, err := pool.Exec(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public;`); err != nil {
		t.Fatal(err)
	}
	if err := store.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}

	st := store.NewPG(pool)
	blobs := blob.New(t.TempDir())
	compiler := rules.NewCompiler(yr)
	ruleSvc := rules.NewService(st, compiler, rules.NewLibraryResolver(st))
	setSvc := ruleset.NewService(st, blobs, compiler)

	// 1. Publish a release.
	if _, err := st.PublishRelease(ctx,
		store.Release{Version: "v1.0.0-231", Target: "linux-amd64", PublishedBy: "v.quannh67"},
		[]store.ReleaseFile{{Path: "shellsight", SHA256: "ab" + repeat62()}}); err != nil {
		t.Fatalf("publish: %v", err)
	}

	// 2. Author a rule. It must compile or it is refused.
	ruleID, err := ruleSvc.Create(ctx, "custom",
		`rule e2e_rule { strings: $a = "eval(" condition: $a }`, "php", "v.quannh67")
	if err != nil {
		t.Fatalf("create rule: %v", err)
	}

	// 3. Compose a set from it and freeze.
	setID, err := st.CreateRuleSet(ctx, "e2e-set", "v.quannh67")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetSelection(ctx, setID, store.Selection{Rules: []int64{ruleID}}); err != nil {
		t.Fatal(err)
	}
	hash, err := setSvc.Freeze(ctx, setID, 1, "v.quannh67")
	if err != nil {
		t.Fatalf("freeze: %v", err)
	}

	// 4. The blob exists and is a real compiled rule set.
	body, err := blobs.Get(hash)
	if err != nil {
		t.Fatalf("blob: %v", err)
	}
	if len(body) == 0 {
		t.Fatal("empty blob")
	}

	// 5. Editing the rule afterwards must not disturb the frozen set.
	if _, err := ruleSvc.Edit(ctx, ruleID,
		`rule e2e_rule { strings: $a = "assert(" condition: $a }`, "php", "someone"); err != nil {
		t.Fatalf("edit: %v", err)
	}
	set, err := st.GetRuleSet(ctx, setID)
	if err != nil {
		t.Fatal(err)
	}
	if set.YarcSHA256 != hash {
		t.Fatalf("frozen blob changed after a rule edit: %s -> %s", hash, set.YarcSHA256)
	}
	members, err := st.FrozenMembers(ctx, setID)
	if err != nil {
		t.Fatal(err)
	}
	if len(members) != 1 || members[0].Revision != 1 {
		t.Fatalf("frozen set no longer pins revision 1: %+v", members)
	}
}

func repeat62() string {
	s := ""
	for i := 0; i < 62; i++ {
		s += "0"
	}
	return s
}
