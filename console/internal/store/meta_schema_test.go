package store

import (
	"context"
	"testing"
)

func TestMetaColumnsExistAndAreNullable(t *testing.T) {
	// Nullable matters: null means the rule declared nothing, and about 17 rules in the shipped
	// packs have no meta block at all. A NOT NULL column would force a lie.
	pool := testPool(t)
	if err := Migrate(context.Background(), pool); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	want := map[string]string{"description": "YES", "score": "YES", "meta": "YES"}
	for col, nullable := range want {
		var isNullable string
		err := pool.QueryRow(context.Background(),
			`SELECT is_nullable FROM information_schema.columns
			  WHERE table_name='rule_revisions' AND column_name=$1`, col).Scan(&isNullable)
		if err != nil {
			t.Errorf("column %s is missing: %v", col, err)
			continue
		}
		if isNullable != nullable {
			t.Errorf("%s is_nullable=%s, want %s", col, isNullable, nullable)
		}
	}
}
