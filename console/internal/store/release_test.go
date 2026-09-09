package store

import (
	"context"
	"testing"
)

func newTestStore(t *testing.T) *PG {
	t.Helper()
	pool := testPool(t)
	if err := Migrate(context.Background(), pool); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return NewPG(pool)
}

func TestPublishReleaseStoresItAndItsFiles(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	id, err := s.PublishRelease(ctx, Release{
		Version: "v1.0.0-231-g098d8f9", Target: "linux-amd64", PublishedBy: "v.quannh67",
	}, []ReleaseFile{
		{Path: "shellsight", SHA256: "aa" + repeat62()},
		{Path: "third_party/yara-x/yr", SHA256: "bb" + repeat62()},
	})
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	if id == 0 {
		t.Fatal("expected a non-zero release id")
	}

	got, err := s.ListReleases(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 1 || got[0].Target != "linux-amd64" {
		t.Fatalf("got %+v, want one linux-amd64 release", got)
	}

	files, err := s.ReleaseFiles(ctx, id)
	if err != nil {
		t.Fatalf("files: %v", err)
	}
	if len(files) != 2 {
		t.Fatalf("got %d files, want 2", len(files))
	}
}

func TestPublishingTheSameVersionAndTargetTwiceIsRejected(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	r := Release{Version: "v1", Target: "windows-amd64", PublishedBy: "a"}
	files := []ReleaseFile{{Path: "shellsight.exe", SHA256: "cc" + repeat62()}}

	if _, err := s.PublishRelease(ctx, r, files); err != nil {
		t.Fatalf("first publish: %v", err)
	}
	if _, err := s.PublishRelease(ctx, r, files); err == nil {
		t.Fatal("expected the second publish of the same version+target to be rejected")
	}
}

func TestPublishRejectsAnUnknownTarget(t *testing.T) {
	s := newTestStore(t)
	_, err := s.PublishRelease(context.Background(),
		Release{Version: "v1", Target: "solaris-sparc", PublishedBy: "a"},
		[]ReleaseFile{{Path: "x", SHA256: "dd" + repeat62()}})
	if err == nil {
		t.Fatal("expected an unknown target to be rejected")
	}
}

func repeat62() string {
	s := ""
	for i := 0; i < 62; i++ {
		s += "0"
	}
	return s
}
