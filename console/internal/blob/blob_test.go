package blob

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestPutReturnsContentHashAndGetRoundTrips(t *testing.T) {
	s := New(t.TempDir())
	data := []byte("rule x { condition: true }")

	sum, err := s.Put(data)
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	// Assert against the standard library rather than a hand-copied constant: a wrong literal
	// here would be a test that passes while the store hashes incorrectly.
	want := sha256.Sum256(data)
	if sum != hex.EncodeToString(want[:]) {
		t.Fatalf("hash %q does not match sha256 of the content", sum)
	}

	got, err := s.Get(sum)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("round trip: got %q, want %q", got, data)
	}
}

func TestPutIsDeterministicAndIdempotent(t *testing.T) {
	s := New(t.TempDir())
	a, err := s.Put([]byte("same"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.Put([]byte("same"))
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatalf("same content gave different hashes: %s vs %s", a, b)
	}
}

func TestGetUnknownHashIsAnError(t *testing.T) {
	s := New(t.TempDir())
	if _, err := s.Get("0000000000000000000000000000000000000000000000000000000000000000"); err == nil {
		t.Fatal("expected an error for an absent blob, got nil")
	}
}

func TestPutRejectsATraversalShapedHash(t *testing.T) {
	// Get must never build a path from caller-supplied text without validating it.
	s := New(t.TempDir())
	if _, err := s.Get("../../etc/passwd"); err == nil {
		t.Fatal("expected an error for a non-hex key, got nil")
	}
}

func TestBlobsAreShardedByPrefix(t *testing.T) {
	root := t.TempDir()
	s := New(root)
	sum, err := s.Put([]byte("shard me"))
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(root, sum[:2], sum)
	if _, err := os.Stat(want); err != nil {
		t.Fatalf("expected blob at %s: %v", want, err)
	}
}
