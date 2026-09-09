// Package blob is a content-addressed file store: content in, SHA-256 out.
//
// It holds release files and compiled rule-set blobs. Two properties matter and both come free
// from addressing by content: identical files across releases are stored once, and integrity
// checking is inherent because the name IS the hash.
//
// The key is validated as 64 hex characters before it is ever joined to a path. Callers pass keys
// that originate in HTTP requests, and a store that joined an unvalidated key would be a directory
// traversal.
package blob

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
)

type Store struct{ root string }

func New(root string) *Store { return &Store{root: root} }

// Put writes data and returns its lowercase hex SHA-256. Writing the same content twice is a
// no-op that returns the same key.
func (s *Store) Put(data []byte) (string, error) {
	sum := sha256.Sum256(data)
	key := hex.EncodeToString(sum[:])
	path, err := s.pathFor(key)
	if err != nil {
		return "", err
	}
	if _, err := os.Stat(path); err == nil {
		return key, nil // already stored; content is identical by construction
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", err
	}
	// Write to a temp name in the same directory, then rename: a crash mid-write must not leave a
	// truncated file under a name that asserts its own hash.
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return "", err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return "", err
	}
	return key, nil
}

func (s *Store) Get(key string) ([]byte, error) {
	path, err := s.pathFor(key)
	if err != nil {
		return nil, err
	}
	return os.ReadFile(path)
}

// pathFor validates the key and sharded-joins it. Sharding by the first two hex characters keeps
// any one directory to roughly 1/256th of the store.
func (s *Store) pathFor(key string) (string, error) {
	if len(key) != 64 {
		return "", fmt.Errorf("blob: key %q is not a 64-character hash", key)
	}
	if _, err := hex.DecodeString(key); err != nil {
		return "", fmt.Errorf("blob: key %q is not hexadecimal", key)
	}
	return filepath.Join(s.root, key[:2], key), nil
}
