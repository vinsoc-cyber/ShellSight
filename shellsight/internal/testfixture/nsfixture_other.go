//go:build !linux

package testfixture

import "testing"

// Namespace is the Linux-only cross-namespace fixture; on other platforms it never exists.
type Namespace struct {
	PID  int
	Root string
}

// Start always skips: only Linux has mount namespaces and a /proc/<pid>/root view.
func Start(t testing.TB, tmpfsAt []string, files map[string]string) *Namespace {
	t.Helper()
	t.Skip("cross-namespace fixture needs Linux (mount namespaces and /proc/<pid>/root)")
	return nil
}

// Path is never reached on this platform.
func (n *Namespace) Path(inNS string) string { return inNS }

// Stop is a no-op on this platform.
func (n *Namespace) Stop() {}
