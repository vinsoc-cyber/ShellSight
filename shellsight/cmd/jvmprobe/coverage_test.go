//go:build linux

package main

import "testing"

// Which gaps are unbounded, and which are merely disclosed. Getting this wrong in either direction
// is costly: too broad and every scan exits 5 and the flag gets ignored; too narrow and a truncated
// sweep reads as a clean host, which is what it did on a live Tomcat holding a resident memshell.
func TestOnlyAnEarlyStopIsTruncated(t *testing.T) {
	// A sweep that ran out of budget cannot say what was in the classes it never reached.
	if !truncatedFrom([]string{"pid 1: time budget exhausted after 0 class(es) captured"}) {
		t.Error("budget exhaustion must set truncated")
	}
	// Neither can one whose agent never signalled completion.
	if !truncatedFrom([]string{"pid 1: the agent did not signal completion (no DONE marker)"}) {
		t.Error("a missing DONE marker must set truncated")
	}
	// A complete sweep is not truncated, and must not be: this is the common case.
	if truncatedFrom(nil) {
		t.Error("a complete sweep must not be truncated")
	}
	if truncatedFrom([]string{}) {
		t.Error("an empty incomplete list must not be truncated")
	}
}
