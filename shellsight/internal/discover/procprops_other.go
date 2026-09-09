//go:build !linux

package discover

import (
	"errors"
	"runtime"
)

// Reading server locations off running processes is Linux-only for now.
//
// Spec 002 is the Linux port, and FR-034a exists because a Linux instance started by systemd or by
// another user is invisible to the scanning user's environment. On Windows the same Tomcat instances
// are reachable through CATALINA_HOME/CATALINA_BASE, which service installs set, and enumerating
// command lines there needs a different mechanism entirely (a toolhelp snapshot or WMI) that this
// feature has no measurement behind.
//
// Reported as unavailable rather than omitted: a mechanism that vanishes on a platform is
// indistinguishable from one that ran and found nothing, and US4's whole point is that those are
// different answers.

var procRoot = "" // no process table is read on this platform

type processTable struct {
	ByPID      map[int][]string
	Unreadable int
	Err        error
}

func (t processTable) Examined() string { return "no process table was read" }

func readProcessTable() processTable {
	return processTable{Err: errors.New("reading process command lines is implemented for Linux only; this host is " + runtime.GOOS)}
}

func unavailableProcessTable(m Mechanism, err error) Outcome {
	return Outcome{Mechanism: m, Status: StatusUnavailable, Detail: err.Error()}
}
