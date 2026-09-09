//go:build !linux

package jvmattach

import "errors"

// Attach is Linux-only: the protocol depends on /proc and POSIX signals. This stub keeps the
// package building on Windows, where most of ShellSight is developed and tested.
func Attach(_ Options) (Result, error) {
	return Result{Refusal: "attach requires Linux"}, errors.New("jvmattach: unsupported platform")
}
