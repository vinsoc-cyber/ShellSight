package main

import (
	"path/filepath"
	"strings"
	"testing"

	"shellsight/internal/finding"
)

// An incomplete scan must not exit 0. Exit 0 is the all-clear an automation harness keys on, so a
// timed-out or failed view returning it would silently convert "I could not check" into "nothing
// here" for every caller downstream.
func TestExitCodeNeverClearsOnUnknownOrIncomplete(t *testing.T) {
	cases := []struct {
		name string
		v    finding.Verdict
		want int
	}{
		{"unknown", finding.Verdict{Tier: finding.TierUnknown, Incomplete: true}, 5},
		{"clean but incomplete", finding.Verdict{Tier: finding.TierClean, Incomplete: true}, 5},
		{"genuinely clean", finding.Verdict{Tier: finding.TierClean}, 0},
		{"suspicious", finding.Verdict{Tier: finding.TierSuspicious}, 2},
		{"likely", finding.Verdict{Tier: finding.TierLikely}, 3},
		{"confirmed", finding.Verdict{Tier: finding.TierConfirmed}, 4},
		// A view failed but a shell was still found: report the finding, not the incompleteness.
		{"confirmed and incomplete", finding.Verdict{Tier: finding.TierConfirmed, Incomplete: true}, 4},
	}
	for _, c := range cases {
		if got := exitCode(c.v); got != c.want {
			t.Errorf("%s: exitCode = %d, want %d", c.name, got, c.want)
		}
	}
}

// The default must be able to finish a real webroot. The disk probe needs 4m16s on 989 obfuscated
// shells, so anything near the old 120s reports incomplete on ordinary IR targets.
func TestDefaultTimeoutFitsARealWebroot(t *testing.T) {
	if defaultTimeoutSec < 900 {
		t.Errorf("default timeout %ds is too low for a real webroot scan", defaultTimeoutSec)
	}
}

// scan hardcoded <exe>/kb/rules with no override, while every `rules` subcommand accepted
// --rules-dir. That asymmetry meant rules could be MANAGED anywhere but only SCANNED with from
// inside bin/ — and bin/ is what an upgrade replaces wholesale, so there was no supported place to
// keep operator rules safe.
func TestScanRulesDirOverrideReachesTheDiskProbe(t *testing.T) {
	custom := filepath.Join(t.TempDir(), "site-rules")
	reg := probeRegistry(custom, "")
	disk, ok := reg["disk"]
	if !ok {
		t.Fatal("disk view must be registered")
	}
	if !containsArg(disk.Args, custom) {
		t.Fatalf("disk probe must be pointed at the override, got %v", disk.Args)
	}
	// mem-contracts.json lives in the rules dir, so it has to follow the override too, otherwise a
	// relocated rule tree silently keeps using the bundled contracts.
	if mem, ok := reg["dotnet-mem"]; ok && !containsArg(mem.Args, custom) {
		t.Errorf("mem-contracts must resolve under the override, got %v", mem.Args)
	}
}

func TestScanDefaultsToTheBundledRules(t *testing.T) {
	reg := probeRegistry("", "")
	disk := reg["disk"]
	want := filepath.Join(exeDir(), "kb", "rules")
	if !containsArg(disk.Args, want) {
		t.Fatalf("with no override the disk probe must use %s, got %v", want, disk.Args)
	}
}

func containsArg(args []string, want string) bool {
	for _, a := range args {
		if strings.Contains(a, want) {
			return true
		}
	}
	return false
}

func TestDefaultViewsIsNotMock(t *testing.T) {
	if defaultViews == "mock" {
		t.Error("defaultViews is 'mock' — must be 'disk,dotnet-mem,java-mem'")
	}
}

func TestBehavioralViewRegistered(t *testing.T) {
	// Windows-only: the behavioural probe reads Windows event logs and Windows process ancestry, so
	// there is nothing for it to do on Linux. Asserted against the table rather than the host so the
	// claim still holds when this suite runs on Linux.
	reg := probeRegistryIn(t.TempDir(), "windows", "", "")
	p, ok := reg["behavioral"]
	if !ok {
		t.Fatal("behavioral view must be registered on windows")
	}
	if p.View != "behavioral" {
		t.Fatalf("wrong view name: %q", p.View)
	}
	if !strings.Contains(defaultViewsFor("windows"), "behavioral") {
		t.Fatalf("behavioral must be a default view on windows, got %q", defaultViewsFor("windows"))
	}
}
