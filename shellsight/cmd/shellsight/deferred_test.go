package main

import (
	"strings"
	"testing"
)

// T093 / FR-007a: a capability this release chose not to ship must say so, and must not claim the
// host cannot support it.
//
// A deferred capability on Linux once reported "java-mem is supported on windows only; this host is linux". That is
// false about the CAPABILITY -- the JVM attach path is portable; what is missing is live validation
// against a Linux application server (US5/T064). The distinction changes what a responder does: told
// it is impossible, they stop looking for Linux Java memshells; told it is deferred, they escalate or
// wait for the release that ships it.


// The deferral MECHANISM is exercised against a synthetic spec, not against a real capability.
//
// java-mem used to be the live example, and these tests asserted it was deferred on Linux. It is
// not any more -- it runs natively there, validated in
// docs/measurements/2026-08-31-tomcat-memshell-corpus. Deleting the tests would have been the easy
// move and the wrong one: nothing else covers the deferral machinery, and the next capability that
// needs deferring depends on it working.
func deferralFixture() []probeSpec {
	return []probeSpec{
		{View: "test-deferred", Default: true, Optional: true,
			DeferredOn:  []string{"linux"},
			DeferredWhy: "synthetic fixture: exercises the deferral mechanism without deferring a real capability"},
	}
}

func TestADeferredCapabilityDoesNotClaimTheHostCannotSupportIt(t *testing.T) {
	p, known := naProbeForSpecs(deferralFixture(), "test-deferred", "linux")
	if !known {
		t.Fatal("a deferred capability must be reported, not treated as a typo")
	}
	if !strings.Contains(p.NotApplicable, "deferred") {
		t.Errorf("the reason must say it is deferred, got %q", p.NotApplicable)
	}
	// The specific false statement this task exists to remove.
	if strings.Contains(p.NotApplicable, "supported on windows only") {
		t.Errorf("a deferred capability must not be reported as unsupported, got %q", p.NotApplicable)
	}
	// FR-012 still applies, and the reason has to name the host it is talking about.
	if !strings.Contains(p.NotApplicable, "linux") {
		t.Errorf("the reason must name the platform, got %q", p.NotApplicable)
	}
	// And it must say WHY, or "deferred" is just a label.
	if len(p.NotApplicable) < 40 {
		t.Errorf("the reason must carry the justification, got %q", p.NotApplicable)
	}
}

func TestADeferredCapabilityIsNotApplicableRatherThanFailed(t *testing.T) {
	// n/a does NOT set the incomplete flag (internal/fusion), so deferring a capability cannot turn every
	// clean Linux scan into exit 5 -- which is the exact failure US4 exists to prevent, and the whole
	// reason this task is separate from simply dropping the view.
	p, _ := naProbeForSpecs(deferralFixture(), "test-deferred", "linux")
	if p.NotApplicable == "" {
		t.Fatal("a deferred capability must carry a NotApplicable reason, which is what makes it n/a")
	}
	if p.Path != "" || len(p.Args) != 0 {
		t.Errorf("a deferred capability must not be runnable: %+v", p)
	}
}

func TestADeferredCapabilityIsDistinguishableFromABrokenPackage(t *testing.T) {
	// The two must never look alike. Deferred is a decision, recorded at registration and reported
	// n/a. A platform-supported component that is simply MISSING is a defective package, and it stays
	// loud: the probe is registered with its real path, runs, fails, and the scan exits 5 (US4/T061).
	deferred, _ := naProbeForSpecs(deferralFixture(), "test-deferred", "linux")
	if deferred.NotApplicable == "" {
		t.Fatal("deferred capability has no reason")
	}

	// disk is supported on Linux, so it must be REGISTERED -- present in the table's Linux set with a
	// binary to run. If a missing binary silently dropped it instead, a broken package would look like
	// a smaller, quieter, apparently-successful scan.
	var disk *probeSpec
	for _, s := range registryFor("linux") {
		if s.View == "disk" {
			spec := s
			disk = &spec
		}
	}
	if disk == nil {
		t.Fatal("disk must be in the Linux capability set")
	}
	if disk.Optional {
		t.Error("disk must not be optional: a missing disk probe is a broken package, not an absent companion")
	}
	if disk.Bin == "" {
		t.Error("disk must name a binary, or nothing can report it missing")
	}
}

func TestADeferredCapabilityStaysInTheTableForItsOtherPlatforms(t *testing.T) {
	// Deferral is per-platform. A deferred-on-linux capability must still RUN on Windows -- modelling the deferral as a
	// platform restriction, or by deleting the row, would have taken it away there too.
	var found bool
	for _, s := range registryForSpecs(deferralFixture(), "windows") {
		if s.View == "test-deferred" {
			found = true
			if s.deferredOn("windows") {
				t.Error("the fixture is not deferred on Windows")
			}
		}
	}
	if !found {
		t.Error("the fixture must remain a Windows capability")
	}
	// ...and must be absent from the Linux registry, so nothing tries to launch it there.
	for _, s := range registryForSpecs(deferralFixture(), "linux") {
		if s.View == "test-deferred" {
			t.Error("a deferred capability must not be registered as runnable on the platform it is deferred on")
		}
	}
}

func TestEveryDeferredPlatformIsOneTheCapabilityCouldOtherwiseRunOn(t *testing.T) {
	// Guards the two fields against contradicting each other: deferring a capability on a platform its
	// OS list already excludes would be a statement with no meaning, and whichever message won would
	// be arbitrary.
	for _, s := range probeSpecs {
		for _, goos := range s.DeferredOn {
			if len(s.OS) == 0 {
				continue // portable capability; deferral is meaningful anywhere
			}
			var supported bool
			for _, o := range s.OS {
				if o == goos {
					supported = true
				}
			}
			if !supported {
				t.Errorf("%s is deferred on %s but its OS list (%v) already excludes it; the two "+
					"statements contradict each other", s.View, goos, s.OS)
			}
		}
		if len(s.DeferredOn) > 0 && strings.TrimSpace(s.DeferredWhy) == "" {
			t.Errorf("%s is deferred with no reason; FR-012 requires one for any status other than ran", s.View)
		}
	}
}
