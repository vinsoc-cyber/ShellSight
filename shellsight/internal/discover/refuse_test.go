package discover

import (
	"strings"
	"testing"
)

// --- T086: individually refusable, and validated ------------------------------------------------

func TestAMechanismIsRefusableByName(t *testing.T) {
	refuse, unknown := ParseRefusal("nginx-dump")
	if len(unknown) != 0 {
		t.Fatalf("unexpected unknown names: %v", unknown)
	}
	if !refuse[MechNginxDump] {
		t.Fatal("nginx-dump must be refused")
	}
	// Individually: refusing one exec mechanism must not refuse the other, or "I do not trust this
	// one binary" would be indistinguishable from "run nothing".
	if refuse[MechApacheDump] {
		t.Fatal("refusing nginx-dump must not refuse apache-dump")
	}
}

func TestTheExecGroupRefusesEveryMechanismThatRunsSomething(t *testing.T) {
	// The case that actually matters on an incident host: "do not run anything on this box."
	refuse, unknown := ParseRefusal("exec")
	if len(unknown) != 0 {
		t.Fatalf("unexpected unknown names: %v", unknown)
	}
	for _, m := range ExecMechanisms() {
		if !refuse[m] {
			t.Errorf("exec must cover %q", m)
		}
	}
	// ...and nothing else. Refusing the execs must leave file reading available, since config-file
	// parsing is the primary method and is unaffected by a replaced binary.
	for _, m := range KnownMechanisms() {
		if refuse[m] && !isExec(m) {
			t.Errorf("exec must not refuse %q, which only reads files", m)
		}
	}
}

func isExec(m Mechanism) bool {
	for _, e := range ExecMechanisms() {
		if e == m {
			return true
		}
	}
	return false
}

func TestAnUnknownMechanismNameIsReportedNotIgnored(t *testing.T) {
	// A typo must be a warning, not a mechanism that quietly keeps running. An operator who typed
	// --discovery-refuse=nginx-dmup and got a silent success would believe they had refused an exec
	// that in fact ran. Same rule US4 applies to an unknown --views name.
	refuse, unknown := ParseRefusal("nginx-dmup,apache-dump")
	if len(unknown) != 1 || unknown[0] != "nginx-dmup" {
		t.Fatalf("want the typo reported, got %v", unknown)
	}
	if !refuse[MechApacheDump] {
		t.Fatal("the valid name in the list must still take effect")
	}
}

func TestAnEmptyRefusalIsNil(t *testing.T) {
	// Options.refused is a nil check on the hot path, and an empty non-nil map would make every
	// mechanism pay for a lookup that can never match.
	refuse, unknown := ParseRefusal("")
	if refuse != nil || len(unknown) != 0 {
		t.Fatalf("got %v / %v", refuse, unknown)
	}
	if (Options{Refuse: refuse}).refused(MechNginxDump) {
		t.Fatal("an empty refusal must refuse nothing")
	}
}

func TestRefusalNamesAreCaseAndSpaceTolerant(t *testing.T) {
	refuse, unknown := ParseRefusal(" NGINX-Dump , , apache-dump ")
	if len(unknown) != 0 {
		t.Fatalf("unexpected unknown names: %v", unknown)
	}
	if !refuse[MechNginxDump] || !refuse[MechApacheDump] {
		t.Fatalf("both must be refused, got %v", refuse)
	}
}

func TestTheHelpTextNamesWhatWouldRun(t *testing.T) {
	// An operator deciding whether to allow an exec on an incident host needs to know which binary.
	help := RefusalHelp()
	for _, want := range []string{"exec", "nginx-dump", "apache-dump", "replaced"} {
		if !strings.Contains(help, want) {
			t.Errorf("help must mention %q, got: %s", want, help)
		}
	}
}

// --- T081: discovery's capability set is complete and reports on every platform -----------------

func TestEveryKnownMechanismReportsItself(t *testing.T) {
	// This is what "registered in the capability table" means for discovery, and why the phantom
	// `--views discovery` entry the task text suggested would have been wrong: discovery is not a
	// scan surface, it is a sub-capability of the disk view. The property that matters is the same
	// one probeSpec/registryFor gives the probes -- nothing silently absent -- so every mechanism
	// that can exist must account for itself on this host, whatever this host happens to be.
	res := Discover(nil, Options{})
	reported := map[Mechanism]bool{}
	for _, o := range res.Outcomes {
		reported[o.Mechanism] = true
	}
	for _, m := range KnownMechanisms() {
		switch m {
		case MechExplicit, MechDiscovery:
			// Only meaningful when the operator supplied paths, or switched discovery off; neither
			// applies to a plain auto-discovery run.
			continue
		case MechIISDefault:
			// Reported only on Windows, where SystemDrive exists; iis-config carries the platform
			// statement on Linux, so the pair is covered without duplicating the message.
			continue
		}
		if !reported[m] {
			t.Errorf("mechanism %q did not appear in the capability set for this host", m)
		}
	}
}

func TestNoMechanismReportsTwice(t *testing.T) {
	// One outcome per mechanism, the same invariant US4 enforces for coverage records: a duplicated
	// mechanism would let a report contradict itself about what was consulted.
	res := Discover(nil, Options{})
	seen := map[Mechanism]int{}
	for _, o := range res.Outcomes {
		seen[o.Mechanism]++
	}
	for m, n := range seen {
		if n > 1 {
			t.Errorf("mechanism %q reported %d times", m, n)
		}
	}
}

func TestKnownMechanismsCoversEverythingADiscoverRunReports(t *testing.T) {
	// The guard that was missing. appserver-process shipped absent from KnownMechanisms: the
	// completeness test iterated that list, so it passed VACUOUSLY for the one mechanism it should
	// have caught, and --discovery-refuse could not name it. Comparing the list against what a real
	// run actually reports closes the loop in the direction that matters.
	known := map[Mechanism]bool{}
	for _, m := range KnownMechanisms() {
		known[m] = true
	}
	for _, o := range Discover(nil, Options{}).Outcomes {
		if !known[o.Mechanism] {
			t.Errorf("mechanism %q reported by a real run is absent from KnownMechanisms, so it "+
				"cannot be refused by name and does not appear in the help text", o.Mechanism)
		}
	}
}

func TestEveryRefusableMechanismIsKnown(t *testing.T) {
	// Guards the two lists against drift: a new exec mechanism that is missing from KnownMechanisms
	// could not be refused by name, and FR-039 requires exactly that.
	known := map[Mechanism]bool{}
	for _, m := range KnownMechanisms() {
		known[m] = true
	}
	for _, m := range ExecMechanisms() {
		if !known[m] {
			t.Errorf("exec mechanism %q is missing from KnownMechanisms, so it cannot be refused by name", m)
		}
	}
}
