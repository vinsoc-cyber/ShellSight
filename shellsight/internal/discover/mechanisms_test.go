package discover

// Spec 007 US2: the two convention mechanisms are part of the operator contract -- refusable by name,
// guess-grade in a tie, silent when a location is merely absent.

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestKnownMechanismsIncludeTheConventionMechanisms(t *testing.T) {
	known := KnownMechanisms()
	idx := func(m Mechanism) int {
		for i, k := range known {
			if k == m {
				return i
			}
		}
		return -1
	}
	tc, ac := idx(MechTomcatConvention), idx(MechAppserverConvention)
	if tc < 0 || ac < 0 {
		t.Fatalf("both convention mechanisms must be known, got %v", known)
	}
	if tc != idx(MechTomcatServerXML)+1 {
		t.Fatalf("tomcat-convention reports right after tomcat-server-xml, got order %v", known)
	}
	if ac != idx(MechAppserverProcess)+1 {
		t.Fatalf("appserver-convention reports right after appserver-process, got order %v", known)
	}
	help := RefusalHelp()
	for _, m := range []Mechanism{MechTomcatConvention, MechAppserverConvention} {
		if !strings.Contains(help, string(m)) {
			t.Fatalf("--discovery-refuse help must name %s, got %q", m, help)
		}
	}
	if string(MechTomcatConvention) != "tomcat-convention" || string(MechAppserverConvention) != "appserver-convention" {
		t.Fatalf("the operator-facing names are fixed by the contract, got %q / %q", MechTomcatConvention, MechAppserverConvention)
	}
}

func TestConventionMechanismsAreGuessGrade(t *testing.T) {
	if specificity(MechTomcatConvention) != 1 || specificity(MechAppserverConvention) != 1 {
		t.Fatalf("a documented default is a guess, like convention (1); got %d / %d",
			specificity(MechTomcatConvention), specificity(MechAppserverConvention))
	}
	// A directory both a config read and the convention propose keeps the config's provenance.
	dir := t.TempDir()
	res := assemble([]Root{
		{Path: dir, Mechanism: MechTomcatConvention, Source: "official tomcat image"},
		{Path: dir, Mechanism: MechApacheConfig, Source: "/etc/apache2/apache2.conf"},
	}, nil)
	if len(res.Roots) != 1 || res.Roots[0].Mechanism != MechApacheConfig {
		t.Fatalf("the configuration read must win the merge, got %+v", res.Roots)
	}
	if len(res.Roots[0].AlsoFoundBy) != 1 || res.Roots[0].AlsoFoundBy[0] != MechTomcatConvention {
		t.Fatalf("the convention must still be credited, got %+v", res.Roots[0])
	}
}

func TestAnAbsentConventionalLocationIsSilent(t *testing.T) {
	absent := filepath.Join(t.TempDir(), "usr", "local", "tomcat", "webapps")
	for _, m := range []Mechanism{MechTomcatConvention, MechAppserverConvention} {
		res := assemble([]Root{{Path: absent, Mechanism: m, Source: "x"}}, nil)
		if len(res.Rejected) != 0 || res.RejectedTotal != 0 {
			t.Fatalf("%s: an absent conventional location is a guess that missed, not a refusal; got %+v", m, res.Rejected)
		}
	}
}
