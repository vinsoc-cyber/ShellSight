package jvmprov

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The two family tables must agree.
//
// WHY THIS EXISTS. Family attribution is implemented twice, once per delivery path: this package for
// the Linux native probe, and probes/javamem/src/.../Family.java for the Windows jar. Several records
// claim a change landed on "both delivery paths so they cannot diverge" — and on 2026-09-01 that
// claim was measured false. The tunnel work added the `suo5` marker here and its needle to the Java
// needle list, but not to the Java MARKER table, so the jar path scored the Suo5 corpus cells at the
// correct tier while attributing 28 of 92 against this path's 44. Nothing failed; the two tables just
// quietly disagreed.
//
// A promise in a commit message cannot catch that. This can.
//
// It reads the Java source as text rather than parsing it. That is deliberate: the test must fail
// when a marker is missing from the Java table, and it must not need a JDK, a build, or a running
// JVM to say so — the Go suite runs everywhere and this is the cheapest place to make the parity
// claim mechanical.
func TestFamilyMarkersMatchTheJavaProbe(t *testing.T) {
	src := filepath.Join("..", "..", "probes", "javamem", "src", "com", "shellsight", "javamem", "Family.java")
	b, err := os.ReadFile(src)
	if err != nil {
		// Not a source file this package owns; if the probe tree is absent there is nothing to
		// compare against and this gate has no opinion.
		t.Skipf("no Java Family.java to compare against (%v)", err)
	}
	java := string(b)

	// Only the MARKERS table counts. Comments in that file legitimately mention families and
	// needles in prose, so the check is scoped to the constructor calls that build the table.
	markerBlock := java
	if i := strings.Index(java, "MARKERS = List.of("); i >= 0 {
		markerBlock = java[i:]
		if j := strings.Index(markerBlock, ");"); j >= 0 {
			markerBlock = markerBlock[:j]
		}
	}

	for _, m := range markers {
		if !strings.Contains(markerBlock, `"`+m.family+`"`) {
			t.Errorf(`family %q is attributed by the native probe but is ABSENT from the Java probe's
MARKERS table (%s).

The two delivery paths would report different families for the same class. Add it there, with the
same needle and confidence, or remove it here.`, m.family, src)
			continue
		}
		if !strings.Contains(markerBlock, `"`+m.needle+`"`) {
			t.Errorf("family %q is in both tables but its needle %q is missing from the Java table — "+
				"the paths would attribute on different evidence", m.family, m.needle)
		}
	}

	// And the other direction: a family the Java table attributes and this one does not is the same
	// divergence viewed from the other side.
	for _, fam := range []string{"behinder", "godzilla", "suo5"} {
		if !strings.Contains(markerBlock, `"`+fam+`"`) {
			continue // not claimed by the Java table
		}
		found := false
		for _, m := range markers {
			if m.family == fam {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("family %q is attributed by the Java probe but not by the native probe", fam)
		}
	}
}
