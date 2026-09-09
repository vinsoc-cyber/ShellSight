package output

import (
	"strings"
	"testing"

	"shellsight/internal/finding"
)

// Spec 007 FR-004: an explicit --path inside --root is reported in both namespaces, exactly as a
// discovered root is -- the renderer keys on InFilesystem, not on the mechanism, so no rendering
// change is needed; this pins that the explicit case reads the same way.
func TestSummaryShowsServedAsForAnExplicitRoot(t *testing.T) {
	text := summary(reportWith(&finding.DiscoveryReport{
		Roots: []finding.DiscoveredRoot{{
			Path: "/proc/616/root/srv/www", Mechanism: "explicit", InFilesystem: "/srv/www",
		}},
		Mechanisms: []finding.DiscoveryMechanism{{Mechanism: "explicit", Status: "succeeded", Roots: 1}},
	}))
	if !strings.Contains(text, "root /proc/616/root/srv/www  via explicit, served as /srv/www") {
		t.Fatalf("an explicit root inside --root must show both forms, got:\n%s", text)
	}
}

func TestSummaryShowsNoServedAsForALiveExplicitRoot(t *testing.T) {
	text := summary(reportWith(&finding.DiscoveryReport{
		Roots:      []finding.DiscoveredRoot{{Path: "/var/www", Mechanism: "explicit"}},
		Mechanisms: []finding.DiscoveryMechanism{{Mechanism: "explicit", Status: "succeeded", Roots: 1}},
	}))
	if strings.Contains(text, "served as") {
		t.Fatalf("a live explicit root has one namespace, got:\n%s", text)
	}
}
