package output

import (
	"strings"
	"testing"

	"shellsight/internal/finding"
)

// A clean verdict means something different depending on how the scanned directories were found. If
// every root was a guess off a distro default, the responder's next question is whether the real
// webroot was ever looked at — and before this the report could not answer it, because discovery
// returned bare paths. FR-036.

func reportWith(d *finding.DiscoveryReport) finding.Report {
	return finding.Report{
		Scan:     finding.Scan{Host: "web01", ToolVersion: "v1.0.0", RunID: "20260820_120000"},
		Verdict:  finding.Verdict{Tier: finding.TierClean},
		Coverage: []finding.Coverage{{View: "disk", Status: finding.CovRan, TargetsScanned: 1, Discovery: d}},
	}
}

func TestTheReportSaysHowEachScannedRootWasFound(t *testing.T) {
	text := summary(reportWith(&finding.DiscoveryReport{
		Roots: []finding.DiscoveredRoot{{
			Path: "/srv/sites/a", Mechanism: "nginx-config", Source: "/etc/nginx/sites-enabled/a",
			AlsoFoundBy: []string{"convention"},
		}},
		Mechanisms: []finding.DiscoveryMechanism{
			{Mechanism: "nginx-config", Status: "succeeded", Roots: 1},
		},
	}))
	for _, want := range []string{"/srv/sites/a", "nginx-config", "/etc/nginx/sites-enabled/a", "convention"} {
		if !strings.Contains(text, want) {
			t.Errorf("the report must name %q, got:\n%s", want, text)
		}
	}
}

func TestTheReportDistinguishesAGuessFromAConfiguredRoot(t *testing.T) {
	guessed := summary(reportWith(&finding.DiscoveryReport{
		Roots:      []finding.DiscoveredRoot{{Path: "/var/www", Mechanism: "convention"}},
		Mechanisms: []finding.DiscoveryMechanism{{Mechanism: "convention", Status: "succeeded", Roots: 1}},
	}))
	if !strings.Contains(guessed, "via convention") {
		t.Errorf("a guessed root must say so, got:\n%s", guessed)
	}
	// A convention has no source file to cite, so there must be nothing in parentheses claiming one.
	if strings.Contains(guessed, "convention (") {
		t.Errorf("a conventional root must not appear to come from a file, got:\n%s", guessed)
	}
}

func TestTheReportNamesWhatEveryMechanismDidNotFind(t *testing.T) {
	// "No nginx on this host" and "nginx is here and named no root" mean different things during an
	// IR. A mechanism list that shows only successes can express neither.
	text := summary(reportWith(&finding.DiscoveryReport{
		Roots: []finding.DiscoveredRoot{{Path: "/var/www", Mechanism: "convention"}},
		Mechanisms: []finding.DiscoveryMechanism{
			{Mechanism: "convention", Status: "succeeded", Roots: 1},
			{Mechanism: "nginx-config", Status: "unavailable", Detail: "no Nginx configuration in the standard locations"},
			{Mechanism: "tomcat-env", Status: "attempted", Detail: "CATALINA_BASE set, webapps absent"},
		},
	}))
	if !strings.Contains(text, "found nothing:") {
		t.Fatalf("the quiet mechanisms must be reported, got:\n%s", text)
	}
	for _, want := range []string{"nginx-config=unavailable", "tomcat-env=attempted", "webapps absent"} {
		if !strings.Contains(text, want) {
			t.Errorf("want %q in:\n%s", want, text)
		}
	}
}

func TestARefusedPathIsShownWithItsReason(t *testing.T) {
	// On a compromised host, a config naming `/` is a lead rather than noise, and a directory that
	// vanished is worth seeing. Silently dropping either is how the clean-on-nothing-scanned bug
	// read from the outside.
	text := summary(reportWith(&finding.DiscoveryReport{
		Roots:      []finding.DiscoveredRoot{{Path: "/var/www", Mechanism: "convention"}},
		Mechanisms: []finding.DiscoveryMechanism{{Mechanism: "convention", Status: "succeeded", Roots: 1}},
		Rejected: []finding.DiscoveryRejection{{
			Path: "/", Mechanism: "nginx-config", Source: "/etc/nginx/nginx.conf",
			Reason: "rejected by containment: the filesystem root is not a webroot",
		}},
	}))
	for _, want := range []string{"REFUSED", "nginx-config", "containment"} {
		if !strings.Contains(text, want) {
			t.Errorf("want %q in:\n%s", want, text)
		}
	}
}

func TestABoundedRefusalListSaysItIsBounded(t *testing.T) {
	// The list length is attacker-chosen: a config with 50,000 root directives would otherwise put
	// 50,000 lines here and bury every real finding. Discovery bounds what it retains, so the report
	// has to say the list is partial — a truncated list that reads as complete is the same failure as
	// a silent cap anywhere else in this project.
	text := summary(reportWith(&finding.DiscoveryReport{
		Roots:      []finding.DiscoveredRoot{{Path: "/var/www", Mechanism: "convention"}},
		Mechanisms: []finding.DiscoveryMechanism{{Mechanism: "convention", Status: "succeeded", Roots: 1}},
		Rejected: []finding.DiscoveryRejection{{
			Path: "/nonexistent/path-0", Mechanism: "nginx-config", Reason: "the directory does not exist",
		}},
		RejectedTotal: 50000,
	}))
	if !strings.Contains(text, "49999 further refused") {
		t.Errorf("the report must state how many refusals it is not showing, got:\n%s", text)
	}
	if !strings.Contains(text, "50000 proposed in total") {
		t.Errorf("the true count must be visible, got:\n%s", text)
	}
}

func TestAnUnboundedRefusalListAddsNoExtraLine(t *testing.T) {
	// The normal case must gain nothing. Hardening that put a line in every clean report would not be
	// worth having.
	text := summary(reportWith(&finding.DiscoveryReport{
		Roots:      []finding.DiscoveredRoot{{Path: "/var/www", Mechanism: "convention"}},
		Mechanisms: []finding.DiscoveryMechanism{{Mechanism: "convention", Status: "succeeded", Roots: 1}},
		Rejected: []finding.DiscoveryRejection{{
			Path: "/gone", Mechanism: "nginx-config", Reason: "the directory does not exist",
		}},
		RejectedTotal: 1,
	}))
	if strings.Contains(text, "further refused") {
		t.Errorf("no bound is in play, so no extra line, got:\n%s", text)
	}
}

func TestASubsumedRootStaysVisible(t *testing.T) {
	// It is not scanned separately — the parent covers it — but a discovered root vanishing from the
	// report with no explanation looks like a bug in discovery.
	text := summary(reportWith(&finding.DiscoveryReport{
		Roots: []finding.DiscoveredRoot{{
			Path: "/var/www", Mechanism: "convention", Subsumes: []string{"/var/www/html"},
		}},
		Mechanisms: []finding.DiscoveryMechanism{{Mechanism: "convention", Status: "succeeded", Roots: 1}},
	}))
	if !strings.Contains(text, "covers /var/www/html") {
		t.Errorf("a subsumed root must stay visible, got:\n%s", text)
	}
}

func TestAViewWithoutDiscoveryRendersNothingExtra(t *testing.T) {
	// A memory view discovers no directories, and its coverage line must look exactly as it did.
	text := summary(reportWith(nil))
	if strings.Contains(text, "root ") || strings.Contains(text, "found nothing") {
		t.Errorf("a view that discovered nothing must add no lines, got:\n%s", text)
	}
}
