package main

// Spec 007 US2 scenarios 3 and 7: when nothing is discovered, the reason each mechanism gives -- a
// location that exists without an instance layout, the locations that were checked, a refusal -- must
// reach the operator. Measured 2026-08-26 on the rebuilt bundle: a Tomcat image whose conf/server.xml
// was removed exited 5 with only "no webroot could be discovered on this host and none was supplied",
// while the mechanism's detail ("exists without an instance layout: /usr/local/tomcat") was lost with
// the coverage block the failed probe never emitted.

import (
	"strings"
	"testing"

	"shellsight/internal/discover"
)

func TestNothingDiscoveredNamesWhatEachMechanismDid(t *testing.T) {
	res := discover.Result{Outcomes: []discover.Outcome{
		{Mechanism: discover.MechApacheConfig, Status: discover.StatusUnavailable, Detail: "no Apache configuration in the standard locations"},
		{Mechanism: discover.MechTomcatConvention, Status: discover.StatusAttempted,
			Detail: "checked 3 conventional location(s): /usr/local/tomcat, /var/lib/tomcat[0-9]*, /opt/bitnami/tomcat; none held an instance; exists without an instance layout: /usr/local/tomcat"},
		{Mechanism: discover.MechConvention, Status: discover.StatusAttempted, Detail: "checked 5 conventional location(s)"},
	}}
	msg := webrootGate(0, res)
	if msg == "" {
		t.Fatal("nothing to scan must be a coverage failure")
	}
	for _, want := range []string{"no webroot could be discovered", "name one with --path",
		"tomcat-convention=attempted", "exists without an instance layout: /usr/local/tomcat",
		"apache-config=unavailable"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the failure must carry %q, got:\n%s", want, msg)
		}
	}
}

func TestNothingDiscoveredNamesARefusedMechanism(t *testing.T) {
	res := discover.Result{Outcomes: []discover.Outcome{
		{Mechanism: discover.MechTomcatConvention, Status: discover.StatusRefused, Detail: "refused by the operator"},
	}}
	msg := webrootGate(0, res)
	if !strings.Contains(msg, "tomcat-convention=refused") {
		t.Fatalf("a refusal that left nothing to scan must be named, got:\n%s", msg)
	}
}

func TestTheNothingDiscoveredMessageIsBounded(t *testing.T) {
	// Every detail is attacker-influenced in length (a config with 50,000 directives yields 50,000
	// rejections); the failure line must not become the report.
	long := strings.Repeat("x", 10_000)
	res := discover.Result{Outcomes: []discover.Outcome{
		{Mechanism: discover.MechNginxConfig, Status: discover.StatusAttempted, Detail: long},
	}}
	msg := webrootGate(0, res)
	if len(msg) > 2_500 {
		t.Fatalf("the failure message must be bounded, got %d bytes", len(msg))
	}
}
