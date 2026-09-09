package main

import (
	"os"
	"testing"
)

func TestParseWevtutilXML(t *testing.T) {
	data, err := os.ReadFile("testdata/sample-events.xml")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	events, err := parseEventsXML(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("want 2 events, got %d", len(events))
	}
	// First: Security 4688 with named ParentProcessName.
	if events[0].EventID != 4688 || events[0].Channel != "Security" {
		t.Fatalf("event0 wrong: %+v", events[0])
	}
	if events[0].Data["ParentProcessName"] == "" {
		t.Fatalf("named EventData not captured: %+v", events[0].Data)
	}
	// Second: ASP.NET 1316; unnamed Data must land in Values for the substring scan.
	if events[1].EventID != 1316 {
		t.Fatalf("event1 wrong id: %d", events[1].EventID)
	}
	if !events[1].dataAny("viewstate") {
		t.Fatalf("unnamed Data not captured in Values: %+v", events[1].Values)
	}
}

// End-to-end through the detectors: the fixture must yield a w3wp->cmd and a ViewState finding.
func TestSourceFixtureFeedsDetectors(t *testing.T) {
	data, _ := os.ReadFile("testdata/sample-events.xml")
	events, _ := parseEventsXML(data)
	all := append(detectViewState(events, "WEB01"), detectW3wpChild(events, "WEB01")...)
	if len(all) != 2 {
		t.Fatalf("want 2 findings from fixture, got %d", len(all))
	}
}

// Real `wevtutil qe /f:xml` output is UTF-8 XML but passes through bytes the stdlib decoder rejects:
// CP-1252 bytes that aren't valid UTF-8 (e.g. 0xAE, the ® sign) AND C0 control characters that are
// valid UTF-8 but illegal in XML 1.0 (e.g. U+0002, U+000F). parseEventsXML must scrub both instead
// of failing with "XML syntax error: invalid UTF-8" / "illegal character code". Regression for the
// two-defect bug that real EVTX-ATTACK-SAMPLES captures surfaced and the synthetic fixture never hit
// (the host-validation blind spot, EVAL-CRITICAL F6).
func TestParseEventsXMLToleratesInvalidUTF8(t *testing.T) {
	ns := `xmlns="http://schemas.microsoft.com/win/2004/08/events/event"`
	// A single Sysmon EID 1 event carrying BOTH a stray 0xAE byte (invalid UTF-8) and C0 control
	// chars \x02 / \x0F (illegal XML 1.0), mirroring the real wevtutil emission (no XML declaration,
	// concatenated <Event> form).
	raw := "<Event " + ns + "><System>" +
		`<Provider Name="Microsoft-Windows-Sysmon"/>` +
		"<EventID>1</EventID>" +
		"<Channel>Microsoft-Windows-Sysmon/Operational</Channel>" +
		`<TimeCreated SystemTime="2026-06-15T00:00:00Z"/>` +
		"</System><EventData>" +
		`<Data Name="ParentImage">C:\Windows\System32` + "\x0f" + `\inetsrv\w3wp.exe</Data>` +
		`<Data Name="Image">C:\Program Files\ImageMagick` + "\xAE\x02" + `\x.exe</Data>` +
		"</EventData></Event>"

	events, err := parseEventsXML([]byte(raw))
	if err != nil {
		t.Fatalf("parseEventsXML must tolerate a stray 0xAE byte, got error: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("want 1 parsed event, got %d", len(events))
	}
	e := events[0]
	if e.EventID != 1 {
		t.Fatalf("want EventID 1, got %d", e.EventID)
	}
	if e.Data["ParentImage"] == "" || e.Data["Image"] == "" {
		t.Fatalf("event data not parsed after scrub: %+v", e.Data)
	}
}
