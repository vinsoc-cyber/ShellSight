package main

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"shellsight/internal/finding"
)

// rawEvent mirrors the Windows EventLog XML schema (the subset we need).
type rawEvent struct {
	System struct {
		Provider struct {
			Name string `xml:"Name,attr"`
		} `xml:"Provider"`
		EventID     string `xml:"EventID"` // chardata; may carry a Qualifiers attr
		Channel     string `xml:"Channel"`
		TimeCreated struct {
			SystemTime string `xml:"SystemTime,attr"`
		} `xml:"TimeCreated"`
	} `xml:"System"`
	EventData struct {
		Data []struct {
			Name  string `xml:"Name,attr"`
			Value string `xml:",chardata"`
		} `xml:"Data"`
	} `xml:"EventData"`
}

// parseEventsXML parses the concatenated <Event> elements that `wevtutil qe /f:xml` emits
// (no enclosing root), wrapping them so the stdlib decoder has a single document.
func parseEventsXML(data []byte) ([]Event, error) {
	// wevtutil emits UTF-8 XML but passes through raw event-data bytes the stdlib decoder rejects:
	// (a) CP-1252 bytes that aren't valid UTF-8 (e.g. 0xAE), and (b) C0 control characters that are
	// valid UTF-8 but illegal in XML 1.0 (e.g. U+0002, U+000F). Either aborts the whole batch on one
	// bad byte, so scrub both first. (Surfaced across real EVTX-ATTACK-SAMPLES captures — 3/278 still
	// failed on control chars after the UTF-8-only fix; the synthetic tests never hit it: F6.)
	data = sanitizeXML(data)
	wrapped := "<Events>" + string(data) + "</Events>"
	var doc struct {
		Events []rawEvent `xml:"Event"`
	}
	if err := xml.Unmarshal([]byte(wrapped), &doc); err != nil {
		return nil, fmt.Errorf("parse event xml: %w", err)
	}
	out := make([]Event, 0, len(doc.Events))
	for _, r := range doc.Events {
		id, _ := strconv.Atoi(strings.TrimSpace(r.System.EventID))
		e := Event{
			Channel:  r.System.Channel,
			Provider: r.System.Provider.Name,
			EventID:  id,
			Time:     r.System.TimeCreated.SystemTime,
			Data:     map[string]string{},
		}
		for _, d := range r.EventData.Data {
			v := strings.TrimSpace(d.Value)
			if d.Name != "" {
				e.Data[d.Name] = v
			}
			e.Values = append(e.Values, v)
		}
		out = append(out, e)
	}
	return out, nil
}

// sanitizeXML makes a raw wevtutil byte batch safe for the stdlib XML decoder: it drops invalid
// UTF-8 byte sequences (CP-1252 leakage) and strips XML-1.0-illegal C0 control characters
// (everything < 0x20 except tab/LF/CR). C0 controls are single-byte in UTF-8 — multi-byte
// continuation bytes are all >= 0x80 — so a post-UTF-8 byte filter is correct and allocation-free.
func sanitizeXML(data []byte) []byte {
	data = bytes.ToValidUTF8(data, nil)
	out := data[:0] // in-place: write index never outpaces read index
	for _, b := range data {
		if b >= 0x20 || b == '\t' || b == '\n' || b == '\r' {
			out = append(out, b)
		}
	}
	return out
}

// channelQuery is one (channel, XPath) pull.
type channelQuery struct {
	channel string
	xpath   string
}

// behavioralQueries are the channels + filters the live source pulls.
var behavioralQueries = []channelQuery{
	{"Application", "*[System[(EventID=1316)]]"},
	{"Microsoft-IIS-Configuration/Operational", "*[System[(EventID=29 or EventID=50)]]"},
	{"Security", "*[System[(EventID=4688)]]"},
	{"Microsoft-Windows-Sysmon/Operational", "*[System[(EventID=1)]]"},
}

const maxEventsPerChannel = 2000

// gatherLive queries the live event log via wevtutil for each behavioral channel.
// A channel that does not exist or is inaccessible is skipped, not fatal — but if NO
// channel could be read the caller treats it as a coverage failure.
func gatherLive() ([]Event, int, error) {
	if _, err := exec.LookPath("wevtutil"); err != nil {
		return nil, 0, fmt.Errorf("wevtutil not found on PATH (Windows only) — behavioral live view unavailable")
	}
	var all []Event
	okChannels := 0
	for _, q := range behavioralQueries {
		out, err := runWevtutil(q.channel, q.xpath, "")
		if err != nil {
			continue // channel absent / access denied — skip; coverage decided by okChannels
		}
		okChannels++
		ev, perr := parseEventsXML(out)
		if perr != nil {
			continue
		}
		all = append(all, ev...)
	}
	if okChannels == 0 {
		return nil, 0, fmt.Errorf("no event-log channel could be read (need admin; Windows only)")
	}
	return all, okChannels, nil
}

// channelExists reports whether an event-log channel is present/queryable (`wevtutil gl`).
func channelExists(channel string) bool {
	return exec.Command("wevtutil", "gl", channel).Run() == nil
}

// processCreationAuditing reports whether "Audit Process Creation" (Security 4688) is enabled.
// determined=false means we couldn't tell (auditpol failed — typically not elevated).
func processCreationAuditing() (enabled, determined bool) {
	out, err := exec.Command("auditpol", "/get", "/subcategory:Process Creation").Output()
	if err != nil {
		return false, false
	}
	s := strings.ToLower(string(out))
	return strings.Contains(s, "success") || strings.Contains(s, "failure"), true
}

// coverageFromTelemetry is the PURE honesty rule. The behavioral view's one genuine malicious
// signal (w3wp→shell child) needs a usable process-creation source: Sysmon, OR 4688 events with
// the modern ParentProcessName schema (Server 2016+/Win10). If neither is available we are BLIND
// to it, so report degraded with a cause-specific, actionable reason rather than a false clean.
// ViewState/IIS-config are context-only and don't rescue coverage. Returns nil = ran.
func coverageFromTelemetry(sysmon, have4688, have4688Parent, auditOn, auditDetermined bool) *finding.ProbeCoverage {
	if sysmon || (have4688 && have4688Parent) {
		return nil
	}
	reason := "no usable process-creation telemetry — "
	switch {
	case have4688 && !have4688Parent:
		reason += "4688 events lack ParentProcessName (Windows <=8.1/2012R2 schema); "
	case !have4688 && auditDetermined && !auditOn:
		reason += "Audit Process Creation (4688) is OFF; "
	case !have4688 && !auditDetermined:
		reason += "no 4688 events and audit policy unreadable (run elevated); "
	default:
		reason += "no recent 4688 events; "
	}
	if !sysmon {
		reason += "Sysmon absent; "
	}
	reason += "w3wp->shell detection is BLIND (ViewState/IIS-config are context only). Install Sysmon or enable 'Audit Process Creation' on Server 2016+."
	return &finding.ProbeCoverage{Status: finding.CovDegraded, Reason: reason}
}

// liveCoverage gathers the (impure) telemetry facts — Sysmon channel, audit policy, and what the
// gathered events actually contain (4688 presence + whether the parent-name field is populated) —
// and applies coverageFromTelemetry.
func liveCoverage(events []Event) *finding.ProbeCoverage {
	sysmonChan := channelExists("Microsoft-Windows-Sysmon/Operational")
	auditOn, determined := processCreationAuditing()
	var have4688, have4688Parent, haveSysmon1 bool
	for _, e := range events {
		if e.Channel == "Security" && e.EventID == 4688 {
			have4688 = true
			if e.Data["ParentProcessName"] != "" {
				have4688Parent = true
			}
		}
		if e.EventID == 1 && strings.Contains(e.Channel, "Sysmon") {
			haveSysmon1 = true
		}
	}
	return coverageFromTelemetry(sysmonChan || haveSysmon1, have4688, have4688Parent, auditOn, determined)
}

// gatherEvtx reads all behavioral events from an exported .evtx file (offline mode).
func gatherEvtx(path string) ([]Event, error) {
	out, err := runWevtutil("", "", path)
	if err != nil {
		return nil, fmt.Errorf("read evtx %q: %w", path, err)
	}
	return parseEventsXML(out)
}

// runWevtutil invokes wevtutil. If evtxPath is set, it reads that file (/lf:true) and
// channel/xpath are ignored; otherwise it queries the live channel with the XPath.
// /f:xml emits a concatenated sequence of <Event> elements (no root) — parseEventsXML wraps them.
func runWevtutil(channel, xpath, evtxPath string) ([]byte, error) {
	args := []string{"qe"}
	if evtxPath != "" {
		args = append(args, evtxPath, "/lf:true")
	} else {
		args = append(args, channel, "/q:"+xpath, "/c:"+strconv.Itoa(maxEventsPerChannel), "/rd:true")
	}
	args = append(args, "/f:xml")
	cmd := exec.Command("wevtutil", args...)
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	return out, nil
}
