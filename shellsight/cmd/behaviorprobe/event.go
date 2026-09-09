package main

import "strings"

// Event is one normalized Windows event-log record. Detectors operate only on this,
// so they are testable with synthetic events regardless of the source (wevtutil/.evtx).
type Event struct {
	Channel  string            // e.g. "Application", "Security", "Microsoft-IIS-Configuration/Operational"
	Provider string            // e.g. "ASP.NET 4.0.30319.0", "Microsoft-Windows-Security-Auditing"
	EventID  int               // e.g. 1316, 29, 4688
	Time     string            // ISO-8601 SystemTime, as reported
	Data     map[string]string // named EventData (Data Name="x") → value
	Values   []string          // ALL data values (named + unnamed) for substring scans
}

// dataAny reports whether any captured data value contains needle (case-insensitive).
func (e Event) dataAny(needle string) bool {
	n := strings.ToLower(needle)
	for _, v := range e.Values {
		if strings.Contains(strings.ToLower(v), n) {
			return true
		}
	}
	return false
}
