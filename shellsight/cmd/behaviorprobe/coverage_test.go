package main

import (
	"strings"
	"testing"

	"shellsight/internal/finding"
)

func TestCoverageFromTelemetry(t *testing.T) {
	// Sysmon present → ran (nil).
	if c := coverageFromTelemetry(true, false, false, false, false); c != nil {
		t.Fatalf("sysmon present → ran, got %+v", c)
	}
	// Modern 4688 with ParentProcessName → ran.
	if c := coverageFromTelemetry(false, true, true, true, true); c != nil {
		t.Fatalf("4688+parent → ran, got %+v", c)
	}
	// Old schema (4688 but no parent), no Sysmon → degraded, schema-specific reason.
	c := coverageFromTelemetry(false, true, false, true, true)
	if c == nil || c.Status != finding.CovDegraded || !strings.Contains(strings.ToLower(c.Reason), "parentprocessname") {
		t.Fatalf("old 4688 schema must degrade with a schema reason, got %+v", c)
	}
	// Auditing OFF (no 4688, determined off), no Sysmon → degraded mentioning OFF.
	c = coverageFromTelemetry(false, false, false, false, true)
	if c == nil || !strings.Contains(strings.ToLower(c.Reason), "off") {
		t.Fatalf("auditing off must degrade mentioning OFF, got %+v", c)
	}
	// Undetermined audit policy (not elevated), no 4688, no Sysmon → degraded mentioning elevated.
	c = coverageFromTelemetry(false, false, false, false, false)
	if c == nil || !strings.Contains(strings.ToLower(c.Reason), "elevated") {
		t.Fatalf("undetermined audit policy must degrade mentioning elevation, got %+v", c)
	}
}
