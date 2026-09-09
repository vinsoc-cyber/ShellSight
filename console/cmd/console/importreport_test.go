package main

import (
	"testing"
)

func TestImportReportConfigRequiresDsnDirAndCase(t *testing.T) {
	for _, args := range [][]string{
		{"-dir", "/runs", "-case", "IR-1"},
		{"-dsn", "postgres://x", "-case", "IR-1"},
		{"-dsn", "postgres://x", "-dir", "/runs"},
	} {
		if _, err := parseImportReportConfig(args); err == nil {
			t.Errorf("expected %v to be rejected", args)
		}
	}
}

func TestImportReportConfigAcceptsACompleteInvocation(t *testing.T) {
	cfg, err := parseImportReportConfig([]string{
		"-dsn", "postgres://x", "-dir", "/runs", "-case", "IR-2026-0413",
	})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cfg.Case != "IR-2026-0413" || cfg.Dir != "/runs" {
		t.Fatalf("got %+v", cfg)
	}
}
